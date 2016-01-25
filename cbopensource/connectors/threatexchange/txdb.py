import logging
import datetime
import sqlite3
import dateutil.parser
import dateutil.tz

from pytx import ThreatDescriptor
from pytx.errors import pytxFetchError

import processing_engines
from version import __version__


logger = logging.getLogger(__name__)


db_schema = '''
drop table if exists owners;
drop table if exists indicator_descriptors;
drop index if exists descriptor_id_index;
drop index if exists owner_id_index;
drop index if exists descriptor_time_index;

create table owners (
  id text primary key,
  name text,
  email text
);

create table indicator_descriptors (
  id text primary key,
  status text,
  indicator text,
  indicator_type text,
  severity text,
  last_updated timestamp,
  threat_type text,
  owner_id text,
  description text,
  share_level text,
  confidence integer,
  confidence_band text,

  FOREIGN KEY(owner_id) REFERENCES owners(id)
);

create unique index descriptor_id_index on indicator_descriptors(id);
create unique index owner_id_index on owners(id);
create index descriptor_time_index on indicator_descriptors(last_updated);
'''

owner_cache = set()

confidence_level_map = [
    [33, "LOW"],
    [67, "MEDIUM"],
    [100, "HIGH"],
]

headers = {'User-Agent' : 'CarbonBlackIntegration/v' + __version__}

def confidence_band(confidence):
    for conf_level in confidence_level_map:
        if confidence <= conf_level[0]:
            return conf_level[1]


def ResultIter(cursor, arraysize=1000):
    """An iterator that uses fetchmany to keep memory usage down"""
    while True:
        results = cursor.fetchmany(arraysize)
        if not results:
            break
        for result in results:
            yield result


def add_one_result(cur, result):
    if result.owner["id"] not in owner_cache:
        cur.execute("SELECT * FROM owners WHERE id = ?", (result.owner["id"],))
        if cur.fetchone():
            owner_cache.add(result.owner["id"])
        else:
            owner = result.owner
            cur.execute("INSERT INTO owners VALUES (?, ?, ?)", (owner["id"], owner["name"], owner.get("email", "")))

    insert_values = {
        "id": result.id,
        "status": result.status,
        "indicator": result.raw_indicator,
        "indicator_type": result.type,
        "severity": result.severity,
        "last_updated": dateutil.parser.parse(result.last_updated).replace(tzinfo=None),    # strip timezone
        "threat_type": result.threat_type,
        "owner_id": result.owner["id"],
        "description": result.description,
        "share_level": result.share_level,
        "confidence": result.confidence,
        "confidence_band": confidence_band(result.confidence)
    }

    qstring = "(" + ", ".join(["?"]*len(insert_values)) + ")"
    sql_query = "INSERT OR REPLACE INTO indicator_descriptors (%s) VALUES %s" % (", ".join(insert_values.keys()),
                                                                                 qstring)

    cur.execute(sql_query, tuple(insert_values.values()))


def build_sql_query(minimum_severity='WARNING', status_filter=None, minimum_confidence=50):
    query = ["SELECT * FROM indicator_descriptors,owners WHERE indicator_descriptors.owner_id = owners.id"]
    query_parameters = []

    severity_levels = processing_engines.SEVERITY_LEVELS[processing_engines.SEVERITY_LEVELS.index(minimum_severity):]
    query.append("(%s)" % " OR ".join(["severity = ?" for _ in severity_levels]))
    query_parameters.extend(severity_levels)

    if status_filter is list:
        query.append(" AND ".join(["status <> ?" for _ in status_filter]))
        query_parameters.extend(status_filter)

    query.append("confidence >= ?")
    query_parameters.append(minimum_confidence)

    return " AND ".join(query), tuple(query_parameters)


class ThreatExchangeDb(object):
    def __init__(self, fn):
        self.dbfn = fn
        self.dbconn = sqlite3.connect(self.dbfn, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        self.dbconn.row_factory = sqlite3.Row

        try:
            cur = self.dbconn.execute("SELECT count(*) FROM indicator_descriptors")
            (_, ) = cur.fetchone()
        except Exception:
            self.create_tables()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.dbconn:
            self.dbconn.close()

    def create_tables(self):
        self.dbconn.executescript(db_schema)
        self.dbconn.commit()

    def generate_reports(self, minimum_severity='WARNING', status_filter=None, minimum_confidence=50):
        cur = self.dbconn.cursor()
        q, params = build_sql_query(minimum_severity, status_filter, minimum_confidence)

        cur.execute(q, params)

        for res in ResultIter(cur):
            new_reports = processing_engines.process_ioc(res, minimum_severity, status_filter, minimum_confidence)

            for report in new_reports:
                yield report

    def cull_before(self, ts):
        self.dbconn.execute("DELETE FROM indicator_descriptors WHERE last_updated < ?", (ts,))
        self.dbconn.commit()

    def update(self, ioc_types, tx_limit=250, tx_retries=5, max_historical_days=2):
        now = datetime.datetime.utcnow()
        since_date = now - datetime.timedelta(days=max_historical_days)
        to_date = now + datetime.timedelta(days=1)

        try:
            cur = self.dbconn.execute("SELECT max(last_updated) FROM indicator_descriptors")
            (s, ) = cur.fetchone()
            if s:
                since_date = dateutil.parser.parse(s)
        except sqlite3.OperationalError:
            self.create_tables()

        # clamp maximum historical time
        if now - since_date > datetime.timedelta(days=max_historical_days):
            logger.info("Clamping maximum historical query to %d days." % max_historical_days)
            since_date = now - datetime.timedelta(days=max_historical_days)

        since_date = since_date.strftime("%Y-%m-%dT%H:%M:%S+0000")
        to_date = to_date.strftime("%Y-%m-%d")

        for ioc_type in ioc_types:
            try:
                logger.info("Querying ThreatExchange for %s indicators from %s to %s" % (ioc_type, since_date, to_date))
                for result in ThreatDescriptor.objects(since=since_date, until=to_date, type_=ioc_type,
                                                       limit=tx_limit, retries=tx_retries,
                                                       fields="raw_indicator,owner,indicator{id,indicator},type," +
                                                              "last_updated,share_level,severity,description," +
                                                              "report_urls,status,confidence,threat_type",
                                                       headers=headers):
                    cur = self.dbconn.cursor()
                    try:
                        add_one_result(cur, result)
                    except Exception as e:
                        logger.exception("Exception processing threat descriptor: %s" % result.to_dict())
                        self.dbconn.rollback()
                    else:
                        self.dbconn.commit()
                        owner_cache.add(result.owner["id"])
                    finally:
                        cur.close()
            except pytxFetchError:
                logger.warning("Could not retrieve some IOCs of type %s. Continuing." % ioc_type)
            except Exception as e:
                logger.exception("Unknown exception retrieving IOCs of type %s." % ioc_type)
