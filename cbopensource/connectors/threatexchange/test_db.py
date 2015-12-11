import sys
import traceback

import datetime

from bridge import ThreatExchangeConnector
from pytx import ThreatDescriptor
import sqlite3
import re
import dateutil.parser, dateutil.tz
import json


owner_cache = set()
tz_pattern = re.compile("([^ T]*)[T ](\d+:\d+:\d+)(\.\d+)?(([\+\-Z])(.*))?")
unix_epoch = datetime.datetime(year=1970, month=1, day=1, tzinfo=None)


class InvalidTimestampException(Exception):
    pass


confidence_level_map = [
    [33, "LOW"],
    [67, "MEDIUM"],
    [100, "HIGH"],
]


def confidence_band(confidence):
    for conf_level in confidence_level_map:
        if confidence <= conf_level[0]:
            return conf_level[1]


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
    qvalues = insert_values.keys() + insert_values.values()
    sql_query = "INSERT OR REPLACE INTO indicator_descriptors (%s) VALUES %s" % (", ".join(insert_values.keys()), qstring)

    cur.execute(sql_query, tuple(insert_values.values()))


def create_tables(conn):
    conn.executescript(open('table.sql', 'rb').read())
    conn.commit()


def do_retrieval():
    conn = sqlite3.connect('/tmp/blah.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

    now = datetime.datetime.utcnow()
    since_date = now - datetime.timedelta(days=1)
    to_date = now + datetime.timedelta(days=1)

    try:
        cur = conn.execute("SELECT max(last_updated) FROM indicator_descriptors")
        (since_date, ) = cur.fetchone()
        since_date = dateutil.parser.parse(since_date)
    except sqlite3.OperationalError:
        print "recreating database"
        create_tables(conn)

    since_date = since_date.strftime("%Y-%m-%dT%H:%M:%S+0000")
    to_date = to_date.strftime("%Y-%m-%d")

    print "%s to %s" % (since_date, to_date)

    for result in ThreatDescriptor.objects(since=since_date, until=to_date, type_='IP_ADDRESS',
                                           limit=100, retries=5,
                                           fields="raw_indicator,owner,indicator{id,indicator},type,last_updated," +
                                                  "share_level,severity,description,report_urls,status,confidence," +
                                                  "threat_type"):
        sys.stdout.write('.')
        sys.stdout.flush()

        cur = conn.cursor()
        try:
            add_one_result(cur, result)
        except Exception as e:
            traceback.print_exc()
            print result.to_dict()
            conn.rollback()
        else:
            conn.commit()
            owner_cache.add(result.owner["id"])
        finally:
            cur.close()


def is_ipv4_address(addr):
    try:
        parts = addr.split('.')
        for part in parts:
            part = int(part)
            if part > 255 or part < 0:
                return False
    except:
        return False
    else:
        return True


def process_ip_address(report, raw_data):
    ipv4_indicator = raw_data["indicator"]
    if ipv4_indicator and is_ipv4_address(ipv4_indicator):
        report["iocs"]["ipv4"] = [ipv4_indicator]
        return [report]
    else:
        sys.stderr.write("IP address indicator skipped as it is not an IPv4 address: %s\n" % ipv4_indicator)
        return []


SEVERITY_LEVELS = [
    "UNKNOWN",
    "INFO",
    "WARNING",
    "SUSPICIOUS",
    "SEVERE",
    "APOCALYPSE"
]
SEVERITY_LOOKUP = dict([(value, index) for (index, value) in enumerate(SEVERITY_LEVELS)])
SEVERITY_SCORE_MAP = {
    "UNKNOWN": 10,
    "INFO": 25,
    "WARNING": 40,
    "SUSPICIOUS": 60,
    "SEVERE": 80,
    "APOCALYPSE": 100
}


def get_new_description(raw_data):
    via = raw_data['name']
    via_id = raw_data['owner_id']
    severity_level = raw_data['severity']

    description = ""
    txid = "txid-%s" % severity_level.lower()

    if via:
        description += "Data provided by Threat Exchange Member '%s'" % via
        if via_id:
            description += " with ID of '%s'" % via_id
        description += ". "

        txid += "-%s" % via_id

    description += "All IOCs in this report are severity_level %s." % severity_level

    title = "%s - %s" % (via, severity_level)
    return title, description, txid


def start_report(raw_data):
    title, description, txid = get_new_description(raw_data)
    return {
        "timestamp": int((raw_data["last_updated"] - unix_epoch).total_seconds()),
        "iocs": {},
        "link": "https://developers.facebook.com/products/threat-exchange",
        "id": txid,
        "description": description,
        "title": title,
        "score": SEVERITY_SCORE_MAP.get(raw_data['severity'], 0)
    }


def ResultIter(cursor, arraysize=1000):
    'An iterator that uses fetchmany to keep memory usage down'
    while True:
        results = cursor.fetchmany(arraysize)
        if not results:
            break
        for result in results:
            yield result


def do_generation(tx):
    new_feed = tx.create_feed()

    conn = sqlite3.connect('/tmp/blah.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT * FROM indicator_descriptors,owners where indicator_descriptors.owner_id=owners.id")
    count = 0

    for res in ResultIter(cur):
        new_report = start_report(res)
        new_reports = process_ip_address(new_report, res)

        for report in new_reports:
            new_feed.add_report(report)
            count += 1

    print json.dumps(new_feed.retrieve_feed())


def do_cull():
    pass
    # TODO: remove old data from the database


if __name__ == '__main__':
    tx = ThreatExchangeConnector("threatexchangeconnector", "testing.config", logfile="/tmp/cb-tx-test.log", debug=True)
    tx.validate_config()

    do_cull()
    do_retrieval()
    do_generation(tx)

    # tx.perform_feed_retrieval()
    # f = file('/tmp/cb-out.json', 'wb')
    # f.write(tx.handle_json_feed_request().get_data())
    # f.close()
