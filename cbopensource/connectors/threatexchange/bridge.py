import logging
from logging.handlers import RotatingFileHandler
import os
import threading
import time
import copy
from collections import defaultdict
from datetime import datetime, timedelta

from cbint import CbIntegrationDaemon
from cbint.utils.flaskfeed import FlaskFeed
from cbint.utils.feed import generate_feed
from cbint.utils.daemon import Timer, ConfigurationError
import cbint.utils.filesystem
import cbapi

from pytx.access_token import access_token

import processing_engines
from txdb import ThreatExchangeDb
from version import __version__

from cbapi.response import CbResponseAPI, Feed
from cbapi.example_helpers import get_object_by_name_or_id
from cbapi.errors import ServerError
import traceback

logger = logging.getLogger(__name__)


class FeedHandler(object):
    def __init__(self, feed_metadata):
        self.feed_metadata = feed_metadata
        self.data = {}
        self.iocs = {}

    def add_report(self, report):
        if len(report.get("iocs", {})) == 0:
            return

        # the de-duplication key is the id
        report_key = report.get('id')
        if not report_key:
            return

        if report_key not in self.data:
            self.data[report_key] = {
                'timestamp': report.get('timestamp'),
                'iocs': {},
                'link': report.get('link'),
                'id': report.get('id'),
                'title': report.get('title'),
                'score': report.get('score')
            }
            self.iocs[report_key] = defaultdict(set)

        for ioc_type in report.get('iocs', {}):
            new_report_iocs = self.iocs[report_key]
            for ioc_value in report['iocs'][ioc_type]:
                new_report_iocs[ioc_type].add(ioc_value)

    def retrieve_feed(self):
        retval = copy.deepcopy(self.feed_metadata)
        retval["reports"] = [self.retrieve_report_for(k) for k in self.data.iterkeys()]
        return retval

    def retrieve_report_for(self, key):
        retval = copy.deepcopy(self.data[key])
        for ioc_type in self.iocs[key]:
            if ioc_type == 'query':
                retval["iocs"][ioc_type] = []
                for url_query in self.iocs[key][ioc_type]:
                    retval["iocs"][ioc_type].append({
                        "index_type": "events",
                        "search_query": url_query
                    })
            else:
                retval["iocs"][ioc_type] = list(self.iocs[key][ioc_type])

        return retval


class ThreatExchangeConnector(CbIntegrationDaemon):
    def __init__(self, name, configfile, logfile=None, pidfile=None, debug=False, dbfile=None):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile,
                                     pidfile=pidfile, debug=debug)
        template_folder = "/usr/share/cb/integrations/threatexchange/content"
        self.db_file = dbfile or "/usr/share/cb/integrations/threatexchange/db/threatexchange.db"
        self.flask_feed = FlaskFeed(__name__, False, template_folder)
        self.bridge_options = {}
        self.bridge_auth = {}

        self.validated_config = self.validate_config()

        self.cb = None
        self.feed_name = "threatexchangeconnector"
        self.display_name = "ThreatExchange"
        self.directory = template_folder
        self.cb_image_path = "/carbonblack.png"
        self.integration_image_path = "/threatexchange.png"
        self.integration_small_image_path = "/threatexchange-small.png"
        self.json_feed_path = "/threatexchange/json"
        self.feed_lock = threading.RLock()

        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])

        self.initialize_logging()

        logger.debug("generating feed metadata")
        with self.feed_lock:
            self.feed = self.create_feed()
            self.last_sync = "No sync performed"
            self.last_successful_sync = "No sync performed"

    def initialize_logging(self):
        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
        root_logger.addHandler(rlh)

    @property
    def integration_name(self):
        return 'Cb ThreatExchange Connector 1.2.3'

    def create_feed(self):
        return FeedHandler(generate_feed(
            self.feed_name,
            summary="Connector for Threat intelligence data from Facebook ThreatExchange",
            tech_data="""This connector enables members of the Facebook ThreatExchange to import threat indicators
                from the ThreatExchange, including domain names, IPs, hashes, and behavioral indicators, into Carbon
                Black. The Facebook ThreatExchange and its members provide and maintain this data. This connector
                requires an Access Token to the Facebook ThreatExchange API.  For more information, visit:
                https://developers.facebook.com/products/threat-exchange/""",
            provider_url="https://developers.facebook.com/products/threat-exchange",
            icon_path="%s/%s" % (self.directory, self.integration_image_path),
            small_icon_path="%s/%s" % (self.directory, self.integration_small_image_path),
            display_name=self.display_name,
            category="Partner"))

    def serve(self):
        address = self.bridge_options.get('listener_address', '127.0.0.1')
        port = self.bridge_options.get('listener_port', 6120)
        logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=False,
                                host=address, use_reloader=False)

    def handle_json_feed_request(self):
        with self.feed_lock:
            json = self.flask_feed.generate_json_feed(self.feed.retrieve_feed())
        return json

    def handle_html_feed_request(self):
        with self.feed_lock:
            html = self.flask_feed.generate_html_feed(self.feed.retrieve_feed(), self.display_name)
        return html

    def handle_index_request(self):
        with self.feed_lock:
            index = self.flask_feed.generate_html_index(self.feed.retrieve_feed(), self.bridge_options,
                                                        self.display_name,
                                                        self.cb_image_path, self.integration_image_path,
                                                        self.json_feed_path, self.last_sync)
        return index

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" %
                                                                  (self.directory, self.integration_image_path))

    def get_or_create_feed(self):
        feed_id = None
        try:
            feeds = get_object_by_name_or_id(self.cb, Feed, name=self.feed_name)
        except Exception as e:
            logger.error(e.message)
            feeds = None

        if not feeds:
            logger.info("Feed {} was not found, so we are going to create it".format(self.feed_name))
            f = self.cb.create(Feed)
            f.feed_url = "http://%s:%d%s" % (
                self.bridge_options["feed_host"], int(self.bridge_options["listener_port"]),
                self.json_feed_path)

            f.enabled = True
            f.use_proxy = False
            f.validate_server_cert = False
            try:
                f.save()
            except ServerError as se:
                if se.error_code == 500:
                    logger.info("Could not add feed:")
                    logger.info(
                        " Received error code 500 from server. This is usually because the server cannot retrieve the feed.")
                    logger.info(
                        " Check to ensure the Cb server has network connectivity and the credentials are correct.")
                else:
                    logger.info("Could not add feed: {0:s}".format(str(se)))
            except Exception as e:
                logger.info("Could not add feed: {0:s}".format(str(e)))
            else:
                logger.info("Feed data: {0:s}".format(str(f)))
                logger.info("Added feed. New feed ID is {0:d}".format(f.id))
                f.synchronize(False)

        elif len(feeds) > 1:
            logger.warning("Multiple feeds found, selecting Feed id {}".format(feeds[0].id))

        elif feeds:
            feed_id = feeds[0].id
            logger.info("Feed {} was found as Feed ID {}".format(self.feed_name, feed_id))
            feeds[0].synchronize(False)

        return feed_id

    def run(self):
        logger.info("starting Carbon Black <-> ThreatExchange Connector | version %s" % __version__)

        try:
            self.cb = CbResponseAPI(url=self.get_config_string('carbonblack_server_url', 'https://127.0.0.1'),
                                    token=self.get_config_string('carbonblack_server_token'),
                                    ssl_verify=self.get_config_boolean('carbonblack_server_sslverify', False),
                                    integration_name=self.integration_name)
            self.cb.info()
        except:
            logger.error(traceback.format_exc())
            return False

        logger.debug("starting continuous feed retrieval thread")
        work_thread = threading.Thread(target=self.perform_continuous_feed_retrieval)
        work_thread.setDaemon(True)
        work_thread.start()

        logger.debug("starting flask")
        self.serve()

    def check_required_options(self, opts):
        CbIntegrationDaemon.check_required_options(self, opts)
        for opt in opts:
            val = self.cfg.get("bridge", opt)
            if not val or len(val) == 0:
                raise ConfigurationError("Configuration file has option %s in [bridge] section but not set to value " %
                                         opt)

    def validate_config(self):
        super(ThreatExchangeConnector, self).validate_config()
        self.check_required_options(["tx_app_id", "tx_secret_key", "carbonblack_server_token"])

        self.bridge_options["listener_port"] = self.get_config_integer("listener_port", 6120)
        self.bridge_options["feed_host"] = self.get_config_string("feed_host", "127.0.0.1")
        self.bridge_options["listener_address"] = self.get_config_string("listener_address", "0.0.0.0")

        self.bridge_auth["app_id"] = self.get_config_string("tx_app_id")
        self.bridge_auth["secret_key"] = self.get_config_string("tx_secret_key")
        access_token(self.bridge_auth["app_id"], self.bridge_auth["secret_key"])

        ioc_types = self.get_config_string("tx_ioc_types", None)
        if not ioc_types or len(ioc_types.strip()) == 0:
            ioc_types = processing_engines.ALL_INDICATOR_TYPES
        ioc_types = ioc_types.split(',')
        self.bridge_options["ioc_types"] = []

        for ioc_type in ioc_types:
            if ioc_type not in processing_engines.INDICATOR_PROCESSORS:
                logger.warning("%s is not a valid IOC type, ignoring" % ioc_type)
            else:
                self.bridge_options["ioc_types"].append(ioc_type)

        self.bridge_options["historical_days"] = self.get_config_integer("tx_historical_days", 7)

        # retrieve once a day by default
        self.bridge_options["feed_retrieval_minutes"] = self.get_config_integer("feed_retrieval_minutes", 120)

        self.bridge_options["minimum_severity"] = self.get_config_string("tx_minimum_severity", "WARNING")
        self.bridge_options["minimum_confidence"] = int(self.get_config_string("tx_minimum_confidence", 50))
        status_filter = self.get_config_string("tx_status_filter", None)
        if type(status_filter) == str:
            self.bridge_options["status_filter"] = status_filter.split(',')
        else:
            self.bridge_options["status_filter"] = None

        return True

    def perform_continuous_feed_retrieval(self):
        if not self.validated_config:
            self.validate_config()

        proxy_host = self.get_config_string("https_proxy", None)
        if proxy_host:
            os.environ['HTTPS_PROXY'] = proxy_host
            os.environ['no_proxy'] = '127.0.0.1,localhost'

        sleep_secs = int(self.bridge_options["feed_retrieval_minutes"]) * 60

        while True:
            logger.info("Beginning Feed Retrieval")

            try:
                with Timer() as t:
                    self.perform_feed_retrieval()
                logger.info("Facebook ThreatExchange feed retrieval succeeded after %0.2f seconds" % t.interval)
                self.get_or_create_feed()
                logger.info("Sleeping for %d seconds" % sleep_secs)
                time.sleep(sleep_secs)
            except Exception as e:
                logger.exception("Exception during feed retrieval. Will retry in 60 seconds")
                time.sleep(60)

    def perform_feed_retrieval(self):
        new_feed = self.create_feed()

        with ThreatExchangeDb(self.db_file) as db:
            now = datetime.utcnow()
            since_date = now - timedelta(days=self.bridge_options["historical_days"])
            db.cull_before(since_date)

            tx_limit = self.bridge_options.get('tx_request_limit', 500) or 500
            tx_retries = self.bridge_options.get('tx_request_retries', 5) or 5

            db.update(self.bridge_options["ioc_types"], tx_limit, tx_retries)

            minimum_severity = self.bridge_options["minimum_severity"]
            status_filter = self.bridge_options["status_filter"]
            minimum_confidence = self.bridge_options["minimum_confidence"]

            for report in db.generate_reports(minimum_severity, status_filter, minimum_confidence):
                new_feed.add_report(report)

        with self.feed_lock:
            self.feed = new_feed


if __name__ == '__main__':
    tx = ThreatExchangeConnector("threatexchangeconnector", "testing.config", logfile="/tmp/cb-tx-test.log",
                                 dbfile="./tx.db", debug=True)
    tx.validate_config()
    tx.perform_feed_retrieval()
    f = file('/tmp/cb-out.json', 'wb')
    f.write(tx.handle_json_feed_request().get_data())
    f.close()
