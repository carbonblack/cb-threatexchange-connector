from cbint import CbIntegrationDaemon
from cbint.utils.flaskfeed import FlaskFeed
from cbint.utils.feed import generate_feed
from cbint.utils.daemon import Timer, ConfigurationError
import logging
import threading
from version import __version__
import processing_engines
import time
from pytx import access_token
from pytx import ThreatDescriptor
from pytx.errors import pytxFetchError
from datetime import datetime, timedelta
import cbapi
import copy
from collections import defaultdict


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
    def __init__(self, name, configfile, logfile=None, pidfile=None, debug=False):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile,
                                     pidfile=pidfile, debug=debug)
        template_folder = "/usr/share/cb/integrations/threatexchange/content"
        self.flask_feed = FlaskFeed(__name__, False, template_folder)
        self.bridge_options = {}
        self.bridge_auth = {}
        if 'bridge' in self.options:
            self.debug = self.options['bridge'].get("debug", 0)
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

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

        self.logger.debug("generating feed metadata")
        with self.feed_lock:
            self.feed = self.create_feed()
            self.last_sync = "No sync performed"
            self.last_successful_sync = "No sync performed"

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
        self.logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
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
            index = self.flask_feed.generate_html_index(self.feed.retrieve_feed(), self.bridge_options, self.display_name,
                                                        self.cb_image_path, self.integration_image_path,
                                                        self.json_feed_path, self.last_sync)
        return index

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" %
                                                                  (self.directory, self.integration_image_path))

    def on_start(self):
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

    def on_stopping(self):
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

    def get_or_create_feed(self):
        feed_id = self.cb.feed_get_id_by_name(self.feed_name)
        self.logger.info("Feed id for %s: %s" % (self.feed_name, feed_id))
        if not feed_id:
            feed_url = "http://%s:%d%s" % (self.bridge_options["feed_host"], int(self.bridge_options["listener_port"]),
                                           self.json_feed_path)
            self.logger.info("Creating %s feed @ %s for the first time" % (self.feed_name, feed_url))
            # TODO: clarification of feed_host vs listener_address
            result = self.cb.feed_add_from_url(feed_url, True, False, False)

            # TODO: defensive coding around these self.cb calls
            feed_id = result.get('id', 0)

        return feed_id

    def run(self):
        self.logger.info("starting Carbon Black <-> ThreatExchange Connector | version %s" % __version__)

        self.debug = self.get_config_boolean('debug', False)
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        self.cb = cbapi.CbApi(self.get_config_string('carbonblack_server_url', 'https://127.0.0.1'),
                              token=self.get_config_string('carbonblack_server_token'),
                              ssl_verify=self.get_config_boolean('carbonblack_server_sslverify', False))

        self.logger.debug("starting continuous feed retrieval thread")
        work_thread = threading.Thread(target=self.perform_continuous_feed_retrieval)
        work_thread.setDaemon(True)
        work_thread.start()

        self.logger.debug("starting flask")
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
        access_token.init(self.bridge_auth["app_id"], self.bridge_auth["secret_key"])

        ioc_types = self.get_config_string("tx_ioc_types", None)
        if not ioc_types or len(ioc_types.strip()) == 0:
            ioc_types = processing_engines.ALL_INDICATOR_TYPES
        ioc_types = ioc_types.split(',')
        self.bridge_options["ioc_types"] = []

        for ioc_type in ioc_types:
            if ioc_type not in processing_engines.INDICATOR_PROCESSORS:
                self.logger.warning("%s is not a valid IOC type, ignoring" % ioc_type)
            else:
                self.bridge_options["ioc_types"].append(ioc_type)

        self.bridge_options["historical_days"] = self.get_config_integer("tx_historical_days", 7)

        # retrieve once a day by default
        self.bridge_options["feed_retrieval_minutes"] = self.get_config_integer("feed_retrieval_minutes", 120)

        self.bridge_options["minimum_severity"] = self.get_config_string("tx_minimum_severity", "WARNING")
        status_filter = self.get_config_string("tx_status_filter", None)
        if type(status_filter) == str:
            self.bridge_options["status_filter"] = status_filter.split(',')
        else:
            self.bridge_options["status_filter"] = None

        return True

    def perform_continuous_feed_retrieval(self):
        if not self.validated_config:
            self.validate_config()

        sleep_secs = int(self.bridge_options["feed_retrieval_minutes"]) * 60

        while True:
            self.logger.info("Beginning Feed Retrieval")

            try:
                with Timer() as t:
                    self.perform_feed_retrieval()
                self.logger.info("Facebook ThreatExchange feed retrieval succeeded after %0.2f seconds" % t.interval)
                self.get_or_create_feed()
                self.cb.feed_synchronize(self.feed_name)
                self.logger.info("Sleeping for %d seconds" % sleep_secs)
                time.sleep(sleep_secs)
            except Exception as e:
                self.logger.exception("Exception during feed retrieval. Will retry in 60 seconds")
                time.sleep(60)

    def perform_feed_retrieval(self):
        new_feed = self.create_feed()

        tx_limit = self.bridge_options.get('tx_request_limit', 500) or 500
        tx_retries = self.bridge_options.get('tx_request_retries', 5) or 5

        now = datetime.utcnow()
        since_date = now - timedelta(days=self.bridge_options["historical_days"])
        since_date_str = since_date.strftime("%Y-%m-%d")
        until_date = since_date

        while until_date < now:
            until_date += timedelta(days=1)
            until_date_str = until_date.strftime("%Y-%m-%d")

            for ioc_type in self.bridge_options["ioc_types"]:
                self.logger.info("Pulling %s IOCs (%s to %s)" % (ioc_type, since_date_str, until_date_str))
                try:
                    count = 0
                    for result in ThreatDescriptor.objects(since=since_date_str,
                                                           until=until_date_str,
                                                           type_=ioc_type,
                                                           dict_generator=True,
                                                           limit=tx_limit,
                                                           retries=tx_retries,
                                                           fields="raw_indicator,owner,indicator{id,indicator},type,last_updated,share_level,severity,description,report_urls,status"):

                        new_reports = processing_engines.process_ioc(ioc_type,
                                                                     result,
                                                                     minimum_severity=self.bridge_options["minimum_severity"],
                                                                     status_filter=self.bridge_options["status_filter"])

                        for report in new_reports:
                            new_feed.add_report(report)
                            count += 1

                        if count % 1000 == 0:
                            self.logger.info("%s added %d reports for this iteration" % (ioc_type, count))

                    self.logger.info("%s added %d reports TOTAL" % (ioc_type, count))

                except pytxFetchError:
                    self.logger.warning("Could not retrieve some IOCs of type %s. Continuing." % ioc_type)
                except Exception:
                    self.logger.exception("Unknown exception retrieving IOCs of type %s." % ioc_type)

            # update the start date
            since_date_str = until_date_str

        with self.feed_lock:
            self.feed = new_feed


if __name__ == '__main__':
    tx = ThreatExchangeConnector("threatexchangeconnector", "testing.config", logfile="/tmp/cb-tx-test.log", debug=True)
    tx.validate_config()
    tx.perform_feed_retrieval()
    f = file('/tmp/cb-out.json', 'wb')
    f.write(tx.handle_json_feed_request().get_data())
    f.close()
