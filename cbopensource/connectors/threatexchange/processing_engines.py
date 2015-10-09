__author__ = 'jgarman'
import time
import urllib
import logging
import re
import ipaddr
import struct


log = logging.getLogger(__name__)


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


def get_original_description(raw_data):
    description = raw_data.get('description', '')
    via = raw_data.get('owner', {}).get('name', None)
    email = raw_data.get('owner', {}).get('email', None)

    txid = raw_data.get('indicator', {}).get('id', None)
    if not txid:
        txid = raw_data.get('id', None)
        if not txid:
            log.warning("No id associated with indicator: %s" % raw_data)
            return []

    if not description:
        description = "(no description provided)"
    if via:
        description += " via %s" % via
        if email:
            description += " <%s>" % email

    return description, "txid-%s" % txid


strip_non_alphanum = re.compile('[\W_]+', re.UNICODE)


def get_new_description(raw_data):
    via = raw_data.get('owner', {}).get('name', None)
    via_id = raw_data.get('owner', {}).get('id', None)
    severity_level = raw_data.get('severity', 'UNKNOWN')

    description = ""
    txid = "txid-%s" % severity_level.lower()

    if via:
        description += "Data provided by Threat Exchange Member '%s'" % via
        if via_id:
            description += " with ID of '%s'" % via_id
        description += ". "

        txid += "-%s" % strip_non_alphanum.sub('-', via)

    description += "All IOCs in this report are severity_level %s." % severity_level

    return description, txid


def start_report(raw_data):
    description, txid = get_new_description(raw_data)
    return {
        "timestamp": int(time.time()),
        "iocs": {},
        "link": "https://developers.facebook.com/products/threat-exchange",
        "id": txid,
        "title": description,
        "score": SEVERITY_SCORE_MAP.get(raw_data.get('severity', 'UNKNOWN'), 0)
    }


def get_indicator(raw_data):
    indicator = raw_data.get('indicator', {}).get('indicator', None)
    if not indicator:
        # fall back to use the "root" raw_indicator
        indicator = raw_data.get('raw_indicator', None)

    return indicator


def process_cmd_line(raw_data):
    report = start_report(raw_data)
    if not report:
        return []

    cmdline_indicator = get_indicator(raw_data)
    if not cmdline_indicator:
        return []
    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'cmdline:"%s"' % cmdline_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    query_specification = {
        "index_type": "events",
        "search_query": url_query
    }
    report["iocs"]["query"] = [query_specification]
    return [report]


def process_domain(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    domain_indicator = get_indicator(raw_data)
    if domain_indicator:
        report["iocs"]["dns"] = [domain_indicator]
        return [report]
    else:
        return []


def process_file_name(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    filename_indicator = get_indicator(raw_data)
    if not filename_indicator:
        return []
    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'filemod:"%s"' % filename_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    query_specification = {
        "index_type": "events",
        "search_query": url_query
    }
    report["iocs"]["query"] = [query_specification]
    return [report]


def process_hash_md5(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    md5_indicator = get_indicator(raw_data)
    if md5_indicator:
        report["iocs"]["md5"] = [md5_indicator]
        return [report]
    else:
        return []


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


def process_ip_address(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    ipv4_indicator = get_indicator(raw_data)
    if ipv4_indicator and is_ipv4_address(ipv4_indicator):
        report["iocs"]["ipv4"] = [ipv4_indicator]
        return [report]
    else:
        return []


def process_ip_subnet(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    iprange_indicator = get_indicator(raw_data)
    try:
        ipnetwork = ipaddr.IPv4Network(iprange_indicator)
    except ipaddr.AddressValueError:
        return []

    if ipnetwork.prefixlen > 24:
        report["iocs"]["ipv4"] = []
        for h in ipnetwork.iterhosts():
            report["iocs"]["ipv4"].append(str(h))
    else:
        beginning_ip_address = struct.unpack('>i', ipnetwork.ip.packed)[0]
        end_ip_address = beginning_ip_address + ipnetwork.numhosts - 1
        url_query = urllib.urlencode(
            {'cb.urlver': 1, 'q': 'ipaddr:[%s TO %s]' % (beginning_ip_address, end_ip_address)}
        ).replace('+', "%20")

        query_specification = {
            "index_type": "events",
            "search_query": url_query
        }

        report["iocs"]["query"] = [query_specification]
    return report


def process_registry_key(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    regmod_indicator = get_indicator(raw_data)

    if not regmod_indicator:
        return []

    # normalize the registry indicator
    regmod_indicator = regmod_indicator.lower()
    regmod_parts = regmod_indicator.split('\\')

    if regmod_parts[0] == 'hkey_local_machine':
        regmod_parts[0] = 'machine'
    else:
        # we only support hkey_local_machine
        return []

    regmod_indicator = "\\registry\\" + "\\".join(regmod_parts)

    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'regmod:"%s"' % regmod_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    query_specification = {
        "index_type": "events",
        "search_query": url_query
    }
    report["iocs"]["query"] = [query_specification]
    return [report]


INDICATOR_PROCESSORS = {
    "CMD_LINE": process_cmd_line,
    "DOMAIN": process_domain,
    "FILE_NAME": process_file_name,
    "HASH_MD5": process_hash_md5,
    "IP_ADDRESS": process_ip_address,
    "IP_SUBNET": process_ip_subnet,
    "REGISTRY_KEY": process_registry_key
}
ALL_INDICATOR_TYPES = ','.join(INDICATOR_PROCESSORS)


def process_ioc(ioc_type, raw_data, minimum_severity='WARNING', status_filter=None):
    if ioc_type not in INDICATOR_PROCESSORS:
        return []

    minimum_severity = SEVERITY_LOOKUP.get(minimum_severity, 0)
    current_severity = SEVERITY_LOOKUP.get(raw_data.get('severity', 'UNKNOWN'), 0)

    if current_severity < minimum_severity:
        return []

    if type(status_filter) == list and raw_data.get('status', 'UNKNOWN') not in status_filter:
        return []

    return INDICATOR_PROCESSORS[ioc_type](raw_data)
