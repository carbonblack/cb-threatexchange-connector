__author__ = 'jgarman'
from datetime import datetime
import time
import urllib


def start_report(raw_data):
    # TODO: filter based on "status"
    description = raw_data.get('description', '')
    via = raw_data.get('owner', {}).get('name', None)
    email = raw_data.get('owner', {}).get('email', None)

    if via:
        description += " via %s" % via
        if email:
            description += " <%s>" % email

    return {
        "timestamp": int(time.time()),
        "iocs": {},
        "link": "",
        "id": "txid-%s" % raw_data.get('indicator', {}).get('id', 0),
        "title": description
    }


def get_indicator(raw_data):
    return raw_data.get('indicator', {}).get('indicator', None)


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
    return [report]


def process_file_name(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    return [report]


def process_hash_md5(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    return [report]


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
    ipv4_indicator =get_indicator(raw_data)
    if ipv4_indicator and is_ipv4_address(ipv4_indicator):
        report["iocs"]["ipv4"] = [ipv4_indicator]
        return [report]
    else:
        return []


def process_ip_subnet(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    return report


def process_registry_key(raw_data):
    report = start_report(raw_data)
    if not report:
        return []
    return report


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


def process_ioc(ioc_type, raw_data):
    if ioc_type not in INDICATOR_PROCESSORS:
        return []
    else:
        return INDICATOR_PROCESSORS[ioc_type](raw_data)
