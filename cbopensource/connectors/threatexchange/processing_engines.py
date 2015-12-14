import urllib
import logging
import ipaddr
import struct
import datetime

__author__ = 'jgarman'

log = logging.getLogger(__name__)
unix_epoch = datetime.datetime(year=1970, month=1, day=1, tzinfo=None)


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


def get_indicator(raw_data):
    return raw_data["indicator"]


def process_cmd_line(report, raw_data):
    cmdline_indicator = get_indicator(raw_data)
    if not cmdline_indicator:
        return []
    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'cmdline:"%s"' % cmdline_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    report["iocs"]["query"] = [url_query]
    return [report]


def process_domain(report, raw_data):
    domain_indicator = get_indicator(raw_data)
    if domain_indicator:
        report["iocs"]["dns"] = [domain_indicator]
        return [report]
    else:
        return []


def process_file_name(report, raw_data):
    filename_indicator = get_indicator(raw_data)
    if not filename_indicator:
        return []

    filename_indicator = filename_indicator.lower()
    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'filemod:"%s"' % filename_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    report["iocs"]["query"] = [url_query]
    return [report]


def process_hash_md5(report, raw_data):
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


def process_ip_address(report, raw_data):
    ipv4_indicator = raw_data["indicator"]
    if ipv4_indicator and is_ipv4_address(ipv4_indicator):
        report["iocs"]["ipv4"] = [ipv4_indicator]
        return [report]
    else:
        log.debug("IP address indicator skipped as it is not an IPv4 address: %s" % ipv4_indicator)
        return []


def process_ip_subnet(report, raw_data):
    iprange_indicator = get_indicator(raw_data)
    try:
        ipnetwork = ipaddr.IPv4Network(iprange_indicator)
    except ipaddr.AddressValueError:
        log.warning("IP subnet indicator skipped as it is not an IPv4 subnet: %s" % raw_data)
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

        report["iocs"]["query"] = [url_query]
    return report


def process_registry_key(report, raw_data):
    regmod_indicator = get_indicator(raw_data)

    if not regmod_indicator:
        return []

    # normalize the registry indicator
    regmod_indicator = regmod_indicator.lower()
    regmod_indicator = regmod_indicator.rstrip('\\')
    regmod_parts = regmod_indicator.split('\\')

    if regmod_parts[0] == 'hkey_local_machine':
        regmod_parts[0] = 'machine'
    else:
        # we only support hkey_local_machine
        log.warning("Registry indicator skipped as it is not in the HKLM hive: %s" % raw_data)
        return []

    regmod_indicator = "\\registry\\" + "\\".join(regmod_parts)

    url_query = urllib.urlencode(
        {'cb.urlver': 1, 'q': 'regmod:"%s"' % regmod_indicator.replace('"', '\\"')}
    ).replace('+', "%20")

    report["iocs"]["query"] = [url_query]
    return [report]

# COMMENTED OUT SOME OF THESE BECAUSE WE CAN ONLY HAVE 1 QUERY IOC IN EACH REPORT,
# SO WE NEED TO FIGURE OUT THE BEST WAY TO DO THIS (using 'OR' or seperate reports, etc)
INDICATOR_PROCESSORS = {
    "DOMAIN": process_domain,
    "HASH_MD5": process_hash_md5,
    "IP_ADDRESS": process_ip_address,
#    "CMD_LINE": process_cmd_line,
#    "FILE_NAME": process_file_name,
#    "IP_SUBNET": process_ip_subnet,
#    "REGISTRY_KEY": process_registry_key
}
ALL_INDICATOR_TYPES = ','.join(INDICATOR_PROCESSORS)


def process_ioc(raw_data, minimum_severity='WARNING', status_filter=None, minimum_confidence=50):
    ioc_type = raw_data["indicator_type"]

    if ioc_type not in INDICATOR_PROCESSORS:
        return []

    minimum_severity = SEVERITY_LOOKUP.get(minimum_severity, 0)
    current_severity = SEVERITY_LOOKUP.get(raw_data['severity'], 0)
    current_confidence = raw_data['confidence']

    if current_severity < minimum_severity:
        return []

    if current_confidence < minimum_confidence:
        return []

    if type(status_filter) == list and raw_data['status'] not in status_filter:
        return []

    report_template = start_report(raw_data)
    return INDICATOR_PROCESSORS[ioc_type](report_template, raw_data)
