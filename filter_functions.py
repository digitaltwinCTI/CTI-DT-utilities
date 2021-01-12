"""
This module is intended to provide filtering functionality for the digital twin simulation output
"""

import datetime


def filter_log_severity(log_entry_list, level: str) -> list:
    """Filters log entries based on given severity log level."""
    filtered_log_entries = list()
    for entry in log_entry_list:
        if entry.loglevel.lower() == level.lower():
            filtered_log_entries.append(entry)
    print('Log entries filtered based on {}'.format(level))
    return filtered_log_entries


def filter_timestamps(entry_list, deviation: datetime.timedelta, center_timestamp=None) -> list:
    """Filters entries based on given timestamp and given plus/minus time deviation."""
    filtered_entries = list()
    default_center_timestamp = entry_list[int(len(entry_list) / 2)].timestamp
    for entry in entry_list:
        if center_timestamp is not None:
            if center_timestamp - deviation < entry.timestamp < center_timestamp + deviation:
                filtered_entries.append(entry)
                # print(entry.timestamp, entry.loglevel, entry.message)
        else:
            if default_center_timestamp - deviation < entry.timestamp < default_center_timestamp + deviation:
                filtered_entries.append(entry)
                # print(entry.timestamp, entry.loglevel, entry.message)
    print('Entries filtered based on {} timestamp with {} deviation'.format(center_timestamp, deviation))
    return filtered_entries


def filter_log_ip(log_entry_list, ip_addr: str, host_only=True):
    """Filters log entries based on given IP address (default only for host IP address)."""
    filtered_log_entries = list()
    for entry in log_entry_list:
        if not host_only and (ip_addr == entry.ip_addr_host or ip_addr == entry.ip_addr_external):
            filtered_log_entries.append(entry)
        elif host_only and ip_addr == entry.ip_addr_host:
            filtered_log_entries.append(entry)
    print('Log entries filtered based on {} and host only {}'.format(ip_addr, host_only))
    return filtered_log_entries


def filter_protocols(pcap_frame_list, protocol: str) -> list:
    """Filters pcap frames based on given protocol type."""
    filtered_pcap_frames = list()
    for entry in pcap_frame_list:
        if entry.protocol == protocol:
            filtered_pcap_frames.append(entry)
    print('Pcap frames filtered based on {}'.format(protocol))
    return filtered_pcap_frames


def get_all_severity_level(log_entry_list):
    """Gets all distinct severity log levels found in the log entry list."""
    severity_list = list()
    for entry in log_entry_list:
        severity_list.append(entry.loglevel)
    print('Severity log levels identified within all log entries:')
    return sorted(set(severity_list))


def get_all_protocols(pcap_frame_list):
    """Gets all distinct protocols found in the pcap entry list."""
    protocol_list = list()
    for entry in pcap_frame_list:
        protocol_list.append(entry.protocol)
    print('Protocols identified within all pcap entries:')
    return sorted(set(protocol_list))


def get_timespan(entry_list):
    """Gets first and last timestamp found in the entry list."""
    first_last_timestamp_list = list()
    first_last_timestamp_list.append(entry_list[0].timestamp)
    first_last_timestamp_list.append(entry_list[len(entry_list) - 1].timestamp)
    print('First and last timestamp identified within all entries:')
    return first_last_timestamp_list


def get_all_ip_addr(log_entry_list):
    """Gets all distinct IP addresses found in the log entry list."""
    ip_addr_list = list()
    for entry in log_entry_list:
        ip_addr_list.append(entry.ip_addr_host)
        if entry.ip_addr_external is not None:
            ip_addr_list.append(entry.ip_addr_external)
    print('IP addresses of network topology identified within all log entries:')
    return sorted(set(ip_addr_list))


def get_rfc3339_timestamp(timestamp):
    """Gets an RFC 3339-formatted timestamp in UTC timezone (e.g. 2020-08-17T10:23:37.149Z)"""
    return timestamp.isoformat('T') + 'Z'


def filter_scos(sco_list, sco_type='any'):
    """Filters list of all possible SCOs based on type of SCO (either host, network of any)."""
    filtered_sco_list = list()
    for entry in sco_list:
        if entry[2] == sco_type.lower():
            filtered_sco_list.append(entry)
        elif sco_type == 'any':
            filtered_sco_list = sco_list
    print('STIX2.1 SCOs of type {}:'.format(sco_type))
    return filtered_sco_list
