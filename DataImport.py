import csv
import datetime
import json
import ipaddress
import click

from typing import List, Any, Type

from log_entry import LogEntry
from pcap_entry import PcapEntry

applicable_rel = list()
sdo_list = list()


def import_stix21_relationships(path, filename) -> list:
    """Imports STIX2.1 relationships and saves in list."""
    filepath = path + filename
    rel_list: List[List[str]] = list()
    with open(filepath, 'rt', encoding='utf-8-sig') as f:
        reader = csv.reader(f, delimiter=',', skipinitialspace=True)
        for line in reader:
            rel_list.append(line)
    return rel_list


def search_stix21_objects(rel_list, object_name, rel_type='any') -> list:
    """Searches STIX2.1 relationship list for relationships that include a given object and are of specified type."""
    searched_rel_list: List[Any] = list()
    for relationship in rel_list:
        if relationship[3] == rel_type or rel_type == 'any':
            if relationship[0] == object_name and relationship[0] == relationship[2]:
                searched_rel_list.append(relationship)
            else:
                for position in range(len(relationship)):
                    if relationship[position] == object_name:
                        searched_rel_list.append(relationship)
    return searched_rel_list


def import_simulation_output(path, filename) -> list:
    """Imports digital twin simulation output from common simulation_output_list formats and saves in list."""
    filepath = path + filename
    simulation_output_list: List[List[str]] = list()
    with open(filepath, 'rt', encoding='utf-8-sig') as f:
        if filename.endswith(('.txt', '.log', 'csv')):
            reader = csv.reader(f, delimiter=' ', skipinitialspace=True)
            for line in reader:
                simulation_output_list.append(line)
            print('Simulation output imported (type:log file)')
        elif filename.endswith('.json'):
            simulation_output_list = json.load(f)
            print('Simulation output imported (type:pcap file)')
    return simulation_output_list


def convert_log_entries(simulation_output):
    """Converts a list of log entries to LogEntry class instances and saves objects in list."""
    log_entry_list = list()
    for line in simulation_output:
        level = line[0]
        timestamp = convert_log_timestamp(line)
        ip_addr_host = line[3]
        program = line[4]
        message = ' '.join(line[5:])
        ip_addr_external = analyze_log_message_ip(message)
        log_entry_list.append(LogEntry(level, timestamp, ip_addr_host, program, message, ip_addr_external))
    print('Log entries converted')
    return log_entry_list


def convert_log_timestamp(log) -> datetime:
    """Converts timestamp information of a log entry into a datetime object"""
    log_timestamp = log[1] + log[2]
    return datetime.datetime.strptime(log_timestamp, '%m/%d/%Y%H:%M:%S')


def analyze_log_message_ip(message) -> str:
    """Checks for additional IP address in log message (e.g. log event triggered by external entity)."""
    for element in message.split():
        try:
            ipaddress.ip_address(element[:-1])
            return element[:-1]
        except ValueError:
            pass


def convert_pcap_frames(simulation_output):
    """Converts a list of pcap frames to PcapEntry class instances and saves objects in list."""
    pcap_frame_list = list()
    counter = 0
    for element in simulation_output:
        timestamp = convert_pcap_timestamp(element['_source']['layers']['frame']['frame.time'])
        protocol = element['_source']['layers']['frame']['frame.protocols']
        eth_src = element['_source']['layers']['eth']['eth.src']
        eth_dst = element['_source']['layers']['eth']['eth.dst']
        message = 0  # element
        if protocol.rpartition(':')[2] == 'arp':
            arp_mac_addr = element['_source']['layers']['arp']['arp.src.hw_mac']
            arp_ip_addr = element['_source']['layers']['arp']['arp.src.proto_ipv4']
            for key in element['_source']['layers']:
                if 'Duplicate' in key:
                    arp_info = key
                    # print(arp_info)
                    pcap_frame_list.append(PcapEntry(timestamp, protocol, eth_src, eth_dst, message, arp_mac_addr,
                                                     arp_ip_addr, arp_info))
        elif protocol.rpartition(':')[2] == 'tcp':
            ip_src = element['_source']['layers']['ip']['ip.src']
            ip_dst = element['_source']['layers']['ip']['ip.dst']
            tcp_src_port = element['_source']['layers']['tcp']['tcp.srcport']
            tcp_dst_port = element['_source']['layers']['tcp']['tcp.dstport']
            pcap_frame_list.append(PcapEntry(timestamp, protocol, eth_src, eth_dst, message, None, None, None, ip_src,
                                             ip_dst, tcp_src_port, tcp_dst_port))
        elif protocol.rpartition(':')[2] == 'icmp':
            icmp_type = element['_source']['layers']['icmp']['icmp.type']
            icmp_code = element['_source']['layers']['icmp']['icmp.code']
            pcap_frame_list.append(PcapEntry(timestamp, protocol, eth_src, eth_dst, message, None, None, None, None,
                                             None, None, None, icmp_type, icmp_code))
        elif protocol.rpartition(':')[2] == 'enip':
            ip_src = element['_source']['layers']['ip']['ip.src']
            #print(ip_src)
            ip_dst = element['_source']['layers']['ip']['ip.dst']
            #print(ip_dst)
            tcp_src_port = element['_source']['layers']['tcp']['tcp.srcport']
            #print(tcp_src_port)
            tcp_dst_port = element['_source']['layers']['tcp']['tcp.dstport']
            pcap_frame_list.append(PcapEntry(timestamp, protocol, eth_src, eth_dst, message, None, None, None, ip_src,
                                             ip_dst, tcp_src_port, tcp_dst_port))
        else:
            pcap_frame_list.append(PcapEntry(timestamp, protocol, eth_src, eth_dst, message))
            #counter += 1
    #print('Number of unspecified pcap frames: {}' .format(counter))
    print('Pcap frames converted')
    return pcap_frame_list


def convert_pcap_timestamp(frame_timestamp) -> datetime:
    """Converts timestamp information of a pcap frame into a datetime object"""
    return datetime.datetime.strptime(frame_timestamp[:-32], '%b %d, %Y %H:%M:%S.%f')


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


def build_sco_list(sco_list):
    """Allows the user to build a custom SCO list out of all available SCOs."""
    custom_sco_list = list()
    for element in sco_list:
        answer = str(input('Do you want to select {}? (yes/no) '.format(element[1])))
        if answer.lower()[:1] == 'y':
            custom_sco_list.append(element)
        elif answer.lower()[:1] == 'n':
            pass
        while answer.lower()[:1] != 'y' and answer.lower()[:1] != 'n':
            print("Please enter y (yes) or n (no)")
            answer = str(input('Do you want to select {}? (yes/no) '.format(element[1])))
            if answer.lower()[:1] == 'y':
                custom_sco_list.append(element)
            elif answer.lower()[:1] == 'n':
                pass
    return custom_sco_list


def build_sdo_list(rel_list, scosdo_list, rel_type='any'):
    """Allows the user to build a custom STIX2.1 objects list out of all available relatioships."""
    rel_list_current = rel_list
    custom_scosdo_list = list()
    custom_sro_list = list()
    for element in scosdo_list:
        for rel in search_stix21_objects(rel_list_current, element[0], rel_type):
            answer = str(input('Do you want to select this relationship and associated objects {}? (yes/no) '.format(rel)))
            while answer.lower()[:1] != 'y' and answer.lower()[:1] != 'n':
                print("Please enter y (yes) or n (no)")
                answer = str(input('Do you want to select this relationship and associated objects {}? (yes/no) '
                                   .format(rel)))
            if answer.lower()[:1] == 'y':
                custom_scosdo_list.append(rel[0])
                custom_scosdo_list.append(rel[2])
                custom_sro_list.append(rel)
                rel_list_current.remove(rel)
            elif answer.lower()[:1] == 'n':
                pass
    return sorted(set(custom_scosdo_list)), custom_sro_list


def standardize_scos(sco_list, simulation_output, entry_type):
    """Generates given SCOs with simulation output values based on log or pcap entry."""
    sco_list_json = list()
    for element in sco_list:
        sco_type = element[1]
    return


def parse_simulation_output(simulation_output):
    """Parses digital twin simulation output into STIX2.1 SCOs"""
    print("results are SCOs")


def assess_relationship(relationship):
    applicable_rel.append(relationship)
    print("Relationship and its objects have been added")


def pretty_print_list(list):
    print('The provided list contains the following elements:')
    for element in list:
        print(element)


if __name__ == '__main__':
    print('')
    print('-------------------------------------------')
    print('')
    '''Import and save simulation output from given log file'''
    simulation_output_log = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
                                                     "Filling-plant logs\\", "NEWplc1.log")
    '''Convert imported simulation output to LogEntry objects'''
    converted_logs = convert_log_entries(simulation_output_log)
    '''Provide target information about the log entries contained in the simulation output'''
    print(get_all_ip_addr(converted_logs))
    '''Provide time information about the log entries contained in the simulation output'''
    print(get_timespan(converted_logs))
    '''Provide type information about the log entries contained in the simulation output'''
    print(get_all_severity_level(converted_logs))
    '''Perform filtering based on time, target and type'''
    filtered_ip = filter_log_ip(converted_logs, '10.0.0.1')
    filtered_severity = filter_log_severity(filtered_ip, 'WARNING')
    filtered_time = filter_timestamps(filtered_severity, datetime.timedelta(0, 8, 0, 0, 0),
                                      datetime.datetime(2020, 8, 17, 13, 51, 00))
    pretty_print_list(filtered_time)
    print('')
    print('-------------------------------------------')
    print('')
    print('Generated STIX2.1 SCOs from log entries:')
    '''Generate STIX2.1 SCOs for given log entry'''
    ip1 = filtered_time[0].generate_ipv4_addr('host')
    ip3 = filtered_time[0].generate_ipv4_addr('external')
    process = filtered_time[0].generate_process()
    print(ip1, ip3, process)
    print('')
    print('-------------------------------------------')
    print('')
    '''Import and save simulation output from given pcap file'''
    simulation_output_pcap = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation "
                                                      "Output\\Use Case 1\\", "2501.json")
    '''Convert imported simulation output to PcapEntry objects'''
    converted_pcap = convert_pcap_frames(simulation_output_pcap)

    '''Provide time information about the pcap frames contained in the simulation output'''
    print(get_timespan(converted_pcap))
    '''Provide protocol type information about the pcap frames contained in the simulation output'''
    print(get_all_protocols(converted_pcap))
    print('')
    print('-------------------------------------------')
    print('')
    #filter_enip = filter_protocols(converted_pcap, 'eth:ethertype:ip:tcp:enip:cip:cipcm:cipcls')
    filter_enip = filter_protocols(converted_pcap, 'eth:ethertype:ip:tcp:enip')
    pretty_print_list(filter_enip)
    print('')
    print('-------------------------------------------')
    print('')
    filtered_protocol = filter_protocols(converted_pcap, 'eth:ethertype:arp')
    filtered_pcap_time = filter_timestamps(converted_pcap, datetime.timedelta(0, 0, 500, 0, 0))
    print(filter_timestamps(converted_pcap, datetime.timedelta(0, 0, 500, 0, 0)))
    print('')
    print('-------------------------------------------')
    print('')
    for result in filtered_pcap_time[2].generate_network_traffic():
        print(result)
    print('')
    print('-------------------------------------------')
    print('')
    ''' Import a txt file containing all STIX2.1 relationships'''
    rel_list1 = import_stix21_relationships("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\STIX Relationship Data\\",
                                           "done_STIX21_SCO+SDO_relationship_list_all.txt")
    '''Searching the relationship list for a STIX2.1 object with specified relationship type '''
    search_list1 = search_stix21_objects(rel_list1, "observed-data")
    for entry in search_list1:
        print(entry)
    '''Import the output of digital twin simulation'''
    # print(import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\", "DOS.json"))
    # test1 = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\Filling-plant logs\\", "plc1.log")

    # print(extract_timestamp(test1[0]))
    # print(extract_timestamp(test1[0]) - datetime.timedelta(0, 7))

    print('')
    print('-------------------------------------------')
    print('')
    sco_list = import_stix21_relationships("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\STIX Relationship Data\\",
                                       "done_STIX21_SCO_list.txt")
    pretty_print_list(filter_scos(sco_list, 'network'))
    print('')
    print('-------------------------------------------')
    print('')
    print('Build initial custom SCO list')
    static_SCO_list = [['ipv4-addr', 'IPv4 Address Object', 'network'], ['mac-addr', 'MAC Address Object', 'network'],
                   ['network-traffic', 'Network Traffic Object', 'network'], ['process', 'Process Object', 'host']]
    #pretty_print_list(static_SCO_list)
    #initial_custom_SCO_list = build_sco_list(sco_list)
    print('')
    #pretty_print_list(initial_custom_SCO_list)
    print('')
    print('-------------------------------------------')
    print('')
    print('Search for relationships (SCO embedded & SDO direct) of given SCO list')
    #custom_SCO_SCO_rel_list = build_sdo_list(rel_list1, initial_custom_SCO_list)
    custom_SCO_SCO_rel_list = build_sdo_list(rel_list1, static_SCO_list)

    #for list in custom_SCO_SCO_rel_list:
       #pretty_print_list(custom_SCO_SCO_rel_list)
    print('')
    print('-------------------------------------------')
    print('')


    # custom_list = build_sco_list(test)
    #      pretty_print_list(build_sdo_list(rel_list1, custom_list))

    # print(custom_list)

    # all_rel_list = import_stix21_relationships()

    arp_frames = filtered_protocol
    pretty_print_list(arp_frames)
    list_arp = list()
    for element in arp_frames:
        list_arp.append(element.generate_ipv4_addr())
    #for element in list_arp:
    #    pretty_print_list(element)


    '''
    try:
        print("This script retrieves relationships between STIX2.1 objects")
        search_object = str(input("Enter a STIX2.1 object name (lowercase encoding) to retrieve its "
                                   "possible relationships: "))
        search_rel_type = str(input("Enter relationship type (direct or embedded): "))
        search_stix21object(search_object, search_rel_type)
    except ValueError:
        print("Please enter a valid number")
    '''
