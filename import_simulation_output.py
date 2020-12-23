"""
This module is intended to import and convert the digital twin simulation output (log files and network traffic capture)
"""

import csv
import datetime
import ipaddress
import json
import os

from log_entry import LogEntry
from pcap_entry import PcapEntry


def import_simulation_output(path, filename) -> list:
    """Imports digital twin simulation output from common simulation_output_list formats and saves in list."""
    filepath = path + filename
    simulation_output_list = list()
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


def import_static_simulation_output():
    """Imports digital twin simulation output included in repository data directory"""
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data\\')
    log_data = import_simulation_output(import_path, 'use_case_1_plc1.log')
    pcap_frames = import_simulation_output(import_path, 'use_case_1_network_traffic.json')
    return log_data, pcap_frames


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
