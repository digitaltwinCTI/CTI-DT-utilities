from stix2.v21 import *
import uuid
import json


class PcapEntry:
    def __init__(self, timestamp=None, protocol=None, eth_src=None, eth_dst=None, message=None,
                 arp_mac_addr=None, arp_ip_addr=None, arp_info=None, ip_src=None, ip_dst=None, tcp_src_port=None,
                 tcp_dst_port=None, icmp_type=None, icmp_code=None):
        self.timestamp = timestamp
        self.protocol = protocol
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.arp_mac_addr = arp_mac_addr
        self.arp_ip_addr = arp_ip_addr
        self.arp_info = arp_info
        self.message = message
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.tcp_src_port = tcp_src_port
        self.tcp_dst_port = tcp_dst_port
        self.icm_type = icmp_type
        self.icm_code = icmp_code

    def __repr__(self):
        if self.protocol == 'eth:ethertype:arp':
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.arp_ip_addr}' \
                   f' {self.arp_mac_addr} {self.arp_info} {self.message}'
        elif self.protocol == 'eth:ethertype:ip:tcp':
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.ip_src} {self.ip_dst}' \
                   f' {self.tcp_src_port} {self.tcp_dst_port} {self.message}'
        elif self.protocol == 'eth:ethertype:ip:icmp':
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.message}'
        elif self.protocol == 'eth:ethertype:ip:tcp:enip':
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.message}'
        else:
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.message}'

    def add_message_element(self, data):
        self.message = self.message + data

    def generate_ipv4_addr(self):
        ipv4_addr = IPv4Address(
            id="ipv4-addr--" + str(uuid.uuid4()),
            value=self.ip_dst
        )
        return ipv4_addr

    def generate_mac_addr(self):
        mac_addr = MACAddress(
            id="mac-addr--" + str(uuid.uuid4()),
            value=self.arp_mac_addr
        )
        return mac_addr
