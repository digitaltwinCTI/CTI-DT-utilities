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
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.ip_src} {self.ip_dst}' \
                   f' {self.tcp_src_port} {self.tcp_dst_port} {self.message} '
        else:
            return f'{self.timestamp} {self.protocol} {self.eth_src} {self.eth_dst} {self.message}'

    def add_message_element(self, data):
        self.message = self.message + data

    def generate_ipv4_addr(self, ip_type=None):
        if self.protocol[-3:] == 'arp':
            mac = self.generate_mac_addr()
            ipv4_addr = IPv4Address(
                value=self.arp_ip_addr,
                resolves_to_refs=mac.id
            )
            return mac, ipv4_addr
        elif ip_type == 'src':
            ipv4_addr = IPv4Address(
                value=self.ip_src
            )
        elif ip_type == 'dst':
            ipv4_addr = IPv4Address(
                value=self.ip_dst
            )
        else:
            print('Please specify IP address type (src or dst)')
            return
        return ipv4_addr

    def generate_network_traffic(self, instantiated_stix21_objects=None):
        if self.protocol[-4:] == 'enip':
            source = None
            destination = None
            for object in instantiated_stix21_objects:
                if object.type == 'ipv4-addr':
                    if self.ip_src == object.value:
                        source = object
                    elif self.ip_dst == object.value:
                        destination = object
            if source is None:
                source = self.generate_ipv4_addr('src')
            elif destination is None:
                destination = self.generate_ipv4_addr('dst')

            traffic = NetworkTraffic(
                start=self.timestamp.isoformat(),
                src_ref=source.id,
                dst_ref=destination.id,
                src_port=self.tcp_src_port,
                dst_port=self.tcp_dst_port,
                protocols=['ipv4', 'tcp', 'enip']
            )
        elif self.protocol[-3:] == 'arp':
            source = None
            destination = None
            for object in instantiated_stix21_objects:
                if object.type == 'mac-addr':
                    if self.eth_src == object.value:
                        source = object
                    elif self.eth_dst == object.value:
                        destination = object
            if source is None:
                source = self.generate_mac_addr()
            elif destination is None:
                destination = self.generate_mac_addr()

            traffic = NetworkTraffic(
                start=self.timestamp.isoformat(),
                src_ref=source.id,
                dst_ref=destination.id,
                protocols=['eth', 'arp']
            )
        return traffic

    def generate_mac_addr(self, type=None):
        if type is None or type == 'src':
            mac_addr = MACAddress(
                value=self.eth_src
            )
        elif type == 'dst':
            mac_addr = MACAddress(
                value=self.eth_dst
            )
        elif type == 'arp':
            mac_addr = MACAddress(
                value=self.arp_mac_addr
            )
        return mac_addr
