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
                id="ipv4-addr--" + str(uuid.uuid4()),
                value=self.ip_src
            )
        elif ip_type == 'dst':
            ipv4_addr = IPv4Address(
                id="ipv4-addr--" + str(uuid.uuid4()),
                value=self.ip_dst
            )
        else:
            print('Please specify IP address type (src or dst)')
            return
        return ipv4_addr

    def generate_network_traffic(self, instantiated_stix21_objects=None):
        if self.protocol[-4:] == 'enip':
            print('test')
            for object in instantiated_stix21_objects:
                if self.eth_src == object.value:
                        pass

        source = self.generate_ipv4_addr('src')
        destination = self.generate_ipv4_addr('dst')
        traffic = NetworkTraffic(
            start=self.timestamp.isoformat(),
            src_ref=source.id,
            dst_ref=destination.id,
            protocols=self.protocol
        )
        return source, destination, traffic

    def generate_mac_addr(self, type=None):
        if self.protocol[-3:] == 'arp':
            mac_addr = MACAddress(
                value=self.arp_mac_addr
            )
        else:
            if type is None or type == 'src':
                mac_addr = MACAddress(
                    value=self.eth_src
                )
            else:
                mac_addr = MACAddress(
                    value=self.eth_dst
                )
        return mac_addr
