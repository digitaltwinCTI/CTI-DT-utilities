class PcapEntry:
    def __init__(self, timestamp=None, protocol=None, eth_src=None, eth_dst=None, message=None,
                 arp_mac_addr=None, arp_ip_addr=None, arp_info=None, ip_src=None, ip_dst=None, tcp_src_port=None,
                 tcp_dst_port=None):
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

    #def __repr__(self):
        #return f'{self.loglevel} {self.timestamp} {self.ip_addr_host} {self.program} {self.message}'

    def add_message_element(self, data):
        self.message = self.message + data
