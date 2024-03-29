from stix2.v21 import *
import uuid


class LogEntry:
    def __init__(self, level=None, timestamp=None, ip_addr_host=None, program=None, message=None,
                 ip_addr_external=None):
        self.loglevel = level
        self.timestamp = timestamp
        self.ip_addr_host = ip_addr_host
        self.program = program
        self.message = message
        self.ip_addr_external = ip_addr_external

    def __repr__(self):
        return f'{self.loglevel} {self.timestamp} {self.ip_addr_host} {self.program} {self.message}'

    def add_message_element(self, data):
        self.message = self.message + data

    def generate_ipv4_addr(self, ip_type='host'):
        if ip_type == 'host':
            ipv4_addr = IPv4Address(
                value=self.ip_addr_host
            )
        elif ip_type == 'external':
            ipv4_addr = IPv4Address(
                id="ipv4-addr--" + str(uuid.uuid4()), # id is automatically assigned if unspecified
                value=self.ip_addr_external
            )
        else:
            print('Please specify IP address type (host or external)')
            return
        return ipv4_addr

    def generate_process(self):
        process = Process(
            command_line=self.program
        )
        return process
