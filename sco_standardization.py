from stix2.v21 import *


class SCOStandardization:

    def generate_ipv4_addr(simulation_output) -> set:
        """Add IP address object to SCO list and generate STIX SCO"""
        ip_addr_set = set()
        for line in simulation_output:
            ip_addr_set.add(line[3])
        return ip_addr_set

    if __name__ == '__main__':
        print('hello')
