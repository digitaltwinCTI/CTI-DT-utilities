import stix2.v21


class SCOStandardization:

    def extract_ip_addr(simulation_output) -> set:
        ip_addr_set = set()
        for line in simulation_output:
            ip_addr_set.add(line[3])
        return ip_addr_set

    if __name__ == '__main__':
        print('hello')
