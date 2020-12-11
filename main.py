"""
This is the main program for CTI generation based on digital twin simulation output
"""

from search_stix21_objects import *
from select_stix21_objects import *
from import_stix21_data import *
from import_simulation_output import *
from filter_functions import *


def pretty_print_list(list):
    print('The provided list contains the following elements:')
    for element in list:
        print(element)


if __name__ == '__main__':
    stix21_object_list_MITM = list()
    stix21_object_list_DOS = list()

    print('')

    imported_stix21_data = import_static_stix21_data()
    imported_sco_list = imported_stix21_data[0]
    imported_sro_list = imported_stix21_data[1]

    print('')
    print('-------------------------------------------')
    print('')

    # custom_sco_list_MITM = build_sco_list(imported_sco_list)
    static_sco_list_MITM = get_static_mitm_sco_list()

    print('')
    print('-------------------------------------------')
    print('')

    simulation_output_MITM = import_static_simulation_output()
    converted_logs_MITM = convert_log_entries(simulation_output_MITM[0])
    converted_pcap_MITM = convert_pcap_frames(simulation_output_MITM[1])

    print('')

    print(get_all_ip_addr(converted_logs_MITM))
    print('')

    pretty_print_list(get_timespan(converted_logs_MITM))
    print('')

    print(get_all_severity_level(converted_logs_MITM))
    print('')

    filtered_ip = filter_log_ip(converted_logs_MITM, '10.0.0.1')
    filtered_severity = filter_log_severity(filtered_ip, 'WARNING')
    filtered_time = filter_timestamps(filtered_severity, datetime.timedelta(0, 8, 0, 0, 0),
                                      datetime.datetime(2020, 8, 17, 13, 51, 00))
    print('')

    pretty_print_list(filtered_time)
    print('')

    filtered_ip2 = filter_log_ip(converted_logs_MITM, '10.0.0.2', False)

    print('')
    print('-------------------------------------------')
    print('')

    ip1 = filtered_time[0].generate_ipv4_addr('host')
    stix21_object_list_MITM.append(ip1)
    ip2 = filtered_ip2[0].generate_ipv4_addr('external')
    stix21_object_list_MITM.append(ip2)
    ip3 = filtered_time[0].generate_ipv4_addr('external')
    stix21_object_list_MITM.append(ip3)
    process = filtered_time[0].generate_process()
    stix21_object_list_MITM.append(process)

    print('Generated STIX2.1 SCOs from log entries:')
    print(ip1, ip2, ip3, process)

    print('')
    print('-------------------------------------------')
    print('')

    pretty_print_list(get_timespan(converted_pcap_MITM))
    print('')

    pretty_print_list(get_all_protocols(converted_pcap_MITM))

    print('')
    print('-------------------------------------------')
    print('')

    filtered_enip = filter_protocols(converted_pcap_MITM, 'eth:ethertype:ip:tcp:enip')
    print('')

    pretty_print_list(filtered_enip)

    print('')
    print('-------------------------------------------')
    print('')

    network_traffic_list_enip = list()
    for element in filtered_enip:
        network_traffic = element.generate_network_traffic(stix21_object_list_MITM)
        network_traffic_list_enip.append(network_traffic)
        stix21_object_list_MITM.append(network_traffic)

    print('Generated STIX2.1 network traffic SCOs from enip filtered pcap frames:')
    pretty_print_list(network_traffic_list_enip)

    print('')
    print('-------------------------------------------')
    print('')

    mac1 = filtered_enip[0].generate_mac_addr('src')
    stix21_object_list_MITM.append(mac1)
    mac2 = filtered_enip[0].generate_mac_addr('dst')
    stix21_object_list_MITM.append(mac2)
    mac3 = filtered_enip[2].generate_mac_addr('dst')
    stix21_object_list_MITM.append(mac3)

    print('Generated STIX2.1 MAC addresses from enip filtered pcap frames:')
    print(mac1, mac2, mac3)

    print('')
    print('-------------------------------------------')
    print('')

    filtered_arp = filter_protocols(converted_pcap_MITM, 'eth:ethertype:arp')
    print('')

    pretty_print_list(filtered_arp)

    print('')
    print('-------------------------------------------')
    print('')

    print('Generated STIX2.1 MAC address from arp filtered pcap frames:')
    mac4 = filtered_arp[0].generate_mac_addr('arp')
    print(mac4)

    print('')
    print('-------------------------------------------')
    print('')

    network_traffic_list_arp = list()
    for element in filtered_arp:
        network_traffic_list_arp.append(element.generate_network_traffic(stix21_object_list_MITM))  ##TO DO Continue

    print('Generated STIX2.1 network traffic from arp filtered pcap frames:')
    pretty_print_list(network_traffic_list_arp)

    print('')
    #for result in filtered_pcap_time[2].generate_network_traffic():
     #   print(result)
    print('')
    print('-------------------------------------------')
    print('')
    print('Generated STIX2.1 SDOs')
    attack_pattern = AttackPattern(
        name='ARP Spoofing attack',
        description='The attacker targets the communication between network components as a MITM and uses ARP packets'
                    ' to redirect network traffic',
        external_references=[ExternalReference(
            source_name='capec',
            external_id='CAPEC-94'),
            ExternalReference(
                source_name='capec',
                external_id='CAPEC-141')],
        kill_chain_phases=KillChainPhase(
            kill_chain_name='lockheed-martin-cyber-kill-chain',
            phase_name='reconnaissance'
        )
    )
    infrastructure = Infrastructure(
        name='Filling plant digital twin',
        description="Digital twin representing a filling plant with three PLCs. Target of the conducted attack"
    )
    tool = Tool(
        name='Ettercap'
    )
    print(attack_pattern, infrastructure, tool)
    indicator = Indicator(
        name='ARP spoofing indicator',
        description='ARP spoofing network traffic used to intercept traffic based on MAC addresses',
        pattern="[network_traffic:src = '00:00:00:00:00:05']",
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    observed_data1 = ObservedData(
        first_observed=datetime.datetime.now(),#replace by object timestamp
        last_observed=datetime.datetime.now(),#replace by last object timestamp
        number_observed=6,
        object_refs=ip1#regular traffic
    )
    observed_data2 = ObservedData(
        first_observed=datetime.datetime.now(),
        last_observed=datetime.datetime.now(),
        number_observed=20,
        object_refs=ip1#arp traffic
    )
    observed_data3 = ObservedData(
        first_observed=datetime.datetime.now(),#replace by object timestamp
        last_observed=datetime.datetime.now(),#replace by last object timestamp
        number_observed=1,
        object_refs=ip1# traffic arp spoof last enip entry
    )
    print('')
    print('-------------------------------------------')
    print('')
    ''' Import a txt file containing all STIX2.1 relationships'''
    rel_list1 = import_stix21_relationships("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\STIX Relationship Data\\",
                                           "done_STIX21_SCO+SDO_relationship_list_all.txt")
    '''Searching the relationship list for a STIX2.1 object with specified relationship type '''
    search_list1 = search_stix21_objects(rel_list1, "tool",'direct')
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
    #custom_SCO_SCO_rel_list = build_sdo_list(rel_list1, static_SCO_list)

    #for list in custom_SCO_SCO_rel_list:
       #pretty_print_list(custom_SCO_SCO_rel_list)
    print('')
    print('-------------------------------------------')
    print('')

    # custom_list = build_sco_list(test)
    #      pretty_print_list(build_sdo_list(rel_list1, custom_list))

    # print(custom_list)

    # all_rel_list = import_stix21_relationships()

    arp_frames = filtered_arp
    pretty_print_list(arp_frames)
    list_arp = list()
    for element in arp_frames:
        list_arp.append(element.generate_ipv4_addr())
    #for element in list_arp:
    #    pretty_print_list(element)

    print('')
    print('-------------------------------------------')
    print('')
    print('USE CASE 2 -- DOS Attack:')
    simulation_output_log_dos1 = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
                                                     "Use Case 2\\", "plc.log")
    simulation_output_log_dos2 = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
                                                     "Use Case 2\\", "hmi.log")
    converted_logs_dos1 = convert_log_entries(simulation_output_log_dos1)
    print(get_all_ip_addr(converted_logs_dos1))
    print(get_timespan(converted_logs_dos1))
    print(get_all_severity_level(converted_logs_dos1))
    converted_logs_dos2 = convert_log_entries(simulation_output_log_dos2)
    print(get_all_ip_addr(converted_logs_dos2))
    print(get_timespan(converted_logs_dos2))
    print(get_all_severity_level(converted_logs_dos2))
    #pretty_print_list(converted_logs_dos1)

    ip1dos = converted_logs_dos1[0].generate_ipv4_addr()
    ip2dos = converted_logs_dos2[0].generate_ipv4_addr()

    print(ip1dos, ip2dos)

    print('path to data directory')
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data')

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

    #indicator2 = indicator.new_version(name="File hash for Foobar malware",
     #                                  labels=["malicious-activity"])