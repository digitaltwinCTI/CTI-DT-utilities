"""
This is the main program for CTI generation based on digital twin simulation output
"""

from search_stix21_objects import *
from select_stix21_objects import *
from import_stix21_data import *
from import_simulation_output import *
from filter_functions import *
from stix2.v21 import *
from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression, GreaterThanComparisonExpression,
                   IsSubsetComparisonExpression, FloatConstant, StringConstant, IntegerConstant)


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
    stix21_object_list_MITM.append(mac4)
    print(mac4)

    print('')
    print('-------------------------------------------')
    print('')

    network_traffic_list_arp = list()
    for element in filtered_arp:
        network_traffic_list_arp.append(element.generate_network_traffic(stix21_object_list_MITM))

    for element in network_traffic_list_arp:
        stix21_object_list_MITM.append(element)

    print('Generated STIX2.1 network traffic from arp filtered pcap frames:')
    pretty_print_list(network_traffic_list_arp)

    print('')
    print('-------------------------------------------')
    print('')

    '''
    This is optional search utility can help users to query relationships for a given SCO or SDO prior to building
    a custom relationship list. Comment out if not needed. 
    '''
    print('Searching the relationship list for a STIX2.1 object with specified relationship type:')
    search_list1 = search_stix21_objects(imported_sro_list, "tool", 'direct')
    for entry in search_list1:
        print(entry)

    print('')

    # custom_sco_list_MITM_update = build_sco_list(imported_sco_list)
    # custom_sdo_sro_list_MITM = build_sdosro_list(imported_sro_list, static_sco_list_MITM, 'any')

    print('')

    # custom_sro_list_MITM = custom_sdo_sro_list_MITM[1]
    # custom_sco_sdo_list_MITM = custom_sdo_sro_list_MITM[0]

    print('')
    print('-------------------------------------------')
    print('')

    '''
    Next steps:
    - select embedded relationships between SCOs
    - adapt SCOs: add resolves to for IP and MAC addresses
    - infrastructure consists of IP addresses
    - infrastructure consists of process
    - process opened connections refs to network traffic (enip) NOT arp
    - pattern: ip address resolves to two MAC addresses + arp traffic more than 5 present
    '''

    ip1_updated = IPv4Address(id=ip1.id, value=ip1.value, resolves_to_refs=[mac1.id, mac4.id])
    ip2_updated = IPv4Address(value=ip2.value, resolves_to_refs=[mac2.id, mac4.id])
    ip3_updated = IPv4Address(id=ip3.id, value=ip3.value, resolves_to_refs=[mac3.id, mac4.id])
    stix21_object_list_MITM.remove(ip1)
    stix21_object_list_MITM.remove(ip2)
    stix21_object_list_MITM.remove(ip3)
    stix21_object_list_MITM.append(ip1_updated)
    stix21_object_list_MITM.append(ip2_updated)
    stix21_object_list_MITM.append(ip3_updated)

    nw_traffic_id_list = list()
    for element in network_traffic_list_enip[:-1]:
        nw_traffic_id_list.append(element.id)

    process_updated = Process(id=process.id, command_line=process.command_line,
                              opened_connection_refs=nw_traffic_id_list)
    stix21_object_list_MITM.remove(process)
    stix21_object_list_MITM.append(process_updated)

    print('Updated IPv4 address objects and Process object:')
    print(ip1_updated, ip2_updated, ip3_updated, process_updated)

    print('')
    print('-------------------------------------------')
    print('')

    print('Custom selected and generated STIX2.1 SDOs and SROs:')

    infrastructure = Infrastructure(
        name='Filling plant digital twin',
        description="Digital twin representing a filling plant with three PLCs. Target of the conducted attack"
    )
    stix21_object_list_MITM.append(infrastructure)

    rel_infra_ip1 = Relationship(source_ref=infrastructure, relationship_type='consists_of', target_ref=ip1)
    rel_infra_ip2 = Relationship(source_ref=infrastructure, relationship_type='consists_of', target_ref=ip2)
    rel_infra_ip3 = Relationship(source_ref=infrastructure, relationship_type='consists_of', target_ref=ip3)
    stix21_object_list_MITM.append(rel_infra_ip1)
    stix21_object_list_MITM.append(rel_infra_ip2)
    stix21_object_list_MITM.append(rel_infra_ip3)

    rel_infra_process = Relationship(source_ref=infrastructure, relationship_type='consists_of', target_ref=process)
    stix21_object_list_MITM.append(rel_infra_process)
    print(infrastructure, rel_infra_ip1, rel_infra_ip2, rel_infra_ip3, rel_infra_process)

    print('')

    print('Custom generated Observed Data for regular traffic, ARP traffic and spoofed traffic:')

    observed_data1 = ObservedData(
        first_observed=filtered_enip[0].timestamp,
        last_observed=filtered_enip[5].timestamp,
        number_observed=6,
        object_refs=nw_traffic_id_list  # regular traffic
    )
    stix21_object_list_MITM.append(observed_data1)

    nw_traffic_arp_id_list = list()
    for element in network_traffic_list_arp:
        nw_traffic_arp_id_list.append(element.id)

    observed_data2 = ObservedData(
        first_observed=filtered_arp[0].timestamp,
        last_observed=filtered_arp[19].timestamp,
        number_observed=20,
        object_refs=nw_traffic_arp_id_list  # arp traffic
    )
    stix21_object_list_MITM.append(observed_data2)

    observed_data3 = ObservedData(
        first_observed=filtered_enip[6].timestamp,
        last_observed=filtered_enip[6].timestamp,
        number_observed=1,
        object_refs=network_traffic_list_enip[6].id  # spoofed last enip entry traffic
    )
    stix21_object_list_MITM.append(observed_data3)

    print(observed_data1, observed_data2, observed_data3)

    print('')

    print('Custom generated Indicator based on duplicate IP MAC resolving, ARP traffic and spoofed traffic:')

    indicator = Indicator(
        name='ARP spoofing indicator',
        description='ARP spoofing network traffic used to intercept traffic based on MAC addresses',
        pattern="[network_traffic:src = '00:00:00:00:00:05']",
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )

    lhs1 = ObjectPath("ipv4-addr", ["resolves_to_refs[*]"])
    ob1 = EqualityComparisonExpression(lhs1, StringConstant('00:00:00:00:00:05'))
    obe1 = ObservationExpression(ob1)
    print("\t{}\n".format(obe1))

    lhs2 = ObjectPath('network-traffic', ['scr_ref'])
    ob2 = EqualityComparisonExpression(lhs2, StringConstant('00:00:00:00:00:05'))
    obe2 = ObservationExpression(ob2)


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

    tool = Tool(
        name='Ettercap'
    )

    print(attack_pattern, infrastructure, tool)




    print('')
    print('-------------------------------------------')
    print('')

    '''Import the output of digital twin simulation'''
    # print(import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\", "DOS.json"))
    # test1 = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\Filling-plant logs\\", "plc1.log")

    # print(extract_timestamp(test1[0]))
    # print(extract_timestamp(test1[0]) - datetime.timedelta(0, 7))

    print('')
    print('-------------------------------------------')
    print('')

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