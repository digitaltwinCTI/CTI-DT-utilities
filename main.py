"""
This is the main program for CTI generation based on digital twin simulation output
"""
import sys

from select_stix21_objects import *
from import_stix21_data import *
from import_simulation_output import *
from filter_functions import *
from stix2.v21 import *
from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression, GreaterThanComparisonExpression,
                   IsSubsetComparisonExpression, FloatConstant, StringConstant, IntegerConstant, AndBooleanExpression,
                   FollowedByObservationExpression, RepeatQualifier, WithinQualifier, ParentheticalExpression,
                   QualifiedObservationExpression, MemoryStore)


def pretty_print_list(list):
    print('The provided list contains the following elements:')
    for element in list:
        print(element)


if __name__ == '__main__':
    root_dir = os.path.dirname(os.path.abspath(__file__))
    export_path = os.path.join(root_dir, 'results\\')
    # sys.stdout = open(export_path+'console_output_MITM_use_case', 'w')

    stix21_object_list_MITM = list()
    stix21_object_list_DOS = list()

    print('\nUSE CASE 1 -- MITM Attack:\n')

    imported_stix21_data = import_static_stix21_data()
    imported_sco_list = imported_stix21_data[0]
    imported_sro_list = imported_stix21_data[1]

    print('\n-------------------------------------------\n')

    # custom_sco_list_MITM = build_sco_list(imported_sco_list)
    static_sco_list_MITM = get_static_mitm_sco_list()

    print('\n-------------------------------------------\n')

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

    print('\n-------------------------------------------\n')

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

    print('\n-------------------------------------------\n')

    pretty_print_list(get_timespan(converted_pcap_MITM))
    print('')

    pretty_print_list(get_all_protocols(converted_pcap_MITM))

    print('\n-------------------------------------------\n')

    filtered_enip = filter_protocols(converted_pcap_MITM, 'eth:ethertype:ip:tcp:enip')
    print('')

    pretty_print_list(filtered_enip)

    print('\n-------------------------------------------\n')

    network_traffic_list_enip = list()
    for element in filtered_enip:
        network_traffic = element.generate_network_traffic(stix21_object_list_MITM)
        network_traffic_list_enip.append(network_traffic)
        stix21_object_list_MITM.append(network_traffic)

    print('Generated STIX2.1 network traffic SCOs from enip filtered pcap frames:')
    pretty_print_list(network_traffic_list_enip)

    print('\n-------------------------------------------\n')

    mac1 = filtered_enip[0].generate_mac_addr('src')
    stix21_object_list_MITM.append(mac1)
    mac2 = filtered_enip[0].generate_mac_addr('dst')
    stix21_object_list_MITM.append(mac2)
    mac3 = filtered_enip[2].generate_mac_addr('dst')
    stix21_object_list_MITM.append(mac3)

    print('Generated STIX2.1 MAC addresses from enip filtered pcap frames:')
    print(mac1, mac2, mac3)

    print('\n-------------------------------------------\n')

    filtered_arp = filter_protocols(converted_pcap_MITM, 'eth:ethertype:arp')
    print('')

    pretty_print_list(filtered_arp)

    print('\n-------------------------------------------\n')

    print('Generated STIX2.1 MAC address from arp filtered pcap frames:')
    mac4 = filtered_arp[0].generate_mac_addr('arp')
    stix21_object_list_MITM.append(mac4)
    print(mac4)

    print('\n-------------------------------------------\n')

    network_traffic_list_arp = list()
    for element in filtered_arp:
        network_traffic_list_arp.append(element.generate_network_traffic(stix21_object_list_MITM))

    for element in network_traffic_list_arp:
        stix21_object_list_MITM.append(element)

    print('Generated STIX2.1 network traffic from arp filtered pcap frames:')
    pretty_print_list(network_traffic_list_arp)

    print('\n-------------------------------------------\n')

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

    print('\n-------------------------------------------\n')

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

    print('\n-------------------------------------------\n')

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

    print('Custom generated Observed Data for IP addresses, regular traffic, ARP traffic and spoofed traffic:')

    observed_data1 = ObservedData(
        first_observed=converted_pcap_MITM[0].timestamp,
        last_observed=converted_pcap_MITM[-1].timestamp,
        number_observed=1,
        object_refs=[ip1_updated.id, ip2_updated.id, ip3_updated.id]  # ip addresses
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
        first_observed=filtered_enip[0].timestamp,
        last_observed=filtered_enip[5].timestamp,
        number_observed=6,
        object_refs=nw_traffic_id_list  # regular traffic
    )
    stix21_object_list_MITM.append(observed_data3)

    observed_data4 = ObservedData(
        first_observed=filtered_enip[6].timestamp,
        last_observed=filtered_enip[6].timestamp,
        number_observed=1,
        object_refs=network_traffic_list_enip[6].id  # spoofed traffic, last enip entry
    )
    stix21_object_list_MITM.append(observed_data4)

    print(observed_data1, observed_data2, observed_data3, observed_data4)

    print('')

    print('Custom generated Indicators based on duplicate IP to MAC resolving, ARP traffic and spoofed traffic:')

    lhs1 = ObjectPath("ipv4-addr", ["resolves_to_refs[0]"])
    lhs1b = ObjectPath("ipv4-addr", ["resolves_to_refs[1]"])
    ob1 = EqualityComparisonExpression(lhs1, StringConstant('00:00:00:00:00:05'), True)
    ob1b = EqualityComparisonExpression(lhs1b, StringConstant('00:00:00:00:00:05'))
    pattern1 = ObservationExpression(AndBooleanExpression([ob1, ob1b]))

    indicator1 = Indicator(
        name='ARP spoofing indicator - duplicate IP address',
        description='IP address resolves to two different MAC addresses',
        pattern=pattern1,
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    stix21_object_list_MITM.append(indicator1)

    print(indicator1)

    lhs2 = ObjectPath('network-traffic', ['scr_ref'])
    ob2 = EqualityComparisonExpression(lhs2, StringConstant('00:00:00:00:00:05'))
    lhs2b = ObjectPath('network-traffic', ['protocols[1]'])
    ob2b = EqualityComparisonExpression(lhs2b, StringConstant('arp'))
    obe2 = ObservationExpression(AndBooleanExpression([ob2, ob2b]))
    pattern2 = QualifiedObservationExpression(QualifiedObservationExpression(obe2, RepeatQualifier(10)),
                                              WithinQualifier(5))

    indicator2 = Indicator(
        name='ARP spoofing indicator - repeated arp traffic',
        description='ARP spoofing network traffic originating from malicious MAC address',
        pattern=pattern2,
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    stix21_object_list_MITM.append(indicator2)

    print(indicator2)

    lhs3 = ObjectPath('network-traffic', ['protocols[2]'])
    ob3 = EqualityComparisonExpression(lhs3, StringConstant('enip'))
    pattern3 = ObservationExpression(AndBooleanExpression([ob2, ob3]))

    indicator3 = Indicator(
        name='ARP spoofing indicator - spoofed enip traffic',
        description='Enip traffic originating from malicious MAC address',
        pattern=pattern3,
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    stix21_object_list_MITM.append(indicator3)

    print(indicator3)

    print('')

    print('Custom generated relationships between Observed Data and Indicators:')

    rel_indicator_observed1 = Relationship(source_ref=indicator1, relationship_type='based-on',
                                           target_ref=observed_data1)
    rel_indicator_observed2 = Relationship(source_ref=indicator2, relationship_type='based-on',
                                           target_ref= observed_data2)
    rel_indicator_observed3 = Relationship(source_ref=indicator3, relationship_type='based-on',
                                           target_ref=observed_data4)
    rel_indicator_observed4 = Relationship(source_ref=indicator3, relationship_type='based-on',
                                           target_ref=observed_data3)
    stix21_object_list_MITM.append(rel_indicator_observed1)
    stix21_object_list_MITM.append(rel_indicator_observed2)
    stix21_object_list_MITM.append(rel_indicator_observed3)
    stix21_object_list_MITM.append(rel_indicator_observed4)

    print(rel_indicator_observed1, rel_indicator_observed2, rel_indicator_observed3, rel_indicator_observed4)

    print('')

    print('Custom generated Attack Pattern, Tool and additional relationships:')

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
    stix21_object_list_MITM.append(attack_pattern)

    tool = Tool(
        name='Ettercap'
    )
    stix21_object_list_MITM.append(tool)

    print(attack_pattern, tool)

    rel_indicator_attack1 = Relationship(source_ref=indicator1, relationship_type='indicates',
                                         target_ref=attack_pattern)
    rel_indicator_attack2 = Relationship(source_ref=indicator2, relationship_type='indicates',
                                         target_ref=attack_pattern)
    rel_indicator_attack3 = Relationship(source_ref=indicator3, relationship_type='indicates',
                                         target_ref=attack_pattern)
    rel_attack_tool = Relationship(source_ref=attack_pattern, relationship_type='uses', target_ref=tool)
    stix21_object_list_MITM.append(rel_indicator_attack1)
    stix21_object_list_MITM.append(rel_indicator_attack2)
    stix21_object_list_MITM.append(rel_indicator_attack3)
    stix21_object_list_MITM.append(rel_attack_tool)

    print(rel_indicator_attack1, rel_indicator_attack2, rel_indicator_attack3, rel_attack_tool)

    MITM_id_list = list()
    for element in stix21_object_list_MITM:
        MITM_id_list.append(element.id)

    print('')

    print('Generated Report for the Digital Twin MITM simulation use case:')

    report_MITM = Report(
        name='Digital Twin based MITM attack simulation with ARP spoofing',
        description='This report describes a simulated MITM attack on a filling plant using a digital twin in'
                    ' simulation mode. The attack is based on ARP spoofing.',
        published=datetime.datetime.now(),
        object_refs=MITM_id_list
    )

    print(report_MITM)

    bundle_MITM = Bundle(objects=stix21_object_list_MITM)

    print('\n-------------------------------------------')

    mem = MemoryStore()
    mem.add(bundle_MITM)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    export_path = os.path.join(root_dir, 'data\\')
    # mem.save_to_file(export_path+'STIX21_output_MITM_use_case.json')

    print('-------------------------------------------')

    # sys.stdout.close()

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