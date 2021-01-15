"""
This is module is intended to generate a STIX2.1 report for the digital twin based DoS attack simulation
"""
import sys

from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression, StringConstant,
                   AndBooleanExpression,
                   RepeatQualifier, WithinQualifier, QualifiedObservationExpression, MemoryStore)
from stix2.v21 import *

from filter_functions import *
from import_simulation_output import *
from import_stix21_data import *
from select_stix21_objects import *


def pretty_print_list(list):
    print('The provided list contains the following elements:')
    for element in list:
        print(element)


def generate_dos_stix21_report():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data\\')
    export_path = os.path.join(root_dir, 'results\\')
    # sys.stdout = open(export_path+'console_output_DoS_use_case', 'w')

    stix21_object_list_DOS = list()

    print('\nUSE CASE 2 -- DoS Attack:\n')

    imported_stix21_data = import_static_stix21_data()
    imported_sro_list = imported_stix21_data[1]

    print('\n-------------------------------------------')

    get_static_mitm_sco_list()

    print('-------------------------------------------\n')

    converted_logs_DOS1 = convert_log_entries(import_simulation_output(
        import_path, "use_case_2_plc.log"))
    converted_logs_DOS2 = convert_log_entries(import_simulation_output(
        import_path, "use_case_2_hmi.log"))
    converted_pcap_DOS = convert_pcap_frames(import_simulation_output(
        import_path, "use_case_2_network_traffic.json"))

    print('')

    print(get_all_ip_addr(converted_logs_DOS1))
    print('')

    pretty_print_list(get_timespan(converted_logs_DOS1))
    print('')

    print(get_all_severity_level(converted_logs_DOS1))
    print('')

    print(get_all_ip_addr(converted_logs_DOS2))
    print('')

    pretty_print_list(get_timespan(converted_logs_DOS2))
    print('')

    print(get_all_severity_level(converted_logs_DOS2))

    print('\n-------------------------------------------\n')

    print('Generated STIX2.1 SCOs from log entries:')

    ip1dos = converted_logs_DOS1[0].generate_ipv4_addr()
    ip2dos = converted_logs_DOS2[0].generate_ipv4_addr()
    process_dos = converted_logs_DOS1[0].generate_process()
    stix21_object_list_DOS.append(ip1dos)
    stix21_object_list_DOS.append(ip2dos)
    stix21_object_list_DOS.append(process_dos)

    print(ip1dos, ip2dos, process_dos)

    print('\n-------------------------------------------\n')

    pretty_print_list(get_timespan(converted_pcap_DOS))
    print('')

    print(get_all_protocols(converted_pcap_DOS))

    print('\nDisplaying the last 10 pcap entries:')
    for element in converted_pcap_DOS[-10:]:
        print(element)

    ack_traffic = list()
    for element in converted_pcap_DOS:
        if element.eth_src == '00:00:00:00:00:02' or element.eth_dst == '00:00:00:00:00:02':
            ack_traffic.append(element)

    print('\nDisplaying 5 SYN/ACK pcap entries:')
    pretty_print_list(ack_traffic[:5])

    print('\n-------------------------------------------\n')

    mac3_dos = converted_pcap_DOS[0].generate_mac_addr('src')
    stix21_object_list_DOS.append(mac3_dos)
    mac1_dos = converted_pcap_DOS[0].generate_mac_addr('dst')
    stix21_object_list_DOS.append(mac1_dos)
    mac2_dos = ack_traffic[0].generate_mac_addr('dst')
    stix21_object_list_DOS.append(mac2_dos)

    print('Generated STIX2.1 MAC addresses from pcap frames:')
    print(mac1_dos, mac2_dos, mac3_dos)

    print('\nGenerated STIX2.1 network traffic SCOs from pcap frames (excerpt shown):')

    network_traffic_DOS_list = list()
    for element in converted_pcap_DOS[:100]:
        network_traffic_DOS = element.generate_network_traffic(stix21_object_list_DOS)
        network_traffic_DOS_list.append(network_traffic_DOS)
        stix21_object_list_DOS.append(network_traffic_DOS)

    pretty_print_list(network_traffic_DOS_list[:5])

    print('\n-------------------------------------------\n')
    get_static_stix21_objects_dos_round_1()

    print('\n-------------------------------------------\n')
    ip2dos_updated = IPv4Address(id=ip2dos.id, value=ip2dos.value, resolves_to_refs=[mac2_dos.id, mac3_dos.id])
    stix21_object_list_DOS.remove(ip2dos)
    stix21_object_list_DOS.append(ip2dos_updated)

    print('Updated IPv4 address object (embedded relationship):\n{}\n'.format(ip2dos_updated))

    print('Custom selected and generated Infrastructure SDO and related SROs:')
    infrastructure_dos = Infrastructure(
        name='Conyeor belt digital twin',
        description="Digital twin representing a conveyor belt with HMI and PLC. Target of the conducted attack"
    )
    stix21_object_list_DOS.append(infrastructure_dos)

    rel_infra_ip1_dos = Relationship(source_ref=infrastructure_dos, relationship_type='consists_of', target_ref=ip1dos)
    rel_infra_ip2_dos = Relationship(source_ref=infrastructure_dos, relationship_type='consists_of',
                                     target_ref=ip2dos_updated)
    rel_infra_process_dos = Relationship(source_ref=infrastructure_dos, relationship_type='consists_of',
                                         target_ref=process_dos)
    stix21_object_list_DOS.append(rel_infra_ip1_dos)
    stix21_object_list_DOS.append(rel_infra_ip2_dos)
    stix21_object_list_DOS.append(rel_infra_process_dos)

    print(infrastructure_dos, rel_infra_ip1_dos, rel_infra_ip2_dos, rel_infra_process_dos)

    print('\nCustom generated Observed Data for IP addresses and spoofed SYN-flooding traffic:')

    observed_data1_dos = ObservedData(
        first_observed=converted_logs_DOS2[0].timestamp,
        last_observed=converted_logs_DOS2[-1].timestamp,
        number_observed=1,
        object_refs=[ip2dos_updated] # duplicate IP
    )
    stix21_object_list_DOS.append(observed_data1_dos)

    nw_traffic_dos_id_list = list()
    for element in network_traffic_DOS_list:
        nw_traffic_dos_id_list.append(element.id)

    observed_data2_dos = ObservedData(
        first_observed=converted_pcap_DOS[0].timestamp,
        last_observed=converted_pcap_DOS[len(converted_pcap_DOS)-1].timestamp,
        number_observed=100,
        object_refs=nw_traffic_dos_id_list  # SYN traffic excerpt
    )
    stix21_object_list_DOS.append(observed_data2_dos)

    print(observed_data1_dos, observed_data2_dos)

    print('\n-------------------------------------------\n')

    search_list1 = search_stix21_objects(imported_sro_list, "observed-data", 'direct')
    print('The following direct relationships exist for Observed Data:')
    for entry in search_list1:
        print(entry)

    print('Custom generated Indicators and relationships between Observed Data and Indicators:\n')

    lhs1 = ObjectPath("ipv4-addr", ["resolves_to_refs[0]"])
    lhs1b = ObjectPath("ipv4-addr", ["resolves_to_refs[1]"])
    ob1 = EqualityComparisonExpression(lhs1, StringConstant('00:00:00:00:00:03'), True)
    ob1b = EqualityComparisonExpression(lhs1b, StringConstant('00:00:00:00:00:03'))
    pattern1_dos = ObservationExpression(AndBooleanExpression([ob1, ob1b]))

    indicator1_dos = Indicator(
        name='Spoofing indicator - duplicate IP address',
        description='IP address resolves to two different MAC addresses',
        pattern=pattern1_dos,
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    stix21_object_list_DOS.append(indicator1_dos)

    print(indicator1_dos)

    lhs2 = ObjectPath('network-traffic', ['scr_ref'])
    ob2 = EqualityComparisonExpression(lhs2, StringConstant('00:00:00:00:00:03'))
    lhs2a = ObjectPath('network-traffic', ['dst_ref'])
    ob2a = EqualityComparisonExpression(lhs2a, StringConstant('00:00:00:00:00:01'))
    lhs2b = ObjectPath('network-traffic', ['protocols[1]'])
    ob2b = EqualityComparisonExpression(lhs2b, StringConstant('tcp'))
    obe2 = ObservationExpression(AndBooleanExpression([ob2, ob2a, ob2b]))
    pattern2_dos = QualifiedObservationExpression(QualifiedObservationExpression(obe2, RepeatQualifier(100)),
                                                  WithinQualifier(1))

    indicator2_dos = Indicator(
        name='SYN flooding indicator',
        description='Highly repetitive tcp network traffic originating from malicious MAC address',
        pattern=pattern2_dos,
        pattern_type='stix',
        valid_from=datetime.datetime.now()
    )
    stix21_object_list_DOS.append(indicator2_dos)

    print(indicator2_dos)

    rel_indicator_observed1_dos = Relationship(source_ref=indicator1_dos, relationship_type='based-on',
                                               target_ref=observed_data1_dos)
    rel_indicator_observed2_dos = Relationship(source_ref=indicator2_dos, relationship_type='based-on',
                                               target_ref=observed_data2_dos)

    stix21_object_list_DOS.append(rel_indicator_observed1_dos)
    stix21_object_list_DOS.append(rel_indicator_observed2_dos)

    print(rel_indicator_observed1_dos, rel_indicator_observed2_dos)

    print('\n-------------------------------------------\n')
    print('Custom generated Attack Pattern, Tool and additional relationships:')

    attack_pattern_dos = AttackPattern(
        name='DoS SYN flooding attack',
        description='The attacker executes a Denial of Service attack with TCP SYN requests consuming the resources of'
                    ' its target',
        external_references=[ExternalReference(
            source_name='capec',
            external_id='CAPEC-125'),
            ExternalReference(
                source_name='capec',
                external_id='CAPEC-482')],
        kill_chain_phases=KillChainPhase(
            kill_chain_name='lockheed-martin-cyber-kill-chain',
            phase_name='actions-on-objective'
        )
    )
    stix21_object_list_DOS.append(attack_pattern_dos)

    tool_dos = Tool(
        name='hping3'
    )
    stix21_object_list_DOS.append(tool_dos)

    print(attack_pattern_dos, tool_dos)

    rel_indicator_attack1_dos = Relationship(source_ref=indicator1_dos, relationship_type='indicates',
                                             target_ref=attack_pattern_dos)
    rel_indicator_attack2_dos = Relationship(source_ref=indicator2_dos, relationship_type='indicates',
                                             target_ref=attack_pattern_dos)
    rel_attack_tool_dos = Relationship(source_ref=attack_pattern_dos, relationship_type='uses', target_ref=tool_dos)
    stix21_object_list_DOS.append(rel_indicator_attack1_dos)
    stix21_object_list_DOS.append(rel_indicator_attack2_dos)
    stix21_object_list_DOS.append(rel_attack_tool_dos)

    print(rel_indicator_attack1_dos, rel_indicator_attack2_dos, rel_attack_tool_dos)

    DOS_id_list = list()
    for element in stix21_object_list_DOS:
        DOS_id_list.append(element.id)

    print('\n-------------------------------------------\n')
    print('Generated Report for the Digital Twin DoS simulation use case:')

    report_DOS = Report(
        name='Digital Twin based DoS attack simulation with SYN flooding',
        description='This report describes a simulated DoS attack on a conveyor belt using a digital twin in'
                    ' simulation mode. The attack is based on repeatedly spoofed TCP traffic.',
        published=datetime.datetime.now(),
        object_refs=DOS_id_list
    )
    stix21_object_list_DOS.append(report_DOS)

    print(report_DOS)

    bundle_DOS = Bundle(objects=stix21_object_list_DOS)

    print('\n-------------------------------------------')

    mem = MemoryStore()
    mem.add(bundle_DOS)
    # mem.save_to_file(export_path+'STIX21_output_DoS_use_case.json')

    print('-------------------------------------------')

    # sys.stdout.close()
