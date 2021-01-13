"""
This is module is intended to generate a STIX2.1 report for the digital twin based DOS attack simulation
"""

from select_stix21_objects import *
from import_stix21_data import *
from import_simulation_output import *
from filter_functions import *
from stix2.v21 import *
from stix2 import (ObjectPath, EqualityComparisonExpression, ObservationExpression, GreaterThanComparisonExpression,
                   IsSubsetComparisonExpression, FloatConstant, StringConstant, IntegerConstant, AndBooleanExpression,
                   FollowedByObservationExpression, RepeatQualifier, WithinQualifier, ParentheticalExpression,
                   QualifiedObservationExpression, MemoryStore)

if __name__ == '__main__':
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data\\')
    export_path = os.path.join(root_dir, 'results\\')

    stix21_object_list_DOS = list()

    print('\nUSE CASE 2 -- DOS Attack:\n')

    imported_stix21_data = import_static_stix21_data()
    imported_sco_list = imported_stix21_data[0]
    imported_sro_list = imported_stix21_data[1]

    print('\n-------------------------------------------\n')

    static_sco_list_DOS = get_static_mitm_sco_list()

    print('\n-------------------------------------------\n')

    converted_logs_DOS1 = convert_log_entries(import_simulation_output(
        import_path, "use_case_2_plc.log"))
    converted_logs_DOS2 = convert_log_entries(import_simulation_output(
        import_path, "use_case_2_hmi.log"))
    #converted_pcap_DOS = convert_log_entries(import_simulation_output(
     #   import_path, "use_case_2_network_traffic.json"))
    converted_pcap_DOS = convert_pcap_frames(import_simulation_output(
        "C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
        "Use Case 2\\", "synflood.json"))

    for element in converted_pcap_DOS:
        print(element)

    print('')

    print('')

    simulation_output_log_dos1 = import_simulation_output(
        "C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
        "Use Case 2\\", "plc.log")
    simulation_output_log_dos2 = import_simulation_output(
        "C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
        "Use Case 2\\", "hmi.log")
    converted_logs_dos1 = convert_log_entries(simulation_output_log_dos1)
    print(get_all_ip_addr(converted_logs_dos1))
    print(get_timespan(converted_logs_dos1))
    print(get_all_severity_level(converted_logs_dos1))
    converted_logs_dos2 = convert_log_entries(simulation_output_log_dos2)
    print(get_all_ip_addr(converted_logs_dos2))
    print(get_timespan(converted_logs_dos2))
    print(get_all_severity_level(converted_logs_dos2))
    # pretty_print_list(converted_logs_dos1)

    ip1dos = converted_logs_dos1[0].generate_ipv4_addr()
    ip2dos = converted_logs_dos2[0].generate_ipv4_addr()

    print(ip1dos, ip2dos)

    print('path to data directory')
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data')