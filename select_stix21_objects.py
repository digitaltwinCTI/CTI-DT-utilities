"""
This module is intended to provide the user functions to select STIX2.1 objects
"""

from search_stix21_objects import *


def filter_scos(sco_list, sco_type=None):
    """Filters list of all possible SCOs based on type of SCO (either host, network or none)."""
    filtered_sco_list = list()
    for entry in sco_list:
        if entry[2] == sco_type.lower():
            filtered_sco_list.append(entry)
        elif sco_type is None:
            filtered_sco_list = sco_list
    print('STIX2.1 SCOs of type {}:'.format(sco_type))
    for sco in filtered_sco_list:
        print(sco)
    return filtered_sco_list


def build_sco_list(sco_list, sco_type=None):
    """Allows the user to build a custom SCO list out of all available SCOs in given list of given type."""
    custom_sco_list = list()
    for element in sco_list:
        if element[2] == sco_type or (sco_type is None):
            answer = str(input('Do you want to select {}? (yes/no) '.format(element[1])))
            if answer.lower()[:1] == 'y':
                custom_sco_list.append(element)
            elif answer.lower()[:1] == 'n':
                pass
            while answer.lower()[:1] != 'y' and answer.lower()[:1] != 'n':
                print("Please enter y (yes) or n (no)")
                answer = str(input('Do you want to select {}? (yes/no) '.format(element[1])))
                if answer.lower()[:1] == 'y':
                    custom_sco_list.append(element)
                elif answer.lower()[:1] == 'n':
                    pass
        else:
            pass
    print('You have selected the following SCOs:')
    for sco in custom_sco_list:
        print(sco)
    return custom_sco_list


def get_static_mitm_sco_list():
    """Returns a list of relevant SCOs for the MITM attack simulation use case"""
    print('You have selected the following SCOs:')
    static_mitm_sco_list = [['ipv4-addr', 'IPv4 Address Object', 'network'], ['mac-addr', 'MAC Address Object', 'network'],
                       ['network-traffic', 'Network Traffic Object', 'network'], ['process', 'Process Object', 'host']]
    for sco in static_mitm_sco_list:
        print(sco)
    return static_mitm_sco_list


def build_sdosro_list(rel_list, scosdo_list, rel_type='any'):
    """Allows the user to build a custom STIX2.1 objects list (SCO+SDO+SRO/rel) out of all available relationships."""
    rel_list_current = rel_list
    custom_scosdo_list = list()
    custom_sro_list = list()
    for element in scosdo_list:
        for rel in search_stix21_objects(rel_list_current, element[0], rel_type):
            answer = str(input('Do you want to select this relationship and associated objects {}? (yes/no) '.format(rel)))
            while answer.lower()[:1] != 'y' and answer.lower()[:1] != 'n':
                print("Please enter y (yes) or n (no)")
                answer = str(input('Do you want to select this relationship and associated objects {}? (yes/no) '
                                   .format(rel)))
            if answer.lower()[:1] == 'y':
                custom_scosdo_list.append(rel[0])
                custom_scosdo_list.append(rel[2])
                custom_sro_list.append(rel)
                rel_list_current.remove(rel)
            elif answer.lower()[:1] == 'n':
                pass
    print('You have selected the following SCOs and SDOs:')
    for scosdo in sorted(set(custom_scosdo_list)):
        print(scosdo)
    print('')
    print('You have selected the following SROs / relationships:')
    for sro in custom_sro_list:
        print(sro)
    return sorted(set(custom_scosdo_list)), custom_sro_list
