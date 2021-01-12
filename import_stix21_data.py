"""
This module is intended to import data about STIX2.1 objects
"""

import csv
import os


def import_stix21_data(path, filename) -> list:
    """Imports STIX2.1 data given a path and file and saves it in a list."""
    filepath = path + filename
    stix21_data_list = list()
    with open(filepath, 'rt', encoding='utf-8-sig') as f:
        reader = csv.reader(f, delimiter=',', skipinitialspace=True)
        for line in reader:
            stix21_data_list.append(line)
    return stix21_data_list


def import_static_stix21_data():
    """Imports STIX2.1 data included in repository data directory"""
    root_dir = os.path.dirname(os.path.abspath(__file__))
    import_path = os.path.join(root_dir, 'data\\')
    sco_list = import_stix21_data(import_path, 'STIX21_SCO_list.txt')
    print('STIX2.1 SCOs imported')
    sro_list = import_stix21_data(import_path, 'STIX21_SCO_SDO_relationship_list_all.txt')
    print('STIX2.1 relationships (embedded and direct) imported')
    return sco_list, sro_list
