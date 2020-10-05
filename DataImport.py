import csv
import datetime
import json
import ipaddress
import click

from typing import List, Any, Type

from log_entry import LogEntry

applicable_rel = list()
sdo_list = list()


def import_stix21_relationships(path, filename) -> list:
    """Imports STIX2.1 relationships and saves in list."""
    filepath = path + filename
    rel_list: List[List[str]] = list()
    with open(filepath, 'rt', encoding='utf-8-sig') as f:
        reader = csv.reader(f, delimiter=';', skipinitialspace=True)
        for line in reader:
            rel_list.append(line)
            # print(line)
    return rel_list


def search_stix21_objects(rel_list, object_name, rel_type='any') -> list:
    """Searches STIX2.1 relationship list for relationships that include a given object and are of specified type."""
    searched_rel_list: List[Any] = list()
    for relationship in rel_list:
        if relationship[3] == rel_type or rel_type == 'any':
            if relationship[0] == object_name and relationship[0] == relationship[2]:
                searched_rel_list.append(relationship)
                # print(relationship[0:4])
            else:
                for position in range(len(relationship)):
                    if relationship[position] == object_name:
                        searched_rel_list.append(relationship)
                        # print(relationship[0:4])
    return searched_rel_list


def import_simulation_output(path, filename) -> list:
    """Imports digital twin simulation output from common simulation_output_list formats and saves in list."""
    filepath = path + filename
    simulation_output_list: List[List[str]] = list()
    with open(filepath, 'rt', encoding='utf-8-sig') as f:
        if filename.endswith(('.txt', '.log', 'csv')):
            reader = csv.reader(f, delimiter=' ', skipinitialspace=True)
            for line in reader:
                simulation_output_list.append(line)
                # print(line)
        elif filename.endswith('.json'):
            simulation_output_list = json.load(f)
            # print(json.dumps(simulation_output_list, indent=4, sort_keys=False))
    print('Simulation output imported')
    return simulation_output_list


def convert_log_entries(simulation_output):
    """Converts a list of log entries to LogEntry class instances and saves objects in list."""
    log_entry_list = list()
    for line in simulation_output:
        level = line[0]
        timestamp = extract_timestamp(line)
        ip_addr_host = line[3]
        program = line[4]
        message = ' '.join(line[5:])
        ip_addr_external = analyze_log_message_ip(message)
        log_entry_list.append(LogEntry(level, timestamp, ip_addr_host, program, message, ip_addr_external))
    print('Log entries converted')
    return log_entry_list


def extract_timestamp(log) -> datetime:
    """Extracts and converts timestamp information of a log entry into a datetime object"""
    year = int(log[1][-4:])
    month = int(log[1][0:2])
    day = int(log[1][3:5])
    hour = int(log[2][0:2])
    minute = int(log[2][3:5])
    second = int(log[2][6:8])
    return datetime.datetime(year, month, day, hour, minute, second)


def analyze_log_message_ip(message) -> str:
    """Checks for additional IP address in log message (e.g. log event triggered by external entity)."""
    for element in message.split():
        try:
            ipaddress.ip_address(element[:-1])
            return element[:-1]
        except ValueError:
            pass


def filter_log_severity(log_entry_list, level: str) -> list:
    """Filters log entries based on given severity log level."""
    filtered_log_entries = list()
    for entry in log_entry_list:
        if entry.loglevel.lower() == level.lower():
            filtered_log_entries.append(entry)
    print('Log entries filtered based on {}'.format(level))
    return filtered_log_entries


def filter_log_timestamps(log_entry_list, deviation: datetime.timedelta, center_timestamp=None) -> list:
    """Filters log entries based on given timestamp and given plus/minus time deviation."""
    filtered_log_entries = list()
    default_center_timestamp = log_entry_list[int(len(log_entry_list)/2)].timestamp
    for entry in log_entry_list:
        if center_timestamp is not None:
            if center_timestamp - deviation < entry.timestamp < center_timestamp + deviation:
                filtered_log_entries.append(entry)
                # print(entry.timestamp, entry.loglevel, entry.message)
        else:
            if default_center_timestamp - deviation < entry.timestamp < default_center_timestamp + deviation:
                filtered_log_entries.append(entry)
                # print(entry.timestamp, entry.loglevel, entry.message)
    print('Log entries filtered based on {} timestamp with {} deviation'.format(center_timestamp, deviation))
    return filtered_log_entries


def filter_log_ip(log_entry_list, ip_addr: str, host_only=True):
    """Filters log entries based on given IP address (default only for host IP address)."""
    filtered_log_entries = list()
    for entry in log_entry_list:
        if not host_only and (ip_addr == entry.ip_addr_host or ip_addr == entry.ip_addr_external):
            filtered_log_entries.append(entry)
        elif host_only and ip_addr == entry.ip_addr_host:
            filtered_log_entries.append(entry)
    print('Log entries filtered based on {} and host only {}'.format(ip_addr, host_only))
    return filtered_log_entries


def get_all_severity_level(log_entry_list):
    """Gets all distinct severity log levels found in the log entry list."""
    severity_list = list()
    for entry in log_entry_list:
        severity_list.append(entry.loglevel)
    print('Severity log levels identified within all log entries:')
    return sorted(set(severity_list))


def get_log_timespan(log_entry_list):
    """Gets first and last timestamp found in the log entry list."""
    first_last_timestamp_list = list()
    first_last_timestamp_list.append(log_entry_list[0].timestamp)
    first_last_timestamp_list.append(log_entry_list[len(log_entry_list)-1].timestamp)
    print('First and last timestamp identified within all log entries:')
    return first_last_timestamp_list


def get_all_ip_addr(log_entry_list):
    """Gets all distinct IP addresses found in the log entry list."""
    ip_addr_list = list()
    for entry in log_entry_list:
        ip_addr_list.append(entry.ip_addr_host)
        if entry.ip_addr_external is not None:
            ip_addr_list.append(entry.ip_addr_external)
    print('IP addresses of network topology identified within all log entries:')
    return sorted(set(ip_addr_list))


def get_rfc3339_timestamp(timestamp):
    """Gets an RFC 3339-formatted timestamp in UTC timezone (e.g. 2020-08-17T10:23:37.149Z)"""
    return timestamp.isoformat('T') + 'Z'


def filter_scos(sco_list, sco_type='any'):
    """Filters list of all possible SCOs based on type of SCO (either host, network of any)."""
    filtered_sco_list = list()
    for entry in sco_list:
        if entry[2] == sco_type:
            filtered_sco_list.append(entry)
        elif sco_type == 'any':
            filtered_sco_list = sco_list
    print('STIX2.1 SCOs of type {}:'.format(sco_type))
    return filtered_sco_list









def parse_simulation_output(simulation_output):
    """Parses digital twin simulation output into STIX2.1 SCOs"""
    print("results are SCOs")


def assess_relationship(relationship):
    applicable_rel.append(relationship)
    print("Relationship and its objects have been added")


if __name__ == '__main__':
    '''Import and save simulation output from given log file'''
    simulation_output_log = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\"
                                     "Filling-plant logs\\", "NEWplc1.log")
    '''Convert imported simulation output to LogEntry objects'''
    converted_logs = convert_log_entries(simulation_output_log)
    '''Provide target information about the log entries contained in the simulation output'''
    print(get_all_ip_addr(converted_logs))
    '''Provide time information about the log entries contained in the simulation output'''
    print(get_log_timespan(converted_logs))
    '''Provide type information about the log entries contained in the simulation output'''
    print(get_all_severity_level(converted_logs))
    '''Perform filtering based on time, target and type'''
    filtered_ip = filter_log_ip(converted_logs, '10.0.0.1')
    filtered_severity = filter_log_severity(filtered_ip, 'WARNING')
    filtered_time = filter_log_timestamps(filtered_severity, datetime.timedelta(0, 8, 0, 0, 0), datetime.datetime(2020, 8, 17, 13, 51, 00))
    print(filtered_time)









    ''' Import a txt file containing all STIX2.1 relationships'''
    rel_list1 = import_stix21_relationships("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\STIX Relationship Data\\",
                                            "done_STIX21_SCO_SDO_relationship_list_all.txt")
    '''Searching the relationship list for a STIX2.1 object with specified relationship type '''
    search_list1 = search_stix21_objects(rel_list1, "ipv4-addr", 'direct')
    # print(search_list1)
    '''Import the output of digital twin simulation'''
    # print(import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\", "DOS.json"))
    # test1 = import_simulation_output("C:\\Users\\LocalAdmin\\Documents\\04_DT CTI\\Simulation Output\\Filling-plant logs\\", "plc1.log")





    #print(extract_timestamp(test1[0]))
    #print(extract_timestamp(test1[0]) - datetime.timedelta(0, 7))

    #filter_log_severity(convert_log_entries(test1), 'warning')
    #filter_log_timestamps(convert_log_entries(test1), datetime.timedelta(0, 8, 0, 0, 0))
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
