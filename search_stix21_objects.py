"""
This module is intended to search relationships of STIX2.1 objects
"""


def search_stix21_objects(rel_list, object_name, rel_type='any') -> list:
    """Searches STIX2.1 relationship list for relationships that include a given object and are of specified type."""
    searched_rel_list = list()
    for relationship in rel_list:
        if relationship[3] == rel_type or rel_type == 'any':
            if relationship[0] == object_name and relationship[0] == relationship[2]:
                searched_rel_list.append(relationship)
            else:
                for position in range(len(relationship)):
                    if relationship[position] == object_name:
                        searched_rel_list.append(relationship)
    return searched_rel_list
