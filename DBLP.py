import requests
import json


def get_data():
    url = 'http://dblp.org/search/publ/api?q=Cyber%24%20Threat%24%20Intelligence%24&format=json&h=20'
    result = requests.get(url)
    data = result.text
    json_data = json.loads(data)
    #print(type(json_data))
    #print(json.dumps(json_data, indent=4))
    print_basic_infos(json_data)
    structure_data(json_data)


def print_basic_infos(data):
    basic_info_list = [data['result']['query'], data['result']['hits']['@total']]
    print("Search term: " + basic_info_list[0] + ' (exact)')
    print("Search results: " + basic_info_list[1])

def structure_data(data):

    pub_dict = dict()

    for pub in data['result']['hits']['hit']:
        if pub['info']['year'] in pub_dict:
            pub_dict[pub['info']['year']].append(pub['info']['title'])
        else:
            #pub_dict = {pub['info']['year'] : pub['info']['title']}
            pub_dict[pub['info']['year']] = pub['info']['title']
    print(pub_dict)


if __name__ == '__main__':

    get_data()