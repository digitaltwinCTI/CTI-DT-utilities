from fp.fp import FreeProxy
from scholarly import scholarly


def search_authors(request_number):
    request_counter = request_number

    proxy = FreeProxy(rand=True, timeout=1, country_id=['US', 'CA']).get()
    scholarly.use_proxy(http=proxy, https=proxy)

    search_query = scholarly.search_pubs('Cyber Threat Intelligence')
    while request_counter > 0:
        print(request_counter)
        request_counter -= 1
        extract_information(next(search_query))
        #print(next(search_query).bib['title'])
        # print(next(search_query))


def extract_information(publication_object):
    information_dict = {}
    information_list = [publication_object.bib['author'], publication_object.bib['title'],
                        publication_object.bib['year'], publication_object.bib['cites']]
    #information_dict['1'] = ['1','2']
    information_dict[information_list.append(publication_object.bib['gsrank'])] = information_list
    print(information_list)


if __name__ == '__main__':

    search_request = 1
    try:
        print("This script retrieves information about scientific publications from Google Scholar")
        search_request = int(input("Enter the number of requested search results: "))
        search_authors(search_request)
    except ValueError:
        print("Please enter a valid number")
