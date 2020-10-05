import requests
import urllib3
import time
from bs4 import BeautifulSoup

url = 'https://dblp.uni-trier.de/search?q=Cyber%24%20Threat%24%20Intelligence%24'
page = requests.get(url)

soup = BeautifulSoup(page.content, 'html.parser')

results = soup.find(id='completesearch-info-matches')

print(results.prettify())

#publications = results.find_all('section', class_='card-content')
