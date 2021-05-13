import re

import requests
import json

HEADERS = {
    'User-agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'}


def beaconipsum_text_generator(paragraphs=10):
    url = f'https://baconipsum.com/api/?type=all-meat&paras={str(paragraphs)}&start-with-lorem=1&format=html'
    r = requests.get(url, headers=HEADERS)
    return r.text


def gibberish_text_generator():
    url = "https://www.randomtext.me/api/gibberish/p-25/99-100"
    r = requests.get(url, headers=HEADERS)
    r_json = json.loads(r.text)
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', r_json['text_out'])
    return cleantext
