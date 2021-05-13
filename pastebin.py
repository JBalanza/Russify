import re
import urllib
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from mechanize import Browser

headers = {
    "user-agent": "curl/7.74.0",
    "content-type": "application/x-www-form-urlencoded"
}


def upload(message, dev_key):
    title = str(datetime.now())
    body = {}
    body["api_option"] = "paste"
    # body["api_user_key"] = user_key
    body["api_paste_private"] = "1"  # Public but unlisted
    body["api_paste_name"] = title
    body["api_paste_expire_date"] = "1D"
    body["api_dev_key"] = dev_key
    body["api_paste_code"] = urllib.parse.quote_plus(message)

    body_post = "&".join([key + "=" + value for key, value in body.items()])
    response = requests.post("https://pastebin.com/api/api_post.php", data=body_post, headers=headers)

    link = response.text

    return add_raw(link)


def download(url):
    br = Browser()
    br.set_handle_robots(False)
    br.addheaders = [('User-agent',
                      'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
    br.open("https://translate.google.com/translate?hl=&sl=&tl=&u=" + url + "&anno=2")
    for link in br.links():
        if "https://translate.googleusercontent.com/translate_p?" in link.absolute_url:
            br.follow_link(link)
            break
    response = BeautifulSoup(br.response().read().decode(),"html.parser").find("pre").get_text()
    return response


def add_raw(link):
    """
    Add the raw parameter into the url in order to get the raw message
    from pastebin.

    :param link: Original url from pastebin
    :return:
    """
    new_link = link.split("/")
    new_link.insert(len(new_link) - 1, "raw")
    return '/'.join(new_link)  # target URL
