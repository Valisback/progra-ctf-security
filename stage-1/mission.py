#!/usr/bin/env python

import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

def categorize_status(dom_status, dom):
    print("\nDomain Status: ")
    if dom_status == 1:
        print(f"| => The domain {dom} is found CLEAN")
    elif dom_status == -1:
        print(f"| => The domain {dom} is found MALICIOUS")
    elif dom_status == 0:
        print(f"| => The domain {dom} is found UNDEFINED")

def format_response(resp_json, dom_url):
    print("\nMore about this URL: ")
    for elem in resp_json[dom_url]:
        print("| => ", elem, ": ", resp_json[dom_url][elem])
    print("\n")

def sanitize_url(dom_url):
    s = list(dom_url)
    for i in range(len(s)):
        if s[i] == ".":
            s[i] = "(dot)"
    sain_url = "".join(s)
    return sain_url



inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")

print("\nWelcome to DN-Checker, I can provide you with security information on a specific domain name! \n\n")
domain = input("Enter domain name:")

url = f"{inv_url}/domains/categorization/{domain}?showLabels"

headers = {"Authorization": f'Bearer {inv_token}'}

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    domain_status = response.json()[domain]["status"]
    dom = sanitize_url(domain)
    categorize_status(domain_status, dom)
    format_response(response.json(), domain)
except Exception as e:
    print(e)






