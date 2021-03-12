#!/usr/bin/env python

import requests
import json
import sys
import base64
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env


def encodeStringBase64(string):
    encodedBytes = base64.b64encode(string.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    return encodedStr


host = env.AMP.get("host")
client_id = env.AMP.get("client_id")
api_key = env.AMP.get("api_key")

## Parameters for the query of specific events on specific host:
exe_mw_id = 1107296272 # Event ID for executed malwares
hostname = "Demo_AMP_Threat_Audit"


# We only want malwares with type "Exected Malware"
url = f"https://{host}/v1/events?event_type[]={exe_mw_id}"

auth_string = encodeStringBase64(f"{client_id}:{api_key}")

headers = {
    "Authorization": f'Basic {auth_string}',
    "Accept": 'application/json',
    "Content-Type": 'application/json'
}

def investigateThreatGrid():
    threatgrid_host = env.THREATGRID.get("host")
    threatgrid_api_key = env.THREATGRID.get("api_key")
    threatgrid_url = f"https://{threatgrid_host}/api/v2/search/submissions?state=succ&q=b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967&api_key={threatgrid_api_key}"
    threatgrid_headers = {
        "Content-Type": 'application/x-www-form-urlencoded',
    }  
    try:
        response = requests.get(threatgrid_url, headers=threatgrid_headers)
        response.raise_for_status()
        sample_id = response.json()["data"]["items"][0]["item"]["sample"]
        print("| => sample_id = ", sample_id, "\n")
        threatgrid_url = f"https://{threatgrid_host}/api/v2/samples/feeds/domains?sample={sample_id}&api_key={threatgrid_api_key}"
        try:
            response = requests.get(threatgrid_url, headers=threatgrid_headers)
            data = {}
            data["domain_list"] = []
            for elem in response.json()["data"]["items"]:
                # We only add unique domain names to the domain list
                if not(elem["domain"] in data["domain_list"]):
                    data["domain_list"].append(elem["domain"])
            print("\n ================== List of domains with the sample ==================")
            for domain in data["domain_list"]:
                print("| => ", domain)
            print("\n")
            with open('domains.json', 'w') as outfile:
                json.dump(data, outfile, indent=4)
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)



def requestComputerIsolation(connector_guid):
    isol_url = f"https://{host}/v1/computers/{connector_guid}/isolation"
    try:
        response = requests.put(isol_url, headers=headers)
        response.raise_for_status()
        pprint(response.json()["data"], indent = 4)
    except Exception as e:
        print(e)
    print("\n ================== ThreatGrid Call ==================")
    investigateThreatGrid()

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()["data"]
    for i in data:
        if(i["computer"]["hostname"] == hostname):
            print("\n ================== AMP Event ==================\n")
            pprint(i, indent=4)
            print("\n ================== AMP Isolation Call ==================")
            requestComputerIsolation(i["connector_guid"])
except Exception as e:
    print(e)






