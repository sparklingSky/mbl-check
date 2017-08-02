import time
import requests
from ip_validator import ip_validator
__author__ = 'sparklingSky, koi8'

requests.packages.urllib3.disable_warnings()

virusTotalUrlStart = 'https://www.virustotal.com/en/ip-address/'
virusTotalUrlEnd = '/information/'

headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
           'accept-encoding': 'gzip, deflate, lzma, sdch',
           'accept-language': 'en-US,en;q=0.8',
           'upgrade-insecure-requests': '1',
           'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36 OPR/32.0.1948.69'}


def checkVirusTotal(ip):
    time.sleep(15)
    url = virusTotalUrlStart + str(ip) + virusTotalUrlEnd
    try:
        req = requests.get(url, headers=headers, verify=False)
    except:
        req = requests
        req.status_code = '300'
    if req.status_code is 200:
        if 'detected by at' in req.text:
            out = str(ip) + " detected by at least one URL scanner or malicious URL dataset at " + url
            return out
    else:
        out = str(ip) + " failed to check, bad status code (not 200) at " + url
        return out
    out = str(ip) + " clean at " + url
    return out


def mbl_checking(ip_list):
    ip_list = ip_validator(ip_list)
    result = []
    for ip in ip_list:
        result.append(checkVirusTotal(ip))
    return result


def write_to_file(result):
    my_file = open("output_mbl.log", "w")
    my_file.close()
    my_file = open("output_mbl.log", "a")
    if not result:
        my_file.write("No blacklisted IP addresses")
    else:
        for listing in result:
            my_file.write(listing + "\n")

    my_file.close()


def mbl_check(ip_list):
    write_to_file(mbl_checking(ip_list))
    print("\n")
    print("Completed. See the result in file output_mbl.log")


# ips = "1.2.3.0/28, 4.5.6.20"
# mbl_check(ips)
