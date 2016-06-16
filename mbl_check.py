import time
import requests
import ipcalc
from xml.dom.minidom import parseString
requests.packages.urllib3.disable_warnings()
__author__ = 'koi8, sparklingSky'

# Specify network to check in 'net' variable,
# Configure run in the 'checkNetwork' function at the end of file
net = '1.2.3.0/24'

cMxUrls = ['http://support.clean-mx.de/clean-mx/xmlviruses.php?review=',
           'http://support.clean-mx.de/clean-mx/xmlportals.php?review=',
           'http://support.clean-mx.de/clean-mx/xmlphishing.php?review=']

virusTotalUrlStart = 'https://www.virustotal.com/en/ip-address/'
virusTotalUrlEnd = '/information/'

headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
           'accept-encoding': 'gzip, deflate, lzma, sdch',
           'accept-language': 'en-US,en;q=0.8',
           'upgrade-insecure-requests': '1',
           'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36 OPR/32.0.1948.69'}


def checkVirusTotal(ip):
    result = checkVirusTtl(ip)
    writeToFile(result)
    print(result)


def checkVirusTtl(ip):
    time.sleep(2)
    url = virusTotalUrlStart + str(ip) + virusTotalUrlEnd
    try:
        req = requests.get(url, headers=headers, verify=False)
    except:
        req = requests
        req.status_code = '300'
    if req.status_code is 200:
        if 'detected by at' in req.text:
            out = str(ip) + ', detected by at least one URL scanner or malicious URL dataset ' + url
            return out
    else:
        out = str(ip) + ', failed to check, bad status code(not 200)'
        return out
    out = str(ip) + ', clean on ' + url
    return out


def checkCleanMx(ip):
    for url in cMxUrls:
        result = checkCleanMxUrl(ip, url)
        writeToFile(result)
        print(result)


def checkCleanMxUrl(ip, url):
    time.sleep(3)
    try:
        req = requests.get(url + str(ip), timeout=40, verify=False)
    except:
        req = requests
        req.status_code = '300'
    if req.status_code is 200:
        try:
            dom = parseString(req.text)
            entries = dom.getElementsByTagName('entry')
            if len(entries) > 0:
                out = str(ip) + ', found ' + str(len(entries)) + ' entries on ' + url + str(ip)
                return out
        except:
            out = str(ip) + ', failed to check(bad page returned with good code 200)'
            return out
    else:
        out = str(ip) + ', failed to check, bad status code(not 200)'
        return out
    out = str(ip) + ', clean on ' + url + str(ip)
    return out


def writeToFile(result):
    my_file = open("output_mbl.log", "a", 0)
    my_file.write(result + '\n')
    my_file.close()


def checkNetwork(net):
    for ip in ipcalc.Network(net):
        # Uncomment or comment required checks:
        # checkCleanMx(ip)
        checkVirusTotal(ip)
    print 'Completed. See the result in file output_mbl.log'


if __name__ == "__main__":
    checkNetwork(net)
