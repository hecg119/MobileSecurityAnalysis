import requests
from pprint import pprint

API_KEY = "805f16812921f8b6ba9d535cabf532930629f569e5f26051027000cf0234222a"
API_SCAN = 'https://www.virustotal.com/vtapi/v2/url/scan'
API_REPORT = 'https://www.virustotal.com/vtapi/v2/url/report' 
API_IP = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

def getReport(url):
    params = {'apikey': API_KEY, 'resource': url, 'allinfo': 1, 'scan': True}
    response = requests.get(API_REPORT, params=params)
    return response.json()

def scanUrl(url):
    params = {'apikey': API_KEY, 'url': url}
    requests.post(API_SCAN, data=params)

def getIPReport(ip):
    params = {'apikey': API_KEY, 'ip': ip}
    response = requests.get(API_IP, params=params)
    return response.json()