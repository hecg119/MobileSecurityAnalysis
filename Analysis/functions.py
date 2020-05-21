import mysql.connector
from queries import *
from wordlists import KEYWORDS, SOCIAL
import math
import re
from pprint import pprint

class DB:
    def __init__(self):
        self.db = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="root",
            database="thesisdata"
        )
    
    def fetch(self, query):
        mycursor = self.db.cursor()
        mycursor.execute(query)
        return mycursor.fetchall()

def getInterestingUserAgentsForDevice(db, deviceId):
    """Extract User-Agents which contain either brand or OS type"""
    interesting = []
    uas = queryUniqueUserAgentsForDevice(db, deviceId)
    uasNormalized = [ua[0].lower() for ua in uas]
    for ua in uasNormalized:
        for keyword in KEYWORDS:
            if keyword in ua:
                interesting.append(ua)
                break
    return interesting

def getAndroidSpecificSubdomains(db):
    return queryAndroidSpecificSubdomains(db)

def getAndroidSpecificSubdomainsWithCount(db, minimum=0):
    return queryAndroidSpecificSubdomainsWithCount(db, minimum)

def getLocationStringsForDevice(db, deviceId):
    urls = queryUniqueURLsForDevice(db, deviceId)
    results = []
    for host, uri in urls:
        url = host + uri
        gps = re.search(r"(\w+=.?\d{1,3}\.\d+&\w+=.?\d{1,3}\.\d+)", url)
        if gps is not None:
            results.append((host, uri, gps.group(0)))
    return results

def getSocialNetworksForDevice(db, deviceId):
    results = []
    queries = queryDNSQueries(db, deviceId, False)
    queriesNormalized = [q[0].lower() for q in queries]
    for q in queriesNormalized:
        for key in SOCIAL:
            if key in q:
                results.append((key, q))
    return results

def getTrackersForDevice(db, deviceId):
    results = []
    subdomains = queryDeviceTrackers(db, deviceId)
    for subdomain, trackerName in subdomains:
        results.append((subdomain, trackerName))
    return results

def getNumberPiHoleTrackers(db):
    results = []
    for i in range(2,67):
        cnt = queryDevicePiHoleTrackers(db, i)
        results.append((i, cnt[0][0]))
    return results

def getPortionPiHoleTrackers(db):
    results = []
    for i in range(2,67):
        cnt = queryDevicePiHoleTrackers(db, i)
        total = queryDNSQueries(db, i, True)
        results.append((i, cnt[0][0]/total[0][0]))
    return results

def printInterestingUserAgents(db):
    print("# Interesting User-Agents\n")
    for i in range(2,67):
        print(f"## DEVICE {i}\n")
        uas = getInterestingUserAgentsForDevice(db, i)
        for ua in uas:
            print(f"```http\n{ua}\n```\n")
        print()

def printBrandSpecificSubdomains(db):
    manufacturers = queryAndroidManufacturersWithCount(db)
    print("# Brand-Specific Subdomains\n")
    for brand, count in manufacturers:
        print(f"## {brand} ({count} devices)\n")
        minimum = int(math.floor(count / 4))
        subdomains = queryManufacturerSpecificSubdomains(db, brand, minimum)
        for subdomain, subCount in subdomains:
            print(f"{subCount}: `url{subdomain}`\n")

def printTopUploadTargets(db):
    print("# TOP Upload Targets\n")
    for i in range(2,67):
        print(f"## DEVICE {i}\n")
        print("| IP | Subdomain | Sent | Received | Duration |\n| --- | --- | --- | --- | --- |")
        res = queryTopUploadTargets(db, i)
        for ip, subdomain, sent, received, duration in res:
            print(f"| {ip} | {subdomain} | {sent} | {received} | {duration} |")
        print("")

def printTLDs(db):
    print("# Most requested TLDs\n")
    for i in range(2,67): 
        print(f"## DEVICE {i}\n")
        tlds = {}
        domains = queryInterestingDomains(db, i)
        for domain in domains:
            domain = domain[0]
            res = re.search(r"(\w+)$", domain)
            tld = res.group(0)
            if tld not in tlds:
                tlds[tld] = 0
            tlds[tld] += 1
        print("| TLD | Count |\n| --- | --- |")
        sortedTlds = sorted(tlds, key=tlds.get, reverse=True)
        for tld in sortedTlds:
            print(f"| {tld} | {tlds[tld]} |")
        print("")


def printLocationStrings(db):
    print("# Location strings\n")
    for i in range(2,67): 
        print(f"## DEVICE {i}\n")
        results = getLocationStringsForDevice(db, i)
        if len(results) > 0:
            print("| Location | URI | Host |\n| ---- | ---- | ---- |")
            for row in results:
                print(f"| {row[2]} | {row[1]} | {row[0]} |")
        print("")


def printSocialNetworks(db):
    print("# Social Networks\n")
    for i in range(2,67): 
        print(f"## DEVICE {i}\n")
        results = getSocialNetworksForDevice(db, i)
        uniqueNets = set([r[0].capitalize() for r in results])
        print(f"### Total networks: {len(uniqueNets)}")
        print(", ".join(uniqueNets))
        print(f"\n### Total subdomains: {len(results)}\n")
        
        if len(results) > 0:
            print("| Social Network | Subdomain |\n| ---- | ---- |")
            for row in results:
                print(f"| {row[0]} | {row[1]} |")
        print("")


def printTrackers(db):
    print("# Trackers\n")
    for i in range(2,67): 
        print(f"## DEVICE {i}\n")
        results = getTrackersForDevice(db, i)
        uniqueTrackers = set([r[1] for r in results])
        print(f"### Total trackers: {len(uniqueTrackers)}")
        print(", ".join(uniqueTrackers))
        print(f"\n### Total tracker domains: {len(results)}")
        if len(results) > 0:
            print("| Subdomain | Name |\n| ---- | ---- |")
            for row in results:
                print(f"| {row[0]} | {row[1]} | ")
        print("")

def getHourlyUsageForDevice(db, deviceId):
    usage = queryHourlyUsage(db, deviceId)
    return [(u[0], u[1], int(u[2])) for u in usage]

def getNumberOfUniqueIPs(db):
    results = []
    for i in range(2,67):
        cnt = queryUniqueIPsForDevice(db, i, True)
        results.append((i, cnt[0][0]))
    return results

def getPortionOfUniqueIPs(db):
    results = []
    for i in range(2,67):
        unique = queryUniqueIPsForDevice(db, i, True)
        total = queryIPsForDevice(db, i, True)
        results.append((i, unique[0][0], total[0][0]))
    return results

def getPortionOfUniqueDNS(db):
    results = []
    for i in range(2,67):
        unique = queryUniqueDNSRequestsForDevice(db, i, True)
        total = queryDNSQueries(db, i, True)
        results.append((i, unique[0][0], total[0][0]))
    return results

def getHTTPxConnectionsForDevice(db, deviceId):
    return queryHTTPxConnectionsForDevice(db, deviceId)

def getPortionHTTPConnections(db):
    result = []
    for i in range(2,67):
        conn = queryHTTPxConnectionsForDevice(db, i)
        result.append((i, conn[0][2]/(conn[0][2] + conn[1][2]), conn[0][1]/(conn[0][1] + conn[1][1])))
    return result

def getTotalThreats(db):
    return queryTotalThreats(db)

def getNumberOfUniqueDNSRequests(db):
    results = []
    for i in range(2,67):
        cnt = queryUniqueDNSRequestsForDevice(db, i, True)
        results.append((i, cnt[0][0]))
    return results

def getNumberOfSocialNetworks(db):
    results = []
    for i in range(2,67): 
        res = getSocialNetworksForDevice(db, i)
        uniqueNets = set([r[0].capitalize() for r in res])
        results.append((i, len(uniqueNets)))
    return results

def getThreats(db):
    fields = ("DeviceID", "ThreatID", "ThreatID", "WorkName", "SeverityLevel", "Name", "Description", "Application", "TargetOwner", "LocationID", "DeviceModel", "OS", "OSVersion", "DeviceDetails", "MobileCarrier", "IPAddress", "InstaleldApps", "AppUpdate", "VOIP", "Tracking", "Profiling", "UserID", "SearchQuery", "VisitedWebsites", "China", "P2P", "BankInfo", "ExtendedUsage", "Email", "Gender", "Age", "MaritalStatus", "IMEI", "PersonName")
    data = queryThreats(db)
    mappedData = []
    for row in data:
        mappedData.append(dict(map(lambda x, y: (x,y), fields, row)))
    return mappedData