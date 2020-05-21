from bro_log_parser import parse_log_file
import re
import csv
import sys
from ipwhois import IPWhois, IPDefinedError
from pprint import pprint
import json
import os
import traceback
import platform
import copy
import time
from pathlib import Path
import virustotal

DNS_FILE = "dns.log"
CONN_FILE = "conn.log"
HTTP_FILE = "http.log"
SERVER_IP = "10.8.0.1"
TRACKERS_SOURCE = "trackers.json"
DEVICES_SOURCE = "devices.csv"
OUTPUT_FOLDER = "out"
CACHE_FOLDER = "cache"

if platform.node() == "edna":
    BASE_PATH = "/home/kuba/pcaps/"
else:
    BASE_PATH = "../"

EXPORT_DNS = True
EXPORT_VIRUSTOTAL_URLS = False
EXPORT_VIRUSTOTAL_IPS = False
EXPORT_CONNECTIONS = False
EXPORT_HTTP = False
EXPORT_USAGE = False


class DnsQuery:
    def __init__(self, fullDomain, recordType, answers, deviceId):
        self.ips = set()
        self.deviceId = deviceId
        self.fullDomain = fullDomain
        self.type = recordType
        self.topDomain = DnsQuery.extractDomain(fullDomain)
        self.extractIpsFromAnswer(answers)

    @staticmethod
    def extractDomain(fullDomain):
        res = re.search(r"\w+\.\w+$", fullDomain)
        return res.group(0)

    def extractIpsFromAnswer(self, answers):
        if answers is not None:
            for x in answers:
                if re.match(r"\d+\.\d+\.\d+\.\d+", x):
                    self.ips.add(x)

    def __hash__(self):
        return hash(self.fullDomain)

    def __eq__(self, other):
        return self.fullDomain == other.fullDomain


class Connection:
    def __init__(self, ip, port, protocol, service, deviceId):
        self.deviceId = deviceId
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.service = service
        self.totalDuration = 0
        self.totalBytesSent = 0
        self.totalBytesReceived = 0

    def addNew(self, duration, sentBytes, receivedBytes):
        self.totalBytesSent += sentBytes
        self.totalBytesReceived += receivedBytes
        self.totalDuration += duration

def readDevices():
    out = []
    with open(DEVICES_SOURCE, "r") as devicesFile:
        reader = csv.DictReader(devicesFile, delimiter=",")
        for row in reader:
            out.append(row)
    return out


def getFullDeviceName(folders, device):
    name = None
    if device["Name"] == "fersantillanglez-20181204173249_10.8.0.41":
        name = "fersantillanglez-20181204173249_10.8.0.41"
    elif device["Name"] == "fersantillanglez-20181204173249_10.8.0.41-smaller":
        name = "fersantillanglez-20181204173249_10.8.0.41-smaller"
    else:
        for folder in folders:
            if device["Name"] in folder:
                name = folder
                break
    return name


def getDnsServers(basePath) -> set:
    servers = set()
    for entry in parse_log_file(f"{basePath}/{DNS_FILE}"):
        servers.add(str(entry.id_resp_h))
    return servers


def getDnsQueries(basePath, deviceId) -> set:
    queries = set()
    for entry in parse_log_file(f"{basePath}/{DNS_FILE}"):
        if entry.rcode == 0:
            if hasattr(entry, "query"):
                query = entry.query
            elif hasattr(entry, "host"):
                query = entry.host
            q = DnsQuery(query, entry.qtype_name, entry.answers, deviceId)
            queries.add(q)
    return queries


def getSummarizedConnections(basePath, deviceId):
    connections = {}
    for entry in parse_log_file(f"{basePath}/{CONN_FILE}"):
        ip = str(entry.id_resp_h)
        srcIp = str(entry.id_orig_h)
        port = entry.id_resp_p
        if srcIp != SERVER_IP and entry.duration is not None:
            if ip not in connections:
                connections[ip] = {port: Connection(
                    ip, entry.id_resp_p, entry.proto, entry.service, deviceId)}
            elif port not in connections[ip]:
                connections[ip][port] = Connection(
                    ip, entry.id_resp_p, entry.proto, entry.service, deviceId)
            connections[ip][port].addNew(
                entry.duration, entry.orig_ip_bytes, entry.resp_ip_bytes)
    connList = []
    for connEntry in connections.values():
        connList += list(connEntry.values())

    return set([*connections]), connList


def getTrackers():
    out = []
    with open(TRACKERS_SOURCE, "r") as trackersFile:
        trackers = json.load(trackersFile)
        trackers = trackers["trackers"]
        for trackerId in trackers:
            tracker = trackers[trackerId]
            signatureRaw = tracker["network_signature"]
            if signatureRaw != "NC":
                signature = signatureRaw.replace("\\", "").split("|")
                entry = {"TrackerID": int(
                    tracker["id"]), "Name": tracker["name"], "Signature":  signature,  "Website": tracker["website"]}
                out.append(entry)
    return out


def identifyTracker(url, trackers) -> int:
    for tracker in trackers:
        for signature in tracker["Signature"]:
            if url.endswith(signature):
                # print(f"Found tracker {tracker['Name']}")
                return tracker["TrackerID"]
    return None


def getHttpConnections(basePath, deviceID):
    out = []
    for entry in parse_log_file(f"{basePath}/{HTTP_FILE}"):
        mime = None
        if entry.resp_mime_types is not None:
            mime = ";".join(entry.resp_mime_types)
        out.append({"DeviceID": deviceID, "IP": entry.id_resp_h, "Port": entry.id_resp_p, "Method": entry.method, "Version": entry.version, "Host": entry.host, "URI": entry.uri,
                    "Referrer": entry.referrer, "UserAgent": entry.user_agent, "StatusCode": entry.status_code, "ResponseMIME": mime})
    return out

def getUsage(basePath):
    hours = [{"Count": 0, "Duration": 0.0} for i in range(0,24)]
    usage = [copy.deepcopy(hours) for i in range(0,7)]  # 0 = Monday
    
    for entry in parse_log_file(f"{basePath}/{CONN_FILE}"):
        srcIp = str(entry.id_orig_h)
        if srcIp != SERVER_IP and entry.duration is not None:
            weekday = entry.ts.weekday()
            hour = entry.ts.hour
            usage[weekday][hour]["Count"] += 1
            usage[weekday][hour]["Duration"] += entry.duration
    return usage

###################
#####  TABLES  ####
###################


def prepareIpsTable(ips) -> list:
    out = []
    cachedIps = set()
    fieldnames = ["IP", "ASN", "ASNCountry", "ASNDescription"]

    with open(f"{CACHE_FOLDER}/cachedIPs.csv", 'r', encoding="utf-8", newline='') as cacheFile:
        cacheReader = csv.DictReader(
            cacheFile, delimiter=",", fieldnames=fieldnames)
        for cacheEntry in cacheReader:
            out.append(cacheEntry)
            cachedIps.add(cacheEntry["IP"])
        print(f"Using {len(cachedIps)} cached IPs")

    with open(f"{CACHE_FOLDER}/cachedIPs.csv", 'a', encoding="utf-8", newline='') as cacheFile:
        cacheWriter = csv.DictWriter(
            cacheFile, delimiter=",", fieldnames=fieldnames)
        print(f"ASM info is missing for {len(ips) - len(cachedIps)} IPs")
        for ip in ips:
            if ip not in cachedIps:
                print(f"Looking up ASN info for {ip}")
                try:
                    results = IPWhois(ip).lookup_rdap(
                        depth=1, asn_methods=['dns', 'whois', 'http'])
                    entry = {"IP": ip, "ASN": results["asn"], "ASNCountry": results["asn_country_code"],
                             "ASNDescription": results["asn_description"]}
                except IPDefinedError:
                    entry = {"IP": ip, "ASN": None, "ASNCountry": None,
                             "ASNDescription": "Private-Use Network"}
                out.append(entry)
                cacheWriter.writerow(entry)
        return out


def prepareSubdomainsTable(dns, trackers) -> list:
    out = []
    for q in dns:
        tracker = identifyTracker(q.fullDomain, trackers)
        entry = {"SubdomainName": q.fullDomain,
                 "DomainName": q.topDomain, "TrackerID": tracker, "VTPositives": None, "VTLink": None}
        out.append(entry)
    return out

def prepareDNSQueriesTable(dns) -> list:
    out = []
    for q in dns:
        entry = {"DeviceID": q.deviceId, "SubdomainName": q.fullDomain}
        out.append(entry)
    return out

def prepareIPsHasSubdomainsTable(dns, ips) -> list:
    out = []
    for q in dns:
        for ip in q.ips:
            if ip in ips:
                entry = {"SubdomainName": q.fullDomain, "IP": ip}
                out.append(entry)
    return out


def prepareConnectionsTable(connections) -> list:
    out = []
    for conn in connections:
        entry = {"DeviceID": conn.deviceId, "IP": conn.ip, "Port": conn.port, "Protocol": conn.protocol, "Service": conn.service,
                 "TotalBytesSent": conn.totalBytesSent, "TotalBytesReceived": conn.totalBytesReceived, "TotalDuration": conn.totalDuration}
        out.append(entry)
    return out

def prepareUsageTable(usage) -> list:
    out = []
    for deviceId in usage:
        for weekday in range(0,7):
            for hour in range(0,24):
                u = usage[deviceId]
                entry = {"DeviceID": deviceId, "DayID": weekday, "Hour": hour, "Duration": u[weekday][hour]["Duration"], "Count": u[weekday][hour]["Count"]}
                out.append(entry)
    return out

def retrieveVirusTotalUrlReports():
    queue = set()
    missing = []
    allSubdomains = {}
    failed = False
    i = 0
    fieldnames = ["SubdomainName", "DomainName", "TrackerID", "VTPositives", "VTLink"]

    with open(f"{OUTPUT_FOLDER}/subdomains.csv", 'r', encoding="utf-8", newline='') as subFile:
        subReader = csv.DictReader(
            subFile, delimiter=",", fieldnames=fieldnames)
        for entry in subReader:
            allSubdomains[entry["SubdomainName"]] = entry
            queue.add(entry["SubdomainName"])
    
    with open(f"{CACHE_FOLDER}/virustotal.csv", 'r', encoding="utf-8", newline='') as vtFile:
        vtReader = csv.DictReader(
            vtFile, delimiter=",", fieldnames=fieldnames)
        for entry in vtReader:
            queue.discard(entry["SubdomainName"])
    
    with open(f"{CACHE_FOLDER}/virustotal.csv", 'a', encoding="utf-8", newline='') as vtFile:
        subWriter = csv.DictWriter(
            vtFile, delimiter=",", fieldnames=fieldnames)
        total = len(queue)
        print(f"Retrieving VT reports for {len(queue)} URLs")
        for url in queue:
            sys.stdout.write(f"\r{i}/{total}")
            sys.stdout.flush()
            i +=1
            entry = allSubdomains[url]
            report = virustotal.getReport(url)
            if report["response_code"] == 0:
                failed = True
                virustotal.scanUrl(url)
                missing.append(entry)
            else:
                entry["VTPositives"] = report["positives"]
                entry["VTLink"] = report["permalink"]
                subWriter.writerow(entry)
    print("")
    if failed:
        print("Some subdomains weren't retrieved, please rerun.")
    print("VirusTotal analysis finished")
    return missing

def parseSamples(ip, entryType, values):
    total = {"IP": ip, "Type": entryType, "Positives": 0, "Total": 0, "Count": 0}
    for x in values:
        total["Positives"] += x["positives"]
        total["Total"] += x["total"]
        total["Count"] += 1
    return [total]

def retrieveVirusTotalIpReports():
    out = []
    try:
        with open(f"{OUTPUT_FOLDER}/ips.csv", 'r', encoding="utf-8", newline='') as ipFile:
            ipReader = csv.DictReader(ipFile, delimiter=",")
            i = 1
            for entry in ipReader:
                try:
                    data = virustotal.getIPReport(entry["IP"])
                    out += parseSamples(entry["IP"], "P_COMM", data.get("detected_communicating_samples", []))
                    out += parseSamples(entry["IP"], "N_COMM", data.get("undetected_communicating_samples", []))
                    out += parseSamples(entry["IP"], "P_DOWN", data.get("detected_downloaded_samples", []))
                    out += parseSamples(entry["IP"], "N_DOWN", data.get("undetected_downloaded_samples", []))
                    out += parseSamples(entry["IP"], "P_REFF", data.get("detected_referrer_samples", []))
                    out += parseSamples(entry["IP"], "N_REFF", data.get("undetected_referrer_samples", []))
                except Exception as e:
                    pprint(e)
                    print(f"Error: {entry['IP']}\n")
                sys.stdout.write(f"\r{i} IPs processed")
                sys.stdout.flush()
                i += 1
        print("")
    except FileNotFoundError:
        print("ERROR: ips.csv was not found")
    return out

    
    

###################
#####  EXPORT  ####
###################

def exportTable(path, fieldnames, content):
    with open(path, 'w', encoding="utf-8", newline='') as outFile:
        writer = csv.DictWriter(
            outFile, dialect='excel', fieldnames=fieldnames)
        writer.writeheader()
        for row in content:
            writer.writerow(row)


def exportTrackersTable(trackersTable):
    fieldnames = ["TrackerID", "Name", "Signature",  "Website"]
    exportTable(f"{OUTPUT_FOLDER}/trackers.csv", fieldnames, trackersTable)
    print(f"{len(trackersTable)} trackers exported.")


def exportSubdomainsTable(subdomainsTable):
    fieldnames = ["SubdomainName", "DomainName", "TrackerID", "VTPositives", "VTLink"]
    exportTable(f"{OUTPUT_FOLDER}/subdomains.csv", fieldnames, subdomainsTable)
    print(f"{len(subdomainsTable)} subdomains exported.")

def exportDNSQueriesTable(dnsQueriesTable):
    fieldnames = ["DeviceID", "SubdomainName"]
    exportTable(f"{OUTPUT_FOLDER}/dnsQueries.csv", fieldnames, dnsQueriesTable)
    print(f"{len(subdomainsTable)} DNS queries exported.")

def exportSubdomainsWithVTReportsTable(missing):
    subdomainsTable = missing
    fieldnames = ["SubdomainName", "DomainName", "TrackerID", "VTPositives", "VTLink"]
    with open(f"{CACHE_FOLDER}/virustotal.csv", 'r', encoding="utf-8", newline='') as vtFile:
        vtReader = csv.DictReader(
            vtFile, delimiter=",", fieldnames=fieldnames)
        for entry in vtReader:
            subdomainsTable.append(entry)
    exportTable(f"{OUTPUT_FOLDER}/subdomainsWithVT.csv", fieldnames, subdomainsTable)
    print(f"{len(subdomainsTable)} subdomains exported.")


def exportIPsHasSubdomainsTable(ipsHasSubdomainsTable):
    fieldnames = ["IP", "SubdomainName"]
    exportTable(f"{OUTPUT_FOLDER}/ipsHasSubdomains.csv",
                fieldnames, ipsHasSubdomainsTable)
    print(f"{len(ipsHasSubdomainsTable)} IP-Subdomain pairs exported.")


def exportIPsTable(ipsTable):
    fieldnames = ["IP", "ASN", "ASNCountry", "ASNDescription"]
    exportTable(f"{OUTPUT_FOLDER}/ips.csv", fieldnames, ipsTable)
    print(f"{len(ipsTable)} IPs exported.")


def exportConnectionsTable(connectionsTable):
    fieldnames = ["DeviceID", "IP", "Port", "Protocol", "Service",
                  "TotalBytesSent", "TotalBytesReceived", "TotalDuration"]
    exportTable(f"{OUTPUT_FOLDER}/connections.csv",
                fieldnames, connectionsTable)
    print(f"{len(connectionsTable)} connections exported.")


def exportIPsToBeProcessed(ips):
    with open(f"{OUTPUT_FOLDER}/ipsToBeProcessed.csv", "w") as outFile:
        ipsList = list(ips)
        outFile.writelines(s + '\n' for s in ipsList)
    print(f"{len(ips)} IPs exported.")


def exportHTTPCommsTable(httpTable):
    fieldnames = ["DeviceID", "IP", "Port", "Method", "Version", "Host", "URI",
                    "Referrer", "UserAgent", "StatusCode", "ResponseMIME"]
    exportTable(f"{OUTPUT_FOLDER}/httpcomms.csv", fieldnames, httpTable)
    print(f"{len(httpTable)} HTTP requests exported.")

def exportUsageTable(usageTable):
    fieldnames = ["DeviceID", "DayID", "Hour", "Duration", "Count"]
    exportTable(f"{OUTPUT_FOLDER}/usage.csv", fieldnames, usageTable)
    print("Usage exported.")

def exportSamplesTable(samplesTable):
    fieldnames = ["IP", "Type", "Positives", "Total", "Count"]
    exportTable(f"{OUTPUT_FOLDER}/samples.csv", fieldnames, samplesTable)
    print("Samples exported.")

###################
#####   RUN    ####
###################


notFoundDevices = []
notFoundFiles = []
dnsServers = {}
dnsQueries = set()
dnsDeviceQueries = []
ips = set()
connections = []
http = []
usage = {}

allPcapFolders = os.listdir(BASE_PATH)
allAltPcapFolders = os.listdir(BASE_PATH)
Path(OUTPUT_FOLDER).mkdir(parents=True, exist_ok=True)
Path(CACHE_FOLDER).mkdir(parents=True, exist_ok=True)
open(f"{CACHE_FOLDER}/cachedIPs.csv", 'a').close()
open(f"{CACHE_FOLDER}/virustotal.csv", 'a').close()
devices = readDevices()


for device in devices:
    fullName = getFullDeviceName(allPcapFolders, device)
    if fullName is None:
        notFoundDevices.append(device)
        print(f"Could not find device {device['Name']}")
        continue
    path = f"{BASE_PATH}{fullName}/bro"
    print(f"Processing {fullName}")
    try:
        if EXPORT_DNS or EXPORT_CONNECTIONS:
            try:
                qs = getDnsQueries(path, device["ID"])
                dnsQueries = dnsQueries.union(qs)
                dnsDeviceQueries += list(qs)
                print(f"Total DNS queries: {len(dnsQueries)}")
            except FileNotFoundError:
                print(f"!!! DNS file not found in {device['Name']}")
                notFoundFiles.append(f"{device['Name']}/bro/dns.log")

            try:
                deviceIps, deviceConnections = getSummarizedConnections(
                    path, device["ID"])
                ips = ips.union(deviceIps)
                connections += deviceConnections
                print(f"Total connections: {len(deviceConnections)}")
            except FileNotFoundError:
                print(f"!!! Conn file not found in {device['Name']}")
                notFoundFiles.append(f"{device['Name']}/bro/conn.log")

        if EXPORT_HTTP:
            try:
                http += getHttpConnections(path, device["ID"])
            except FileNotFoundError:
                print(f"!!! HTTP file not found in {device['Name']}")
                notFoundFiles.append(f"{device['Name']}/bro/http.log")
            
        if EXPORT_USAGE:
            try:
                usage[device["ID"]] = getUsage(path)
            except FileNotFoundError:
                print(f"!!! Conn file not found in {device['Name']}")
                notFoundFiles.append(f"{device['Name']}/bro/conn.log")

    except Exception as ex:
        print(f"Error in {device['Name']}")
        traceback.print_tb(ex.__traceback__)


if EXPORT_CONNECTIONS:
    exportIPsToBeProcessed(ips)
    connectionsTable = prepareConnectionsTable(connections)
    exportConnectionsTable(connectionsTable)

if EXPORT_DNS:
    trackers = getTrackers()
    ipsHasSubdomainsTable = prepareIPsHasSubdomainsTable(dnsQueries, ips)
    subdomainsTable = prepareSubdomainsTable(dnsQueries, trackers)
    dnsQueriesTable = prepareDNSQueriesTable(dnsDeviceQueries)
    exportTrackersTable(trackers)
    exportIPsHasSubdomainsTable(ipsHasSubdomainsTable)
    exportSubdomainsTable(subdomainsTable)
    exportDNSQueriesTable(dnsQueriesTable)

if EXPORT_VIRUSTOTAL_URLS:
    missing = retrieveVirusTotalUrlReports()
    exportSubdomainsWithVTReportsTable(missing)

if EXPORT_VIRUSTOTAL_IPS:  
    samples = retrieveVirusTotalIpReports()
    exportSamplesTable(samples)

if EXPORT_HTTP:
    exportHTTPCommsTable(http)

if EXPORT_USAGE:
    usageTable = prepareUsageTable(usage)
    exportUsageTable(usageTable)


print("######################")
print("Missing devices:")
pprint(notFoundDevices)

print("######################")
print("Missing files:")
pprint(notFoundFiles)

# To lookup ips use https://ipinfo.io.
### Token: 84d55fac004ef7
# Command:
# cat ips.txt | xargs -n100 | sed 's/ /","/g' | sed 's/^/["/g' | sed 's/$/"]/g' > grouped.ips
# cat grouped.ips | sed 's/"/\\"/g' | xargs -P1  -n1 -I% curl -s -XPOST  -H "Content-Type: application/json" --data % ipinfo.io/batch?token=84d55fac004ef7 > grouped.results
# Parse the results using ipsTableExport.py
