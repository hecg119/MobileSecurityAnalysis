import csv
import json

IPINFO_JSON = "ipsRaw.json"
ALL_IPS = "cache/ipsToBeProcessed.csv"
OUTPUT_FOLDER = "out"



def checkForMissingIps(lookup):
    missing = []
    with open(ALL_IPS, "r", encoding="utf-8", newline='') as allIpsFile:
        allIps = allIpsFile.read().splitlines()
        db =  set([*lookup])
        for ip in allIps:
            if ip not in db:
                missing.append({"IP": ip, "Hostname": None, "Organization": None, "Country": None, "Region": None, "City": None, "Location": None})
    print(f"{len(missing)} IPs are missing")
    return missing

with open(IPINFO_JSON, "r", encoding="utf-8", newline='') as inFile:
    tmpOut = {}
    lookup = json.load(inFile)
    # checkForMissingIps(lookup)
    with open(f"{OUTPUT_FOLDER}/ips.csv", "w", encoding="utf-8", newline='') as outFile:
        fieldnames = ["IP", "Hostname", "Organization", "Country", "Region", "City", "Location"]
        writer = csv.DictWriter(
            outFile, dialect='excel', fieldnames=fieldnames)
        writer.writeheader()
        for entryId in lookup:
            entry = lookup[entryId]
            # print(entry["ip"])
            row = {"IP": entry["ip"], "Hostname": entry.get("hostname", None), "Organization":  entry.get("org", None), "Country":  entry.get("country", None), "Region":  entry.get("region", None), "City":  entry.get("city", None), "Location": entry.get("loc", None)}
            tmpOut[entry["ip"]] = row
        for row in tmpOut.values():
            writer.writerow(row)
        
    
        
