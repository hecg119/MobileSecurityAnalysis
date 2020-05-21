def queryUniqueUserAgentsForDevice(db, deviceId):
    return db.fetch(
        f"""
        SELECT DISTINCT
            UserAgent
        FROM
            thesisdata.httpcomms
        WHERE
            deviceID = {deviceId} AND UserAgent IS NOT NULL;
        """
        )

def queryUniqueURLsForDevice(db, deviceId):
    return db.fetch(
        f"""
        SELECT DISTINCT
            Host, URI
        FROM
            thesisdata.httpcomms
        WHERE
            deviceID = {deviceId} 
            AND Host IS NOT NULL 
            AND URI IS NOT NULL;
        """
        )

def queryAndroidSpecificSubdomains(db):
    return db.fetch(
        """
        SELECT DISTINCT
            android.SubdomainName AS AndroidSubdomain
        FROM
            (SELECT DISTINCT
                SubdomainName
            FROM
                thesisdata.dnsqueries
            LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
            WHERE
                OS = 'Android') AS android
        LEFT JOIN
            (SELECT DISTINCT
                SubdomainName
            FROM
                thesisdata.dnsqueries
            LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
            WHERE
                OS = 'iOS') AS ios ON android.SubdomainName = ios.SubdomainName
        WHERE
            ios.SubdomainName IS NULL;
        """
    )

def queryAndroidSpecificSubdomainsWithCount(db, minimum=0):
    return db.fetch(
        f"""
            SELECT 
                result.SubdomainName AS AndroidSubdomain,
                COUNT(*) AS Occurences
            FROM
                (SELECT 
                    android.SubdomainName
                FROM
                    (SELECT 
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'Android') AS android
                LEFT JOIN (SELECT DISTINCT
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'iOS') AS ios ON android.SubdomainName = ios.SubdomainName
                WHERE
                    ios.SubdomainName IS NULL) AS result
            GROUP BY result.SubdomainName
            HAVING Occurences >= {minimum}
            ORDER BY Occurences DESC
        """
    )

def queryIosSpecificSubdomainsWithCount(db, minimum=0):
    return db.fetch(
        f"""
            SELECT 
                result.SubdomainName AS IosSubdomain,
                COUNT(*) AS Occurences
            FROM
                (SELECT 
                    ios.SubdomainName
                FROM
                    (SELECT 
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'iOS') AS ios
                LEFT JOIN (SELECT DISTINCT
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'Android') AS android ON android.SubdomainName = ios.SubdomainName
                WHERE
                    android.SubdomainName IS NULL) AS result
            GROUP BY result.SubdomainName
            HAVING Occurences >= {minimum}
            ORDER BY Occurences DESC
        """
    )

def queryCommonSubdomainsWithCount(db, minimum=0):
    return db.fetch(
        f"""
            SELECT 
                result.SubdomainName AS CommonSubdomain,
                COUNT(*) AS Occurences
            FROM
                (SELECT 
                    ios.SubdomainName
                FROM
                    (SELECT 
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'iOS') AS ios
                LEFT JOIN (SELECT DISTINCT
                    dnsqueries.SubdomainName
                    FROM
                        thesisdata.dnsqueries
                    LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                    WHERE
                        OS = 'Android') AS android ON android.SubdomainName = ios.SubdomainName
                WHERE
                    android.SubdomainName IS NOT NULL) AS result
            GROUP BY result.SubdomainName
            HAVING Occurences >= {minimum}
            ORDER BY Occurences DESC
        """
    )

def queryAndroidManufacturersWithCount(db):
    return db.fetch(
        """
        SELECT 
            Manufacturer, COUNT(*) AS Occurences
        FROM
            (SELECT 
                Manufacturer
            FROM
                thesisdata.deviceinfo
            WHERE
                OS = 'Android') AS brands
        GROUP BY Manufacturer
        ORDER BY Occurences DESC;
        """
    )

def queryManufacturerSpecificSubdomains(db, manufacturer, minimum=0):
    return db.fetch(
        f"""
        SELECT 
            result.SubdomainName AS CommonSubdomain,
            COUNT(*) AS Occurences
        FROM
            (SELECT 
                target.SubdomainName
            FROM
                (SELECT 
                dnsqueries.SubdomainName
                FROM
                    thesisdata.dnsqueries
                LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                WHERE
                    Manufacturer = '{manufacturer}') AS target
            LEFT JOIN (SELECT DISTINCT
                dnsqueries.SubdomainName
                FROM
                    thesisdata.dnsqueries
                LEFT JOIN deviceinfo ON dnsqueries.DeviceID = deviceinfo.DeviceID
                WHERE
                    Manufacturer <> '{manufacturer}') AS complement ON target.SubdomainName = complement.SubdomainName
            WHERE
                complement.SubdomainName IS NULL) AS result
        GROUP BY result.SubdomainName
        HAVING Occurences >= {minimum}
        ORDER BY Occurences DESC
        """
    )

def queryTopUploadTargets(db, deviceId, limit=20):
    return db.fetch(
        f"""
        SELECT 
            conn.ip,
            dns.subdomainname,
            TotalBytesSent,
            TotalBytesReceived,
            ROUND(TotalDuration)
        FROM
            connections AS conn
                LEFT JOIN
                    (SELECT 
                        ips_has_subdomains.*
                    FROM
                        dnsqueries
                    LEFT JOIN ips_has_subdomains ON dnsqueries.SubdomainName = ips_has_subdomains.SubdomainName
                    WHERE
                        dnsqueries.DeviceID = {deviceId}) AS dns ON dns.IP = conn.IP
        GROUP BY deviceID , ip
        HAVING deviceid = {deviceId}
        ORDER BY TotalBytesSent DESC
        LIMIT {limit};
        """
    )

def queryInterestingDomains(db, deviceId):
    return db.fetch(
        f"""
        SELECT DISTINCT
            SubdomainName
        FROM
            dnsqueries
        WHERE
            deviceid = {deviceId}
        """
    )

                # AND SubdomainName NOT LIKE '%com'
                # AND SubdomainName NOT LIKE '%org'
                # AND SubdomainName NOT LIKE '%net'
                # AND SubdomainName NOT LIKE '%io'
                # AND SubdomainName NOT LIKE '%ly'
                # AND SubdomainName NOT LIKE '%tv'
                # AND SubdomainName NOT LIKE '%gl';

def queryDNSQueries(db, deviceId, countOnly):
    select = "COUNT(*)" if countOnly else "SubdomainName"
    return db.fetch(
        f"""
        SELECT 
            {select}
        FROM
            dnsqueries
        WHERE
            DeviceID = {deviceId};
        """
    )

def queryDeviceTrackers(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            dnsqueries.SubdomainName, Name
        FROM
            dnsqueries
                LEFT JOIN
            subdomains ON dnsqueries.subdomainname = subdomains.SubdomainName
                LEFT JOIN
            trackers ON subdomains.TrackerID = trackers.trackerid
        WHERE
            deviceID = {deviceId} AND subdomains.TrackerID IS NOT NULL;
        """
    )


def queryDevicePiHoleTrackers(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            COUNT(*)
        FROM
            dnsqueries
                LEFT JOIN
            subdomains ON dnsqueries.subdomainname = subdomains.SubdomainName
        WHERE
            deviceID = {deviceId} AND subdomains.piholepositive = 1;
        """
    )

def queryNonStandardServers(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            Location, Organization, Country, Region, City, servers.IP
        FROM
            connections
                INNER JOIN
                    (SELECT 
                        *
                    FROM
                        ips
                    WHERE
                        Organization NOT LIKE '%Cloudflare%'
                            AND Organization NOT LIKE '%Google%'
                            AND Organization NOT LIKE '%Akamai%'
                            AND Organization NOT LIKE '%Facebook%'
                            AND Organization NOT LIKE '%Amazon%'
                            AND Organization NOT LIKE '%Uber%'
                            AND Organization NOT LIKE '%Twitter%'
                            AND Organization NOT LIKE '%Microsoft%'
                            AND Location IS NOT NULL
                            AND Location <> '0.0000,0.0000') AS servers ON servers.ip = connections.ip
        WHERE
            DeviceID = {deviceId}
        """
    )

def queryHourlyUsage(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            Hour, ROUND(SUM(Duration)), SUM(Count)
        FROM
            usagetimes
        GROUP BY DeviceID, Hour
        HAVING DeviceID = {deviceId};
        """
    )

def queryUniqueIPsForDevice(db, deviceId, countOnly=True):
    select = "COUNT(*)" if countOnly else "IP"
    return db.fetch(
        f"""
        SELECT 
            {select}
        FROM
            connections
                LEFT JOIN
                    (SELECT DISTINCT
                        IP
                    FROM
                        connections
                    WHERE
                        DeviceID <> {deviceId}) AS common ON connections.IP = common.IP
        WHERE
            DeviceID = {deviceId}
            AND common.IP IS NULL;
        """
    )

def queryIPsForDevice(db, deviceId, countOnly=True):
    select = "COUNT(*)" if countOnly else "*"
    return db.fetch(
        f"""
        SELECT 
            {select}
        FROM
            connections
        WHERE
            DeviceID = {deviceId};
        """
    )

def queryConnectionsByPortsForDevice(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            Port, SUM(TotalBytesSent), SUM(TotalBytesReceived), SUM(TotalDuration)
        FROM
            connections
        GROUP BY DeviceID , Port
        HAVING DeviceID =  {deviceId};
        """
    )

def queryHTTPxConnectionsForDevice(db, deviceId):
    return db.fetch(
        f"""
        SELECT 
            Port, SUM(TotalBytesSent), SUM(TotalBytesReceived), SUM(TotalDuration)
        FROM
            connections
        GROUP BY DeviceID , Port
        HAVING DeviceID =  {deviceId}
            AND Port in (80, 443)
        ORDER BY Port;
        """
    )

def queryTotalThreats(db):
    return db.fetch(
        f"""
        SELECT 
            deviceinfo.DeviceID, coalesce(cnt, 0), Manufacturer, OS, PhonePrice
        FROM
            deviceinfo
                LEFT JOIN
            (SELECT 
                DeviceID, COUNT(*) AS cnt
            FROM
                deviceinfo_has_threats
            GROUP BY DeviceID) AS th ON deviceinfo.DeviceID = th.DeviceID
        """
    )

def queryUniqueDNSRequestsForDevice(db, deviceId, countOnly=True):
    select = "COUNT(*)" if countOnly else "IP"
    return db.fetch(
        f"""
            SELECT 
                {select}
            FROM
                dnsqueries
                    LEFT JOIN
                (SELECT DISTINCT
                    subdomainname
                FROM
                    dnsqueries
                WHERE
                    DeviceID <> {deviceId}) AS common ON dnsqueries.subdomainname = common.subdomainname
            WHERE
                DeviceID = {deviceId}
                    AND common.subdomainname IS NULL;
        """
    )

def queryThreats(db):
    return db.fetch(
        f"""
            SELECT 
                *
            FROM
                deviceinfo_has_threats
                    LEFT JOIN
                threats ON deviceinfo_has_threats.ThreatID = threats.ThreatID;
        """
    )