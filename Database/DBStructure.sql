CREATE DATABASE  IF NOT EXISTS `thesisdata` /*!40100 DEFAULT CHARACTER SET utf8 */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `thesisdata`;

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `connections`
--

DROP TABLE IF EXISTS `connections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `connections` (
  `DeviceID` int NOT NULL,
  `IP` varchar(45) NOT NULL,
  `Port` int NOT NULL,
  `Protocol` varchar(45) DEFAULT NULL,
  `Service` varchar(45) DEFAULT NULL,
  `TotalBytesSent` bigint DEFAULT NULL,
  `TotalBytesReceived` bigint DEFAULT NULL,
  `TotalDuration` double DEFAULT NULL,
  PRIMARY KEY (`DeviceID`,`IP`,`Port`),
  KEY `fk_Connections_DeviceInfo1_idx` (`DeviceID`),
  KEY `fk_Connections_IPs1_idx` (`IP`),
  CONSTRAINT `fk_Connections_DeviceInfo1` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`),
  CONSTRAINT `fk_Connections_IPs1` FOREIGN KEY (`IP`) REFERENCES `ips` (`IP`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dayofweek`
--

DROP TABLE IF EXISTS `dayofweek`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dayofweek` (
  `DayID` int NOT NULL,
  `Name` varchar(45) NOT NULL,
  PRIMARY KEY (`DayID`),
  UNIQUE KEY `Name_UNIQUE` (`Name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `deviceinfo`
--

DROP TABLE IF EXISTS `deviceinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `deviceinfo` (
  `DeviceID` int NOT NULL,
  `Manufacturer` varchar(45) DEFAULT NULL,
  `Model` varchar(45) DEFAULT NULL,
  `OS` varchar(20) DEFAULT NULL,
  `OSVersion` varchar(20) DEFAULT NULL,
  `Root` tinyint DEFAULT NULL,
  `PcapSize` float DEFAULT NULL,
  `Duration` float DEFAULT NULL,
  `PhonePrice` int DEFAULT NULL,
  `PhoneRelease` int DEFAULT NULL,
  `GeneralRisk` double DEFAULT NULL,
  `OwnerExposure` double DEFAULT NULL,
  PRIMARY KEY (`DeviceID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `deviceinfo_has_services`
--

DROP TABLE IF EXISTS `deviceinfo_has_services`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `deviceinfo_has_services` (
  `DeviceID` int NOT NULL,
  `ServiceID` int NOT NULL,
  PRIMARY KEY (`DeviceID`,`ServiceID`),
  KEY `fk_DeviceInfo_has_Services_Services1_idx` (`ServiceID`),
  KEY `fk_DeviceInfo_has_Services_DeviceInfo1_idx` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Services_DeviceInfo1` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Services_Services1` FOREIGN KEY (`ServiceID`) REFERENCES `services` (`ServiceID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `deviceinfo_has_threats`
--

DROP TABLE IF EXISTS `deviceinfo_has_threats`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `deviceinfo_has_threats` (
  `DeviceID` int NOT NULL,
  `ThreatID` int NOT NULL,
  PRIMARY KEY (`DeviceID`,`ThreatID`),
  KEY `fk_DeviceInfo_has_Threats_Threats1_idx` (`ThreatID`),
  KEY `fk_DeviceInfo_has_Threats_DeviceInfo1_idx` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Threats_DeviceInfo1` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Threats_Threats1` FOREIGN KEY (`ThreatID`) REFERENCES `threats` (`ThreatID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dnsqueries`
--

DROP TABLE IF EXISTS `dnsqueries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dnsqueries` (
  `DeviceID` int NOT NULL,
  `SubdomainName` varchar(150) NOT NULL,
  PRIMARY KEY (`DeviceID`,`SubdomainName`),
  KEY `fk_DeviceInfo_has_Subdomains_Subdomains1_idx` (`SubdomainName`),
  KEY `fk_DeviceInfo_has_Subdomains_DeviceInfo1_idx` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Subdomains_DeviceInfo1` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`),
  CONSTRAINT `fk_DeviceInfo_has_Subdomains_Subdomains1` FOREIGN KEY (`SubdomainName`) REFERENCES `subdomains` (`SubdomainName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `httpcomms`
--

DROP TABLE IF EXISTS `httpcomms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `httpcomms` (
  `CommId` int NOT NULL AUTO_INCREMENT,
  `DeviceID` int NOT NULL,
  `IP` varchar(45) NOT NULL,
  `Port` int NOT NULL,
  `Method` varchar(45) DEFAULT NULL,
  `Version` varchar(45) DEFAULT NULL,
  `Host` varchar(100) DEFAULT NULL,
  `URI` text,
  `Referrer` text,
  `UserAgent` text,
  `StatusCode` int DEFAULT NULL,
  `ResponseMIME` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`CommId`),
  KEY `fk_HTTPComms_Connections1_idx` (`DeviceID`,`IP`,`Port`),
  CONSTRAINT `fk_HTTPComms_Connections1` FOREIGN KEY (`DeviceID`, `IP`, `Port`) REFERENCES `connections` (`DeviceID`, `IP`, `Port`)
) ENGINE=InnoDB AUTO_INCREMENT=59087 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ips`
--

DROP TABLE IF EXISTS `ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ips` (
  `IP` varchar(45) NOT NULL,
  `Hostname` text,
  `Organization` text,
  `Country` varchar(45) DEFAULT NULL,
  `Region` varchar(45) DEFAULT NULL,
  `City` varchar(100) DEFAULT NULL,
  `Location` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`IP`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ips_has_subdomains`
--

DROP TABLE IF EXISTS `ips_has_subdomains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ips_has_subdomains` (
  `IP` varchar(45) NOT NULL,
  `SubdomainName` varchar(150) NOT NULL,
  PRIMARY KEY (`IP`,`SubdomainName`),
  KEY `fk_IPs_has_Subdomains_Subdomains1_idx` (`SubdomainName`),
  KEY `fk_IPs_has_Subdomains_IPs1_idx` (`IP`),
  CONSTRAINT `fk_IPs_has_Subdomains_IPs1` FOREIGN KEY (`IP`) REFERENCES `ips` (`IP`),
  CONSTRAINT `fk_IPs_has_Subdomains_Subdomains1` FOREIGN KEY (`SubdomainName`) REFERENCES `subdomains` (`SubdomainName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `locationdesc`
--

DROP TABLE IF EXISTS `locationdesc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `locationdesc` (
  `LocationID` int NOT NULL,
  `Name` varchar(45) NOT NULL,
  PRIMARY KEY (`LocationID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `overview`
--

DROP TABLE IF EXISTS `overview`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `overview` (
  `DeviceID` int NOT NULL,
  `Date` date DEFAULT NULL,
  `Identity` varchar(100) DEFAULT NULL,
  `Link` varchar(150) DEFAULT NULL,
  PRIMARY KEY (`DeviceID`),
  UNIQUE KEY `DeviceID_UNIQUE` (`DeviceID`),
  CONSTRAINT `fk_Overview_DeviceInfo` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `piholetrackers`
--

DROP TABLE IF EXISTS `piholetrackers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `piholetrackers` (
  `Name` varchar(300) NOT NULL,
  PRIMARY KEY (`Name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `samples`
--

DROP TABLE IF EXISTS `samples`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `samples` (
  `IP` varchar(45) NOT NULL,
  `Type` enum('P_COMM','P_DOWN','P_REFF','N_COMM','N_DOWN','N_REFF') NOT NULL,
  `Positives` int DEFAULT NULL,
  `Total` int DEFAULT NULL,
  `Count` int DEFAULT NULL,
  PRIMARY KEY (`IP`,`Type`),
  CONSTRAINT `fk_CommunicatingSamples_IPs1` FOREIGN KEY (`IP`) REFERENCES `ips` (`IP`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `services`
--

DROP TABLE IF EXISTS `services`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `services` (
  `ServiceID` int NOT NULL,
  `Name` varchar(45) DEFAULT NULL,
  `Category` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`ServiceID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `severitydesc`
--

DROP TABLE IF EXISTS `severitydesc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `severitydesc` (
  `SeverityLevel` int NOT NULL,
  `Name` varchar(45) NOT NULL,
  PRIMARY KEY (`SeverityLevel`),
  UNIQUE KEY `Name_UNIQUE` (`Name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `subdomains`
--

DROP TABLE IF EXISTS `subdomains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `subdomains` (
  `SubdomainName` varchar(150) NOT NULL,
  `DomainName` varchar(150) NOT NULL,
  `TrackerID` int DEFAULT NULL,
  `VTPositives` int DEFAULT NULL,
  `VTLink` varchar(150) DEFAULT NULL,
  `PiholePositive` int DEFAULT '0',
  PRIMARY KEY (`SubdomainName`),
  KEY `fk_Subdomains_Trackers1_idx` (`TrackerID`),
  CONSTRAINT `fk_Subdomains_Trackers1` FOREIGN KEY (`TrackerID`) REFERENCES `trackers` (`TrackerID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `threats`
--

DROP TABLE IF EXISTS `threats`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `threats` (
  `ThreatID` int NOT NULL,
  `WorkName` varchar(45) NOT NULL,
  `SeverityLevel` int NOT NULL,
  `Name` text,
  `Description` text,
  `Application` varchar(100) DEFAULT NULL,
  `TargetOwner` varchar(100) DEFAULT NULL,
  `LocationID` int DEFAULT NULL,
  `DeviceModel` int DEFAULT NULL,
  `OS` int DEFAULT NULL,
  `OSVersion` int DEFAULT NULL,
  `DeviceDetails` int DEFAULT NULL,
  `MobileCarrier` int DEFAULT NULL,
  `IPAddress` int DEFAULT NULL,
  `InstaleldApps` int DEFAULT NULL,
  `AppUpdate` int DEFAULT NULL,
  `VOIP` int DEFAULT NULL,
  `Tracking` int DEFAULT NULL,
  `Profiling` int DEFAULT NULL,
  `UserID` int DEFAULT NULL,
  `SearchQuery` int DEFAULT NULL,
  `VisitedWebsites` int DEFAULT NULL,
  `China` int DEFAULT NULL,
  `P2P` int DEFAULT NULL,
  `BankInfo` int DEFAULT NULL,
  `ExtendedUsage` int DEFAULT NULL,
  `Email` int DEFAULT NULL,
  `Gender` int DEFAULT NULL,
  `Age` int DEFAULT NULL,
  `MaritalStatus` int DEFAULT NULL,
  `IMEI` int DEFAULT NULL,
  `PersonName` int DEFAULT NULL,
  PRIMARY KEY (`ThreatID`),
  KEY `fk_Threats_LocationDesc1_idx` (`LocationID`),
  KEY `fk_Threats_SeverityDesc1_idx` (`SeverityLevel`),
  CONSTRAINT `fk_Threats_LocationDesc1` FOREIGN KEY (`LocationID`) REFERENCES `locationdesc` (`LocationID`),
  CONSTRAINT `fk_Threats_SeverityDesc1` FOREIGN KEY (`SeverityLevel`) REFERENCES `severitydesc` (`SeverityLevel`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trackers`
--

DROP TABLE IF EXISTS `trackers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trackers` (
  `TrackerID` int NOT NULL,
  `Name` varchar(45) DEFAULT NULL,
  `Signature` text,
  `Website` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`TrackerID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `usagetimes`
--

DROP TABLE IF EXISTS `usagetimes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usagetimes` (
  `DeviceID` int NOT NULL,
  `DayID` int NOT NULL,
  `Hour` int NOT NULL,
  `Duration` double DEFAULT '0',
  `Count` int DEFAULT '0',
  PRIMARY KEY (`DeviceID`,`DayID`,`Hour`),
  KEY `fk_ConnectionTime_DayOfWeek1_idx` (`DayID`),
  CONSTRAINT `fk_ConnectionTime_DayOfWeek1` FOREIGN KEY (`DayID`) REFERENCES `dayofweek` (`DayID`),
  CONSTRAINT `fk_ConnectionTime_DeviceInfo1` FOREIGN KEY (`DeviceID`) REFERENCES `deviceinfo` (`DeviceID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
