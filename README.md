# MobileSecurityAnalysis
Code developed for thesis "The first comprehensive report on the state of the security of mobile phones of civil society." written by Jakub Cech

Uses Python 3 and MySQL

## MySQL Database
The folder [Database](Database) contains data related to the MySQL database structure.

* [Database/DBModel.mwb](Database/DBModel.mwb) - MySQL Workbench model
* [Database/DBModel.mwb](Database/DBModel.mwb) - SQL script which creates database schema used in this thesis


## Zeek Processing
These scripts process bro logs and extract the data into CSV files. 

It is possible to select what data will be exported by enabling the following switches:
* EXPORT_DNS = True/False
* EXPORT_VIRUSTOTAL_URLS = True/False
* EXPORT_VIRUSTOTAL_IPS = True/False
* EXPORT_CONNECTIONS = True/False
* EXPORT_HTTP = True/False
* EXPORT_USAGE = True/False

To execute the script, run [ZeekProcessing/main.py](ZeekProcessing/main.py).

## Analysis
These scripts query the MySQL database to create graphs or other data representation.

It is possible to select what data will be exported by uncommenting lines in [Analysis/main.py](Analysis/main.py).

To execute the script, run [Analysis/main.py](Analysis/main.py).

## Results
This folder contains list of domains specific to Android, iOS, and particular Android device brands.


* [Results/OSSpecificDomains.xlsx](Results/OSSpecificDomains.xlsx) - domains specific to Android and iOS
* [Results/BrandSpecificDomains.md](Results/BrandSpecificDomains.md) - domains specific to Android brands

