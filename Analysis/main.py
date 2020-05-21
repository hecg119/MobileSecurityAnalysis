from functions import *
import plotly.graph_objects as go
from pprint import pprint
from plots import *

TOTAL_DEVICES = 65
ANDROID_CNT = 39
IOS_CNT = 25

db = DB()

# printInterestingUserAgents(db)
# printBrandSpecificSubdomains(db)
# printLocationStrings(db)
# printTopUploadTargets(db)
#printTLDs(db)
# printSocialNetworks(db)
# printTrackers(db)

exportPlotUniqueIPs(db)
exportPlotPortionUniqueIPs(db)
exportPlotSocialNetworks(db)
exportPlotAllHTTPxTraffic(db)
exportPlotThreatsVsHTTPTraffic(db)
exportPlotTrackersVsHTTPTraffic(db)
exportPlotThreatsVsTrackers(db)
exportPlotBoxThreatsVsTrackers(db)
exportPlotUniqueDNSRequests(db)
exportPlotSocialNetworkPerDevice(db)
exportPlotScatterHourlyUsage(db)
exportPlotNormalizedHourlyUsage(db)
exportPlotThreatTypes(db)
exportPlotThreatApplications(db)
exportPlotPortionUniqueDNS(db)
exportPlotThreatsVsPiHole(db)
exportPlotPiHoleTrackersVsHTTPTraffic(db)
exportPlotPortionPiHoleTrackersVsHTTPTraffic(db)
exportPlotThreatsVsPiHole(db)