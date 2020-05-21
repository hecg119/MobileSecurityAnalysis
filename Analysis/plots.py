import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
import os
from functions import *
import statistics

FORMAT = "pdf"
WIDTH_SMALL = 700
HEIGHT_SMALL = 500
WIDTH_LARGE = 800
HEIGHT_LARGE = 600


def exportPlotAllHourlyUsage(db):
    if not os.path.exists("export/Graphs/HourlyUsage/"):
        os.mkdir("export/Graphs/HourlyUsage")

    for i in range(2, 67):
        usage = getHourlyUsageForDevice(db, i)
        fig = go.Figure(
            data=[go.Bar(x=[u[0] for u in usage], y=[u[1] for u in usage])])
        fig.update_layout(title_text=f"Hourly Usage of Device {i}")
        fig.update_layout(xaxis_type="category")
        fig.write_image(f"export/Graphs/HourlyUsage/{i:02}_HourlyUsage.{FORMAT}",
                        format=FORMAT, width=WIDTH_SMALL, height=HEIGHT_SMALL)

def exportPlotScatterHourlyUsage(db):
    if not os.path.exists("export/Graphs"):
        os.mkdir("export/Graphs")
    
    fig = go.Figure()
    fig.update_layout(title_text=f"Hourly Usage")
    fig.update_layout(xaxis_type="category")

    for i in range(2, 67):
        usage = getHourlyUsageForDevice(db, i)
        fig.add_trace(go.Scatter(x=[u[0] for u in usage], y=[u[1] for u in usage], mode="lines", name=f"Device {i}"))
        
    fig.write_image(f"export/Graphs/Hourly.{FORMAT}",
            format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotNormalizedHourlyUsage(db):
    if not os.path.exists("export/Graphs"):
        os.mkdir("export/Graphs")
    
    fig = go.Figure()
    fig.update_layout(title_text=f"Hourly Usage")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(xaxis_title="Hour")
    fig.update_layout(yaxis_title="% of Max Value")

    for i in range(2, 67):
        usage = getHourlyUsageForDevice(db, i)
        maximum = max([u[1] for u in usage])
        fig.add_trace(go.Scatter(x=[u[0] for u in usage], y=[u[1]/maximum for u in usage], mode="lines", name=f"Device {i}"))
        
    fig.write_image(f"export/Graphs/HourlyNormalized.{FORMAT}",
            format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)


def exportPlotUniqueIPs(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    usage = getNumberOfUniqueIPs(db)
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in usage], y=[u[1] for u in usage])])
    #fig.update_layout(title_text="Number of IPs Unique to a Device")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_title="No. of IPs")
    fig.write_image(f"export/Graphs/UniqueIPs.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)


def exportPlotPortionUniqueIPs(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    usage = getPortionOfUniqueIPs(db)
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in usage], y=[(u[1]/u[2]) for u in usage])])
    #fig.update_layout(title_text="Percentage of IPs Unique to a Device")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(yaxis_title="Fraction of IPs unique to the device")
    fig.write_image(
        f"export/Graphs/PortionUniqueIPs.{FORMAT}", format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotPortionUniqueDNS(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    usage = getPortionOfUniqueIPs(db)
    average = statistics.mean([(u[1]/u[2]) for u in usage])
    print(average)
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in usage], y=[(u[1]/u[2]) for u in usage], name="Unique DNS requests")])
    fig.add_trace(go.Line(x=[u[0] for u in usage], y=[average for u in usage], name="Average"))
    #fig.update_layout(title_text="Fraction of DNS Requests Unique to a Device")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(yaxis_title="Fraction of domains unique to the device")
    fig.write_image(
        f"export/Graphs/PortionUniqueDNS.{FORMAT}", format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotSocialNetworks(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    rawData = []
    for i in range(2, 67):
        results = getSocialNetworksForDevice(db, i)
        uniqueNets = set([r[0].capitalize() for r in results])
        rawData += uniqueNets

    data = {}
    for x in rawData:
        data[x] = 0

    for x in rawData:
        data[x] += 1

    sortedData = sorted(data.items(), key=lambda x: x[1], reverse=True)

    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in sortedData], y=[(u[1]/65) for u in sortedData])])
    #fig.update_layout(title_text="Presence of Social Networks")
    fig.update_layout(xaxis_title="Social Network")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(yaxis_title="Fraction of devices")
    fig.write_image(f"export/Graphs/SocialNets.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)


def exportPlotHTTPxTraffic(db):
    if not os.path.exists("export/Graphs/HTTPx/"):
        os.mkdir("export/Graphs/HTTPx")

    for i in range(2, 67):
        conns = getHTTPxConnectionsForDevice(db, i)
        fig = go.Figure(
            data=[go.Pie(labels=[u[0] for u in conns], values=[u[2] for u in conns])])
        fig.update_layout(
            title_text=f"Total HTTP/S Data Received on Device {i}")
        fig.write_image(f"export/Graphs/HTTPx/{i:02}_HTTPx.{FORMAT}",
                        format=FORMAT, width=WIDTH_SMALL, height=HEIGHT_SMALL)


def exportPlotAllHTTPxTraffic(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    conns = getPortionHTTPConnections(db)
    fig = go.Figure(
        data=go.Bar(x=[u[0] for u in conns], y=[u[1] for u in conns], name="Received"))
    fig.add_trace(go.Bar(x=[u[0] for u in conns], y=[u[2]
                                                     for u in conns], name="Sent"))
    #fig.update_layout(title_text="Portion of Data on Port 80 vs. 443")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(yaxis_title="Fraction of web traffic using HTTP")
    fig.write_image(f"export/Graphs/HTTPxTraffic.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)


def exportPlotThreatsVsHTTPTraffic(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    conns = getPortionHTTPConnections(db)
    threats = getTotalThreats(db)
    combined = [(c[2], t[1]) for c, t in zip(conns, threats)]
    sortedCombined = sorted(combined)
    fig = go.Figure(data=[go.Scatter(
        x=[c[0] for c in sortedCombined],
        y=[c[1] for c in sortedCombined],
    )])
    #fig.update_layout(title_text="Number of Threats vs. Portion of HTTP Traffic")
    fig.update_layout(xaxis_title="Fraction of web traffic using HTTP")
    fig.update_layout(yaxis_title="No. of threats")
    fig.update_layout(xaxis_tickformat=".0%")
    fig.write_image(f"export/Graphs/ThreatsVsHTTP.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)                   

def exportPlotTrackersVsHTTPTraffic(db):
    data = []
    conns = getPortionHTTPConnections(db)
    for i in range(2,67): 
        results = getTrackersForDevice(db, i)
        uniqueTrackers = set([r[1] for r in results])
        data.append((conns[i-2][2], len(uniqueTrackers)))

    sortedData = sorted(data)
    
    fig = go.Figure(data=[go.Scatter(
        x=[c[0] for c in sortedData],
        y=[c[1] for c in sortedData],
    )])
    #fig.update_layout(title_text="Number of Trackers vs. Portion of HTTP Traffic")
    fig.update_layout(xaxis_title="Fraction of web traffic using HTTP")
    fig.update_layout(yaxis_title="No. of trackers")
    fig.update_layout(xaxis_tickformat=".0%")
    fig.write_image(f"export/Graphs/TrackersVsHTTP.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)   

def exportPlotThreatsVsTrackers(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    data = []
    threats = getTotalThreats(db)
    for i in range(2,67): 
        results = getTrackersForDevice(db, i)
        uniqueTrackers = set([r[1] for r in results])
        data.append((threats[i-2][1], len(uniqueTrackers)))

    fig = go.Figure(data=[go.Scatter(
        x=[c[0] for c in data],
        y=[c[1] for c in data], mode="markers"
    )])
    #fig.update_layout(title_text="Number of Threats vs. Number of Trackers")
    fig.update_layout(xaxis_title="No. of threats")
    fig.update_layout(yaxis_title="No. of trackers")
    fig.write_image(f"export/Graphs/ThreatsVsTrackers.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotThreatsVsPiHole(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    data = {}
    for i in range(0, 15):
        data[i] = []

    threats = getTotalThreats(db)
    trackers = getPortionPiHoleTrackers(db)
    for i in range(len(trackers)): 
        data[threats[i-2][1]].append(trackers[i][1])

    fig = go.Figure()
    for key in data:
        fig.add_trace(go.Box(y=data[key], name=str(key)))
    #fig.update_layout(title_text="Number of Threats vs. Number of Ads and Trackers")
    fig.update_layout(xaxis_title="No. of Threats")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(yaxis_title="Fraction domains associated with ads and trackers")
    fig.write_image(f"export/Graphs/ThreatsVsPortionPiHoleTrackers.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotPiHoleTrackersVsHTTPTraffic(db):
    data = []
    conns = getPortionHTTPConnections(db)
    trackers = getNumberPiHoleTrackers(db)
    for i in range(len(trackers)): 
        data.append((conns[i][2], trackers[i][1]))

    sortedData = sorted(data)
    
    fig = go.Figure(data=[go.Scatter(
        x=[c[0] for c in sortedData],
        y=[c[1] for c in sortedData], mode="markers"
    )])
    #fig.update_layout(title_text="Number of Trackers vs. Portion of Received HTTP Traffic")
    fig.update_layout(xaxis_title="Fraction of web traffic using HTTP")
    fig.update_layout(yaxis_title="No. of ads and trackers")
    fig.update_layout(xaxis_tickformat=".0%", xaxis_range=[0,0.4])
    fig.write_image(f"export/Graphs/TrackersVsHTTP.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotPortionPiHoleTrackersVsHTTPTraffic(db):
    data = []
    conns = getPortionHTTPConnections(db)
    trackers = getPortionPiHoleTrackers(db)
    for i in range(len(trackers)): 
        data.append((conns[i][2], trackers[i][1]))

    sortedData = sorted(data)
    
    fig = go.Figure(data=[go.Scatter(
        x=[c[0] for c in sortedData],
        y=[c[1] for c in sortedData], mode="markers"
    )])
    #fig.update_layout(title_text="Comparison of Presence of Ads and Trackers to HTTP Traffic ")
    fig.update_layout(xaxis_title="Fraction of web traffic using HTTP")
    fig.update_layout(yaxis_title="Fraction domains associated with ads and trackers")
    fig.update_layout(yaxis_tickformat=".0%")
    fig.update_layout(xaxis_tickformat=".0%", xaxis_range=[0,0.4])
    fig.write_image(f"export/Graphs/PortionTrackersVsHTTP.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)             

def exportPlotBoxThreatsVsTrackers(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    data = {}
    for i in range(0, 15):
        data[i] = []
    threats = getTotalThreats(db)
    for i in range(2,67): 
        results = getTrackersForDevice(db, i)
        uniqueTrackers = set([r[1] for r in results])
        key = threats[i-2][1]
        data[key].append(len(uniqueTrackers))


    fig = go.Figure()
    for key in data:
        fig.add_trace(go.Box(y=data[key], name=str(key)))
    #fig.update_layout(title_text="Number of Threats vs. Number of Trackers")
    fig.update_layout(xaxis_title="No. of threats")
    fig.update_layout(yaxis_title="No. of trackers")
    fig.write_image(f"export/Graphs/ThreatsVsTrackersBox.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)
      

def exportPlotUniqueDNSRequests(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    usage = getNumberOfUniqueDNSRequests(db)
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in usage], y=[u[1] for u in usage])])
    #fig.update_layout(title_text="Number of DNS Requests Unique to a Device")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_title="No. of requests")
    fig.write_image(f"export/Graphs/UniqueDNS.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotSocialNetworkPerDevice(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    usage = getNumberOfSocialNetworks(db)
    avg = statistics.mean([u[1] for u in usage])
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in usage], y=[u[1] for u in usage], name="Social Network")])
    fig.add_trace(go.Scatter(x=[u[0] for u in usage], y=[avg for u in usage], mode="lines", name="Average"))
    #fig.update_layout(title_text="Number of Social Networks Per Device")
    fig.update_layout(xaxis_title="Device ID")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_title="No. of social networks")
    fig.write_image(f"export/Graphs/SocailNetsDevice.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotThreatTypes(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    data = getThreats(db)
    types = ["LocationID", "DeviceModel", "OS", "OSVersion", "DeviceDetails", "MobileCarrier", "IPAddress", "InstaleldApps", "AppUpdate", "VOIP", "Tracking", "Profiling", "UserID", "SearchQuery", "VisitedWebsites", "China", "P2P", "BankInfo", "ExtendedUsage", "Email", "Gender", "Age", "MaritalStatus", "IMEI", "PersonName"]
    res = [0]*25
    for row in data:
        for i in range(len(types)):
            res[i] += 1 if row[types[i]] > 0 else 0

    fig = go.Figure(
        data=[go.Bar(x=types, y=res)])
    #fig.update_layout(title_text="Number of Occurrences of Each Threat Type")
    fig.update_layout(xaxis_title="Threat Type")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_title="Occurrences")
    fig.write_image(f"export/Graphs/ThreatTypes.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)

def exportPlotThreatApplications(db):
    if not os.path.exists("export/Graphs/"):
        os.mkdir("export/Graphs")

    data = getThreats(db)
    res = {}
    for row in data:
        x = row["Application"]
        if x in res:
            res[x] += 1
        else:
            res[x] = 1
    
    res.pop("Unknown")
    res.pop("N/A")
    sortedRes = sorted(res.items(), key=lambda x: x[1], reverse=True)
    fig = go.Figure(
        data=[go.Bar(x=[u[0] for u in sortedRes], y=[u[1] for u in sortedRes])])
    #fig.update_layout(title_text="Number of Threats by Source Application (Known Sources Only)")
    fig.update_layout(xaxis_title="Application")
    fig.update_layout(xaxis_type="category")
    fig.update_layout(yaxis_title="Occurrences")
    fig.write_image(f"export/Graphs/ThreatsApplications.{FORMAT}",
                    format=FORMAT, width=WIDTH_LARGE, height=HEIGHT_LARGE)