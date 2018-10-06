import argparse
from scapy.all import *
from pprint import pprint
import re
import sys
import webbrowser
from tkinter import *
from gui import *

def icmp_ping(hosts):
    aliveHosts = list()
    ans, unans = sr(IP(dst=hosts)/ICMP(),timeout=2)
    for answer in ans:
        aliveHosts.append(answer[1].src)
    return aliveHosts
    
def traceroute(host):
    if(len(icmp_ping(host)) != 0): 
        destinations = set()
        traceDict = dict()
        ans,unans = sr(IP(dst=host,ttl=(1,30),id=RandShort())/TCP(flags=0x2),timeout=10)
        for send,receive in ans:
            destinations.add(send.dst)
        for ip in destinations:
            traceDict[ip] = list()

        for send,receive in ans:
            if(receive.src not in traceDict[send.dst]):
                traceDict[send.dst].append(receive.src)

        return traceDict
    else:
        return -1

def tcp_scan(hosts,ports):
    openPorts = list()
    p = IP(dst=hosts)/TCP(dport=ports,flags='S')
    ans, unans = sr(p,timeout=10)
    #sr1(IP(dst=hosts)/TCP(dport=ports, flags='R'),timeout=2) #***********JUST to make sure that all port sessions are closed****************
    
    for answer in ans:
        if(answer[1][1].flags == 'SA'):
            openPorts.append(answer[1][1].sport)

    if(len(openPorts) != 0):
        sr(IP(dst=hosts)/TCP(dport=openPorts, flags='R'),timeout=2)
    return openPorts

def checkHostInput(hosts):
    ipRegex = '(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))'
    temp1 = re.split('-',hosts)
    temp2 = re.split('/',hosts)
    temp3 = re.split(',',hosts)
    
    try:
        if(len(temp1) > 1):
            if not(re.match(ipRegex,temp1[0])):
                print("invalid IP format for host {}....stopping scan".format(temp2[0]))
                sys.exit()
            if(int(temp1[0].split('.')[3]) > int(temp1[1]) ):
                print("invalid range format....stopping scan")
                sys.exit()
            if(int(temp1[1]) > 256):
                print
                print("range is too high.....stopping scan")
                sys.exit()
            return hosts
        elif(len(temp2) > 1 and len(temp2) < 3):
            if not(re.match(ipRegex,temp2[0])):
                print("invalid IP format for host {}....stopping scan".format(temp2[0]))
                sys.exit()
            else:
                if not(int(temp2[1]) > 0 and int(temp2[1]) < 32):
                    print("invalid CIDR notation...stopping scan")
                    sys.exit()
                    
            return hosts
        elif(len(temp3) > 1):
            hostList = list()
            for host in temp3:
                if not(re.match(ipRegex,host)):
                    print("invalid range format....stopping scan")
                    sys.exit()
                else:
                    hostList.append(host)
            return hostList        
        else:
            if(re.match(ipRegex,hosts)):
                return hosts
            else:
                print("invalid IP format.....stopping scan")
                sys.exit()
    except ValueError:
        print("invalid host format....stopping scan")
        sys.exit()
        
def checkPortInput(ports):
    try:
        if(re.search('-',ports) is not None):
            portRange = re.split('-',ports,1)
            if(portRange[1] <= portRange[0]):
                print("Invalid range given...Stopping scan")
                sys.exit()
            else:
                return range(int(portRange[0]),int(portRange[1]))
            
        elif(re.search(',',ports) is not None):
            stringPorts= re.split(',',ports,1)
            intPorts = list()
            for port in stringPorts:
                intPorts.append(int(port))
            return intPorts
        else:
            return int(ports)
    except ValueError:
        print("Only integer port numbers allowed....Stopping scan")
        sys.exit()

def toStringPing(hosts):
    pingStr = "\n\n*****PingSweep results:*****\n"
    if(len(hosts) != 0):
        for host in hosts:
            pingStr += "[*] {} is alive\n".format(host)
    else:
        pingStr += "All hosts seem to be down\n\n"
    return pingStr

def toStringTrace(hosts,traceDict):
    traceStr = "\n\n*****Traceroute results:******\n"
    for host in hosts:
        traceStr += "\nTraceroute to {}:\n".format(host)
        traceStr += "Hop IP\n"
        hops = 1
        ips = traceDict[host]
        for ip in ips:
            traceStr += "{} {}\n".format(hops,ip)
            hops += 1
    return traceStr

def toStringScan(hosts,tcpDict):
    scanStr = "\n\n*****Port scan result:*****"
    for host in hosts:
        scanStr += "\n\n{}:\n".format(host)
        ports = tcpDict[host]
        if(len(ports) != 0):
            for port in ports:
                scanStr += "[*] {} TCP Open\n".format(port)
        else:
            scanStr += "No open ports found\n\n"
    return scanStr


def toHTML(resultString,pingString,traceString,scanString):
    resultStr = re.sub('\n\t','',resultString)
    htmlFile = open('results.html','w')

    htmlContents = """
    <html>
    <head></head>
    <body>
    <h1 style=\"text-align:center\">{}</h1>""".format(resultStr)
    if(pingString is not None):
        temp = pingString.split('\n')
        for string in temp:
            htmlContents += "<p\"text-align:center\">{}</p>".format(string)
    if(traceString is not None):
        temp = traceString.split('\n')
        for string in temp:
            htmlContents += "<p\"text-align:center\">{}</p>".format(string)
    if(scanString is not None):
        temp = scanString.split('\n')
        for string in temp:
            htmlContents += "<p\"text-align:center\">{}</p>".format(string)
    htmlContents += """
    </body>
    </html>"""

    htmlFile.write(htmlContents)
    htmlFile.close()

    filename = "results.html"
    webbrowser.open_new_tab(filename)
    
def giveResults(pingFlag,traceFlag,allFlag,traceDict,hosts,tcpDict,html):
    printString = "\n\tResults:"
    resultString = "\n\tResults:"
    pingString = None
    traceString = None
    scanString = None
    if(pingFlag):
        pingString = toStringPing(hosts)
        printString += pingString
    elif(traceFlag):
        if(traceDict != -1):
            traceString = toStringTrace(hosts,traceDict)
            printString += traceString
        else:
            traceString = "\n\n*****Traceroute Results:*****\nInvalid hosts...Traceroute was not performed\n"   
            printString += traceString
    elif(allFlag):
        pingString = toStringPing(hosts)
        traceString = toStringTrace(hosts,traceDict)
        scanString = toStringScan(hosts,tcpDict)
        printString += pingString + traceString + scanString
    else:
        scanString= toStringScan(hosts,tcpDict)
        printString += scanString
    
    if(html):
        toHTML(resultString,pingString,traceString,scanString)
    else:
        print(printString)
        


ports = range(1,1081)
parser = argparse.ArgumentParser()
parser.add_argument("-H","--HOST",type=str,dest='host',help="The host ip/range to scan")
parser.add_argument("-p","--PORT", dest='port',help="The port(s) to scan")
parser.add_argument("-ps","--PINGSWEEP",dest='ps',action='store_true',help="This flag will only perform a ping sweep and return the results")
parser.add_argument("-T","--TRACEROUTE",dest='T',action='store_true',help="This will only perform a traceroute on a given host")
parser.add_argument("-a","--ALL",dest='a',action='store_true',help="This will perform a pingsweep,traceroute, and port scan to the given host(s) and port(s)")
parser.add_argument("-wh","--HTML",dest='wh',action='store_true',help="Creates an HTML page with the results")
args = parser.parse_args()

pingResult = None
traceResult = None
scanResult = None

if(args.host is not None):
    hosts = checkHostInput(args.host)
    print(hosts)
    if(args.port is None):
        print("No port entered......using default")
    else:
        ports = checkPortInput(args.port)

    if(args.a):
        pingResult = icmp_ping(hosts)
        traceResult = traceroute(pingResult)
        tcpDictionary = dict()
        for host in pingResult:
            tcpDictionary[host]=tcp_scan(host,ports)
        scanResult = tcpDictionary
    elif(args.T):
        pingResult = icmp_ping(hosts)
        traceResult = traceroute(pingResult)
    elif(args.ps):
        pingResult = icmp_ping(hosts)
    else:
        print("\nStarting scan:\n")
        print("Host(s): {}\nPort(s): {}\n\n".format(hosts,ports))

        pingResult = icmp_ping(hosts)
        tcpDictionary = dict()
        for host in pingResult:
            print("\n\n[*] {} is alive. Starting scan:\n".format(host))
            tcpDictionary[host]=tcp_scan(host,ports)
        scanResult = tcpDictionary
    giveResults(args.ps,args.T,args.a,traceResult,pingResult,scanResult,args.wh)
else:
    startGUI()
