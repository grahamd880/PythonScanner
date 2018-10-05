import argparse
from scapy.all import *
from pprint import pprint
import re
import sys

def icmp_ping(hosts):
    aliveHosts = list()
    ans, unans = sr(IP(dst=hosts)/ICMP(),timeout=2)
    for answer in ans:
        aliveHosts.append(answer[1].src)
    return aliveHosts
    
def traceroute(host):
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
    
    for ip in destinations:
        print("\nTraceroute to {}:".format(ip))
        print("Hop  IP")
        hops = 1
        for ips in traceDict[ip]:
            print("{}  {}".format(hops,ips))
            hops += 1
    #for key, value in traceDict.values():
    #    print("\nTraceroute to {}:".format(key))
    #    print("Hop  IP")
    #    hops = 1
    #    for ip in value:
    #        print("{}  {}".format(hops,ip))
    #print(send.ttl,receive.src)

def tcp_scan(hosts,ports):
    openPorts = list()
    p = IP(dst=hosts)/TCP(dport=ports,flags='S')
    ans, unans = sr(p,timeout=2)
    #sr1(IP(dst=hosts)/TCP(dport=ports, flags='R'),timeout=2) #***********JUST to make sure that all port sessions are closed****************
    
    for answer in ans:
        if(answer[1][1].flags == 'SA'):
            openPorts.append(answer[1][1].sport)
    if(len(openPorts) != 0):
        sr1(IP(dst=hosts)/TCP(dport=openPorts, flags='R'),timeout=2)
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

def giveResults(hosts,tcpDict):
    for host in hosts:
        print("\n\n{}:".format(host))
        ports = tcpDict[host]
        if(len(ports) != 0):
            for port in ports:
                print("[*] {} TCP Open".format(port))
        else:
            print("No open ports found")


ports = range(1,1081)
parser = argparse.ArgumentParser()
parser.add_argument("host",help="The host ip/range to scan")
parser.add_argument("-p","--PORT",dest='port',help="The port(s) to scan")
parser.add_argument("-ps","--PINGSWEEP",dest='ps',action='store_true',help="This flag will only perform a ping sweep and return the results")
parser.add_argument("-t", "--TCP",dest='t',action='store_true',help="This will perform a TCP scan")
parser.add_argument("-u","--UDP",dest='u',action='store_true',help="This will perform a UDP scan")
parser.add_argument("-b","--BOTH",dest='b',action='store_true',help="This will perform both a TCP and UDP scan")
parser.add_argument("-T","--TRACEROUTE",dest='T',action='store_true',help="This will only perform a traceroute on a given host")

args = parser.parse_args()


hosts = checkHostInput(args.host)

if(args.ps):
    aliveHosts = icmp_ping(hosts)
    print("\n\n*****PingSweep results:*****")
    for host in aliveHosts:
        print("[*] {} is alive".format(host))
elif(args.T):
    traceroute(hosts)
elif(args.b):
    print("doSomething")
elif(args.t and args.u):
    print("dosame as both")
elif(args.t):
    print("do tcp scan")
elif(args.u):
    print("do udp scan")
else:
    if(args.port is None):
        print("No port entered......using default")
    else:
        ports = checkPortInput(args.port)

    print("\nStarting scan:\n")
    print("Host(s): {}\nPort(s): {}\n\n".format(hosts,ports))

    aliveHosts = icmp_ping(hosts)
    tcpDictionary = dict()
    udpDictionary = dict()
    for host in aliveHosts:
        print("\n\n[*] {} is alive. Starting scan:\n".format(host))
        tcpDictionary[host]=tcp_scan(host,ports)

    giveResults(aliveHosts,tcpDictionary)