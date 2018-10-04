import argparse
from scapy.all import *
from pprint import pprint

def icmp_ping(hosts):
    aliveHosts = list()
    ans, unans = sr(IP(dst=hosts)/ICMP(),timeout=2)
    for answer in ans:
        aliveHosts.append(answer[1].src)
    return aliveHosts
    

def tcp_scan(hosts,ports):
    openPorts = list()
    p = IP(dst=hosts)/TCP(dport=ports,flags='S')
    ans, unans = sr(p,timeout=2)
    sr1(IP(dst=hosts)/TCP(dport=ports, flags='R'),timeout=2) #***********JUST to make sure that all port sessions are closed****************
    
    for answer in ans:
        if(answer[1][1].flags == 'SA'):
            openPorts.append(answer[1][1].sport)
    return openPorts

#fixthis
def giveResults(tcpDict):
    for key, value in tcpDict.items():
        print("\n\n{}:".format(key))
        for port in value:
            print("{} TCP Open".format(port))


ports = range(1,1081)
parser = argparse.ArgumentParser()
parser.add_argument("host",help="The host ip/range to scan")
parser.add_argument("-p","--PORT",type=int,dest='port',help="The port(s) to scan")
args = parser.parse_args()
print("\nStarting scan:\n")
print("Host: {}\nPort: {}\n\n".format(args.host,args.port))

aliveHosts = icmp_ping(args.host)
tcpDictionary = dict()
udpDictionary = dict()
for host in aliveHosts:
    print("\n\n[*] {} is alive. Starting scan:\n".format(host))
    tcpDictionary[host]=tcp_scan(host,ports)

giveResults(tcpDictionary)