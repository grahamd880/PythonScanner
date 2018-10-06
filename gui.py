from tkinter import *
from scapy.all import *

def startScan(flags, hostInput, portInput, result):
    flag = flags.get()
    if(flag == 1):
        pingList,resultStr = pingHandler(hostInput)
        result.delete('1.0',END)
        result.insert(CURRENT,resultStr)
    if(flag == 2):
        traceHandler(hostInput)
    if(flag == 3):
        scanHandler(hostInput,portInput)
    if(flag == 4):
        allHandler(hostInput,portInput)


def pingHandler(hostInput):
    validHosts = list()
    result = "*****Starting Ping Sweep*****\n"
    hosts = hostInput.get()
    if(hosts != ""):
        print("start ping")
        ans, unans = sr(IP(dst=hosts)/ICMP(),timeout=2)
        for answer in ans:
            validHosts.append(answer[1].src)

    for host in validHosts:
        result += "[*] {} is alive\n".format(host)
    if(len(validHosts)==0):
        result += "[*] hosts seem to all be down\n"

    return validHosts,result

def traceHandler(hostInput):
    print("In the traceHandler")

def scanHandler(hostInput,portInput):
    print("In the scanHandler")

def allHandler(hostInput,portInput):
    aliveHosts, resultString = pingHandler(hostInput)
    print(aliveHosts,resultString)
    #traceHandler(aliveHosts)

def startGUI():
    root = Tk()
    root.title("Scanner")
    
    Label(root,text="Host(s)").grid(row=1,column=0)
    Label(root,text="Port(s)").grid(row=1,column=2)

    hostInput = Entry(root)
    portInput = Entry(root)
    
    hostInput.grid(row=1,column=1)
    portInput.grid(row=1,column=3)

    Label(root,text="Results:").grid(row=2,column=2,sticky=E)

    results = Text(root,width=50,height=40)
    results.grid(row=3,columnspan=4)

    v = IntVar()
    Radiobutton(root,text='Ping',variable=v,value=1).grid(row=0,column=0)
    Radiobutton(root,text='Traceroute',variable=v,value=2).grid(row=0,column=1)
    Radiobutton(root,text='Scan',variable=v,value=3).grid(row=0,column=2)
    Radiobutton(root,text='All',variable=v,value=4).grid(row=0,column=3)
    v.set(1)
    #Button(root,text='Ping',command=lambda:pingHandler(hostInput,results)).grid(row=0,column=1,sticky=E)
    #Button(root,text='Traceroute',command=lambda:traceHandler(hostInput,results)).grid(row=0,column=2)
    #Button(root,text='Scan',command=lambda:scanHandler(hostInput,portInput,results)).grid(row=0,column=3,sticky=W)


    Button(root,text="Start Scan",command=lambda:startScan(v,hostInput,portInput,results)).grid(row=4,column=1,sticky=W,pady=4)
    Button(root,text='Quit',command=root.quit).grid(row=4,column=0,sticky=W,pady=4)
    mainloop()