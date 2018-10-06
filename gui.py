from tkinter import *

def pingHandler(hostInput,result):
    result.delete(0,END)
    hosts = hostInput.get()
    result.insert(10,hosts)
def traceHandler(hostInput,result):
    print("In the traceHandler")
def scanHandler(hostInput,portInput,result):
    print("In the scanHandler")

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

    results = Entry(root)
    results.grid(row=3,columnspan=4)

    Button(root,text='Ping',command=pingHandler(hostInput,results)).grid(row=0,column=1,sticky=E)
    Button(root,text='Traceroute',command=traceHandler).grid(row=0,column=2)
    Button(root,text='Scan',command=scanHandler).grid(row=0,column=3,sticky=W)



    Button(root,text='Quit',command=root.quit).grid(row=4,column=0,sticky=W,pady=4)
    Button(root,text='Start Scan').grid(row=4,column=1,sticky=W,pady=4)
    mainloop()