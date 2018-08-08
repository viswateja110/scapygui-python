from Tkinter import *
import Tkinter
import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP,TCP,UDP
from io import BytesIO  
import StringIO
from contextlib import contextmanager
import threading
from ScrolledText import *
import os
from scapy.arch.windows import *
import tkMessageBox

  
root=Tk()
root.title("SCAPY GUI")
root.geometry("1024x724")  
topframe=Frame(root)
topframe.pack()
bottomframe=Frame(root) 
bottomframe.pack(side='bottom')
data1=StringVar()
data2=StringVar()
data3=StringVar()
data4=StringVar()
#data entry
label_1=Label(topframe, text="Source")
label_2=Label(topframe, text="Destination")
label_3=Label(topframe, text="Port")
label_4=Label(topframe, text="Message")
entry_1=Entry(topframe,textvariable=data1)
entry_2=Entry(topframe,textvariable=data2)
entry_3=Entry(topframe,textvariable=data3)
entry_4=Entry(topframe,textvariable=data4)
label_1.grid(row=0)
label_2.grid(row=1)
label_3.grid(row=2)
label_4.grid(row=3)
entry_1.grid(row=0,column=1)
entry_2.grid(row=1,column=1)
entry_3.grid(row=2,column=1)
entry_4.grid(row=3,column=1)




#drop down box


choice={'ICMP','ARP','TCP','UDP','HTTP'}
Tkvar=StringVar(root)
Tkvar.set('ICMP')
popupMenu=OptionMenu(topframe,Tkvar,*choice)
Label(topframe,text="Type of packet").grid(row=4,column=0)
popupMenu.grid(row=4,column=1)
packetType=''
def change_dropdown(*args):
    if Tkvar.get()=='ICMP':
       global packetType
       packetType='ICMP'
    elif Tkvar.get()=='TCP':
       global packetType
       packetType='TCP'
    elif Tkvar.get()=='UDP':
       global packetType
       packetType='UDP'
    
        

Tkvar.trace('w',change_dropdown)
#to send packet
e=''
d=''
def storePacket(pkt):
    wrpcap('scapypackets.pcap', pkt, append=True)
def sendPacket():
    global packetType
    c=data3.get()
    d=data4.get()
    p=''
    
    if  packetType=='ICMP':  
        a=data1.get()
        b=data2.get()
        c=data3.get()
        d=data4.get()
        p=(IP(src=a,dst=b)/ICMP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue()  # retrieve written string
           
            output2= hexdump(p,dump=True)

        finally:
            sys.stdout = old_stdout
        storePacket(p)
        send(p)

        
    elif packetType=='TCP':
        a=data1.get()
        b=data2.get()
        p=(IP(src=a,dst=b)/TCP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue() 
            
            output2= hexdump(p,dump=True)
             # retrieve written string
        finally:
            sys.stdout = old_stdout
        storePacket(p)
        send(p)
          
    elif packetType=='UDP':
        a=data1.get()
        b=data2.get()
        p=(IP(src=a,dst=b)/UDP()/d)
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            p.show()
            output = sys.stdout.getvalue() # retrieve written string
             
            output2= hexdump(p,dump=True)
            
        finally:
            sys.stdout = old_stdout
        storePacket(p)
        send(p)
    
    p.show()
    global e
    global d
    e = output
    d= output2
    printPacket()
label_pktheader=Label(bottomframe, text="Packet Header")
label_pktheader.grid(row=0,column=1)
T = ScrolledText(bottomframe, height=10, width=100)
T.grid(row=1,column=1,padx=50,pady=50)
def printPacket():
    
    global e
    global d
    print(e)
    print (d)    
    
    T.delete('1.0', Tkinter.END)
    T.insert(Tkinter.END, e)
    T.insert(Tkinter.END, d)


    #elif packetType=='ARP':
        #a=data1.get()
        #b=data2.get()
        #op=2
        #p=IP(src=a,dst=b,op)/TCP()
        #send(p)    

button1=Tkinter.Button(topframe,text="send packet",command=sendPacket)
button1.grid(padx=5,pady=5,row=5,column=1)

'''button2=Tkinter.Button(topframe, text="Print Me", command=printSomething)
button2.grid(padx=5,pady=5,row=5,column=1) '''


#sniff the data 
label_pktheader=Label(bottomframe, text="Sniffed Packets")
label_pktheader.grid(row=2,column=1)
T1 = ScrolledText(bottomframe, height=10, width=100)
T1.grid(padx=20,pady=20,row=3,column=1)


#def printToBox():
#    with open('sniff.txt','r') as fp:
#        msg=fp.read()
#        fp.close()
#    T1.insert(END,msg)
    


def sniffPackets(packet):        # custom custom packet sniffer action method
    
        if packet.haslayer(IP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            pckt_ttl=packet[IP].ttl
            old_stdout, sys.stdout = sys.stdout, BytesIO()
            try:
                print ('IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl))
                output = sys.stdout.getvalue()  # retrieve written string
            finally:
                sys.stdout = old_stdout
            
            print ('IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl))
            s='IP Packet: %s is going to %s and has ttl value %s' % (pckt_src,pckt_dst,pckt_ttl)
            T1.insert(END,s+'\n')
thread=None
switch=False
def stop_sniffing(x):
    global switch
    return switch
        
def startSniffing():
    print ('custom packet sniffer')
    sniff(filter="ip",prn=sniffPackets,stop_filter=stop_sniffing)  
def startSniffBtn():
    global switch
    global thread

    if (thread is None) or (not thread.is_alive()):
        switch=False
        thread=threading.Thread(target=startSniffing)
        thread.start()
    
def stopSniffBtn():
    global switch
    switch=True
    
     
button2=Tkinter.Button(topframe, text="sniff the data ", command=startSniffBtn)
button2.grid(row=6,column=0)
button3=Tkinter.Button(topframe, text="stop sniff the data ", command=stopSniffBtn)
button3.grid(row=6,column=2)
label_pktheader=Label(topframe, text="scapy pcap file stored at :'"+os.getcwd()+"\\scapypackets.pcap'")
label_pktheader.grid(row=7,column=1,padx=10,pady=10)



#***************************** attachment sending code***********************************************
from tkinter.filedialog import askopenfilename
def sendFile(filename):
    try:
        CHUNK_SIZE = 430    
        cntpkt=0
        with open(filename, 'rb') as infile:
            while True:
                # Read 430byte chunks of the image
                chunk = infile.read(CHUNK_SIZE)
                if not chunk: break
                send(IP(dst='192.168.50.121')/TCP()/Raw(load=chunk))
                cntpkt+=1
                # Do what you want with each chunk (in dev, write line to file)            
        print(cntpkt)
        infile.close()
        return True
    except:
        return False
    

def openWindow():
    Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
    filename = askopenfilename() # show an "Open" dialog box and return the path to the selected file
    print(filename)
    if sendFile(filename):
        tkMessageBox.showinfo("Success", "Attachment has been sent")
    else:
        tkMessageBox.showinfo("Failed", "Please try again")
import pcapparser
def getFile():
    Tk().withdraw() # we don't want a full GUI, so keep the root window from appearing
    filename = askopenfilename()
    if pcapparser.extractFile(filename):
        tkMessageBox.showinfo("Success", "File has been extracted")
    else:
        tkMessageBox.showinfo("Error", "some error occurred")



button4=Tkinter.Button(topframe, text="send attachment ", command=openWindow)
button4.grid(row=7,column=2)
button5=Tkinter.Button(topframe, text="Retrive File ", command=getFile)
button5.grid(row=8,column=2)

root.mainloop()