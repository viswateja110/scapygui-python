from scapy.all import *
from scapy.layers.inet import IP,TCP,UDP
import os
import uuid

filetypes={"504B030414":".zip","89504E470D0A1A0A":".png","D0CF11E0A1B11AE1":".doc"}
packets=rdpcap('zipfile.pcap')
sessions=packets.sessions()
hexdumpvar=''
filetypefound=False

filetype=''
for session in sessions:
    for packet in sessions[session]:
        try:
            if (packet[TCP].dport == 80 or packet[TCP].sport == 80) and packet[IP].src=='192.168.50.122' :
                
                if not filetypefound:
                    hexdumpvar=hexdump(packet[TCP].payload,dump=True)
                    for i in filetypes:
                        if hexdumpvar[6:].startswith(i):
                            filetype=filetypes[i]
                with open("data"+filetype,"ab") as fp:
                    fp.write(bytes(packet[TCP].payload))
                            
                
                

            
        except:
            pass

        