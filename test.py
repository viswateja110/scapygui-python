from scapy.utils import PcapWriter
from scapy.layers.inet import IP,TCP
from scapy.all import *



# SPLIT IMAGE APART
# Maximum chunk size that can be sent
CHUNK_SIZE = 430

# Location of source image


cntpkt=0

with open('test.doc', 'rb') as infile:
    while True:
        # Read 430byte chunks of the image
        chunk = infile.read(CHUNK_SIZE)
        if not chunk: break
        send(IP(dst='192.168.50.121')/TCP()/Raw(load=chunk))
        cntpkt+=1
        # Do what you want with each chunk (in dev, write line to file)
        
print(cntpkt)
infile.close()

