from socket import *
from sys import stderr
import binascii

class DHCPDiscover:
	def __init__(self, data):
		self.xid = b''
		self.mac = b''
		self.data = data
		self.unPack()
	def unPack(self):
		print('********** Receive DHCP Discover **********')
		self.xid = self.data[4:8]
		self.mac = self.data[28:34]
		
		unpackmac = str(binascii.hexlify(self.mac))
		print (unpackmac)
		print (self.mac)
		

if __name__ == "__main__":
	#define the socket
    s = socket(AF_INET, SOCK_DGRAM)             # internet, UDP
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)   # broadcast
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    try:
        s.bind(('', 67))
    except Exception as msg:
        stderr.write("%s\n" % msg)
    
    s.settimeout(10)
    
    try:
	    while True:
	        data = s.recv(1024)
	        discoverPacket = DHCPDiscover(data)

    except timeout as msg:
        stderr.write("%s\n" % msg)
