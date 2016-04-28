from socket import *
from sys import stderr
from random import randint
import struct
import binascii

def randomMAC():
    mac = [ 0xDE, 0xAD, 
        randint(0x00, 0x29),
        randint(0x00, 0x7f),
        randint(0x00, 0xff),
        randint(0x00, 0xff) ]
    #print(mac)

    tmp = ""
    macAdd = ""
    
    tmp += (''.join(map(lambda x: "%02x" % x, mac)))
    print ('MACaddress = '+ ':'.join(map(lambda x: "%02x" % x, mac)))
    macAdd = binascii.unhexlify(tmp)

    return macAdd

class DHCPDiscover:
    def __init__(self):
        self.xid = b''
        self.mac = b''
        for i in range(4):
            t = randint(0x00, 0xff)
            self.xid += struct.pack('!B', t)
    def sendPacket(self):
        macb = randomMAC()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.xid       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01' # Message Type(code=53 len=1 type=1(DHCPDISCOVER))
        return bytes(packet)

class DHCPOffer:
    def __init__(self, data, xid):
        self.xid = xid
        self.op = data[0]
        self.htype = data[1]
        self.hlen = data[2]
        self.hops = data[3]
        self.mac = data[28:34]
        self.offerIP = data[16:20]
        self.nextServerIP = data[20:24]
        self.server = data[263:267]
        self.data = data
        if self.xid == data[4:8]:
            self.unPack()
    def unPack(self):
        print('********** Receive DHCP Offer **********')
        key = ['opcode', 'htype', 'hlen', 'hops']
        val = [self.op, self.htype, self.hlen, self.hops]
        for i in range (0, len(key), 1):
            print(' {0:20s} : {1:15x}'.format(key[i], val[i]))

class DHCPRequest:
    def __init__(self, data):
        self.xid = data.xid
        self.mac = data.mac
        self.offerIP = data.offerIP
        self.nextServerIP = data.nextServerIP
        self.server = data.server
    def sendPacket(self):
        packet = b''
        return bytes(packet)

if __name__ == "__main__":
    #define the socket
    s = socket(AF_INET, SOCK_DGRAM)             # internet, UDP
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)   # broadcast
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    try:
        s.bind(('', 67))
    except Exception as msg:
        stderr.write("%s\n" % msg)
    else:
        print('DHCP Client')
    
    discoverPacket = DHCPDiscover()
    s.sendto(discoverPacket.sendPacket(), ('<broadcast>', 67))
    
    s.settimeout(20)
    try:
	    data = s.recv(1024)
	    offerPacket = DHCPOffer(data, discoverPacket.xid)
	    requestPacket = DHCPRequest(offerPacket)
    except timeout as msg:
        stderr.write("%s\n" % msg)
    s.close()
    
    exit()
