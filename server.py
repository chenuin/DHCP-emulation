from socket import *
from sys import stderr
import binascii

def convertBytes(value, length):
    #print(value)
    strValue = hex(value)
    strValue = strValue[2:]
    while len(strValue) < length*2 :
        strValue = '0' + strValue
    valueBytes = b''
    valueBytes = binascii.unhexlify(strValue)
    #print(valueBytes)
    return valueBytes

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
		
        xid = ''.join(map(lambda x: "%02x" % x, data[4:8]))
        mac = ':'.join(map(lambda x: "%02x" % x, data[28:34]))
        key = ['TransactionID', 'macAddress']
        val = [xid, mac]

        for i in range (0, len(key), 1):
            print(' {0:20s} : {1:15s}'.format(key[i], val[i]))

class DHCPOffer:
    def __init__(self, data, offerIP, nextServerIP, subnetMask, router, leaseTime, DHCPServer, DNS1, DNS2, DNS3):
        self.xid = data.xid
        self.mac = data.mac
        self.offerIP = offerIP
        self.nextServerIP = nextServerIP
        self.subnetMask = subnetMask
        self.router = router
        self.leaseTime = leaseTime
        self.server = DHCPServer
        self.DNS1 = DNS1
        self.DNS2 = DNS2
        self.DNS3 = DNS3
        
        #print(self.xid)
        #print(self.mac)
    def sendPacket(self):
        packet = b''
        packet += b'\x02'   #Message type: Boot Reply (2)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += self.xid
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'    #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += inet_aton('0.0.0.0')
        packet += inet_aton(self.offerIP)
        packet += inet_aton(self.nextServerIP)
        packet += inet_aton('0.0.0.0')
        packet += self.mac
        packet += b'\x00' * 10
        packet += b'\x00' * 192
        packet += b'\x63\x82\x53\x63' #Magic Cookie
        packet += b'\x35\x01\x02'     # Message Type(Option 53 len=1 type=2(offer))
        packet += b'\x01\x04' #subnet mask
        packet += inet_aton(self.subnetMask) 
        packet += b'\x03\x04' #router
        packet += inet_aton(self.router) #router
        packet += b'\x33\x04' #lease time
        packet += convertBytes(self.leaseTime,4)
        packet += b'\x36\x04' #DHCP server
        packet += inet_aton(self.server)
        packet += b'\x07\x04' #DNS servers
        packet += inet_aton(self.DNS1)
        packet +=  b'\x07\x04' #DNS servers
        packet +=  inet_aton(self.DNS2)
        packet += b'\x07\x04' #DNS servers
        packet += inet_aton(self.DNS3)
        
        return bytes(packet)
		
class DHCPRequest:
    def __init__(self, data):
        self.xid = b''
        self.mac = b''
        self.data = data
        self.unPack()
    def unPack(self):
        print('********** Receive DHCP Request ***********')
        self.xid = data[4:8]
        self.mac = data[28:34]
        print(' success!\n')
        print('Wait for another client...')
        
        #print (self.xid)
        #print (self.mac)

class DHCPAck:
    def __init__(self, data, offerIP, nextServerIP, subnetMask, router, leaseTime, DHCPServer, DNS1, DNS2, DNS3):
        self.xid = data.xid
        self.mac = data.mac
        self.offerIP = offerIP
        self.nextServerIP = nextServerIP
        self.subnetMask = subnetMask
        self.router = router
        self.leaseTime = leaseTime
        self.server = DHCPServer
        self.DNS1 = DNS1
        self.DNS2 = DNS2
        self.DNS3 = DNS3
    def sendPacket(self):
        packet = b''
        packet += b'\x02'   #Message type: Boot Reply (2)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += self.xid
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x00\x00'    #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += inet_aton('0.0.0.0')
        packet += inet_aton(self.offerIP)
        packet += inet_aton(self.nextServerIP)
        packet += inet_aton('0.0.0.0')
        packet += self.mac
        packet += b'\x00' * 10
        packet += b'\x00' * 192
        packet += b'\x63\x82\x53\x63' #Magic Cookie
        packet += b'\x35\x01\x05'     # Message Type(Option 53 len=1 type=5(ACK))
        packet += b'\x01\x04' #subnet mask
        packet += inet_aton(self.subnetMask) 
        packet += b'\x03\x04' #router
        packet += inet_aton(self.router) #router
        packet += b'\x33\x04' #lease time
        packet += convertBytes(self.leaseTime,4)
        packet += b'\x36\x04' #DHCP server
        packet += inet_aton(self.server)
        packet += b'\x07\x04' #DNS servers
        packet += inet_aton(self.DNS1)
        packet +=  b'\x07\x04' #DNS servers
        packet +=  inet_aton(self.DNS2)
        packet += b'\x07\x04' #DNS servers
        packet += inet_aton(self.DNS3)
        return bytes(packet)

if __name__ == "__main__":
    offerIP = '192.168.1.100'
    nextServerIP = '192.168.1.1'
    subnetMask = '255.255.255.0'
    router = '192.168.1.1'
    leaseTime = 86400
    DHCPServer = '192.168.1.1'
    DNS1 = '9.7.10.15'
    DNS2 = '9.7.10.16'
    DNS3 = '9.7.10.18'
    
    #define the socket
    s = socket(AF_INET, SOCK_DGRAM)             # internet, UDP
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)   # broadcast
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    try:
        s.bind(('', 67))
    except Exception as msg:
        stderr.write("%s\n" % msg)
    else:
        print('DHCP Server')
    
    s.settimeout(10)

    try:
       while True:
            data = s.recv(1024)
            discoverPacket = DHCPDiscover(data)
            offerPacket = DHCPOffer(discoverPacket,offerIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3)
            s.sendto(offerPacket.sendPacket(), ('<broadcast>', 68))
            data = s.recv(1024)
            requestPacket = DHCPRequest(data)
            ackPacket = DHCPAck(requestPacket,offerIP,nextServerIP,subnetMask,router,leaseTime,DHCPServer,DNS1,DNS2,DNS3)
            s.sendto(ackPacket.sendPacket(), ('<broadcast>', 68))

    except timeout as msg:
        stderr.write("%s\n" % msg)
    s.close()
