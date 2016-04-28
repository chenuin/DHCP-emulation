from socket import *
import struct
from random import randint
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
    print ('MAC = '+ ':'.join(map(lambda x: "%02x" % x, mac)))
    macAdd = binascii.unhexlify(tmp)

    return macAdd
    
class DHCPDiscover:
    def __init__(self):
        self.xid = b''
        self.mac = b''
        for i in range(4):
            t = randint(0, 255)
            self.xid += struct.pack('!B', t)
    def sendPacket(self):
        macb = self.mac =randomMAC()
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
        packet += b'\x35\x01\x01' # Message Type(code=53 len=1 type=1(DHCP_DISCOVER))
        return bytes(packet)
    def unPack(self,data):
        mac = data[28:34]
        print("mac: " + mac)
class DHCPOffer:
    def __init__(self,data,xid):
        self.data = data
        self.xid = xid
        self.offerIP = ''
        self.dhcpServer = ''
        self.nextServerIP = ''
        self.unPack()
    def unPack(self):
        print('********** Receive DHCP Offer **********')
        if self.data[4:8] == self.xid :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))
            self.dhcpServer = '.'.join(map(lambda x:str(x), data[263:267]))
            
            key = ['Offer IP', 'Next Server IP', 'Subnet Mask', 'Router', 'DHCP Server', 'DNS server', 'DNS server', 'DNS server']
            val = [data[16:20], data[20:24], data[245:249], data[251:255], data[263:267], data[269:273], data[275:279], data[281:285]]
            
            for i in range (0, len(val), 1):
                print(' {0:20s} : {1:15s}'.format(key[i], '.'.join(map(lambda x:str(x),val[i]))))
            print(" Lease Time           :"  + str(struct.unpack('!i',data[257:261])))

class DHCPRequest:
    def __init__(self,xid,mac,nextServerIP,dhcpServer,offerIP):
        self.xid = xid
        self.mac = mac
        self.nextServerIP = nextServerIP
        self.dhcpServer = dhcpServer
        self.offerIP = offerIP
    def sendPacket(self):
        packet = bytearray(246)
        packet[0] = 1 #self.message_type
        packet[1] = 1 #self.hardware_type
        packet[2] = 6 #self.hardware_address_length
        packet[3] = 0 #self.hops

        packet[4:8] = self.xid #xid
        packet[ 8:10] = b'\x00\x00' #SECS
        packet[10:12] = b'\x00\x00' #FLAGS

        packet[12:16] = inet_aton('0.0.0.0') #client_ip_address
        packet[16:20] = inet_aton('0.0.0.0') #your_ip_address
        packet[20:24] = inet_aton(self.nextServerIP) #next_server_ip_address
        packet[24:28] = inet_aton('0.0.0.0') #relay_agent_ip_address

        packet[28:35] = self.mac
        packet[35:44] = b'\x00' * 10
        packet[44:236]= b'\x00' * 192
        
        packet[236:240] =  b'\x63\x82\x53\x63' #Magic Cookie
        packet[243:246] =  b'\x35\x01\x03' # Message Type(code=53 len=1 type=3(DHCPRequest))
        packet[246:248] = b'\x32\x04'
        packet[248:252] = inet_aton(self.offerIP)
        packet[252:254] = b'\x36\x04'
        packet[254:258] = inet_aton(self.dhcpServer)
        packet += b'\xff'
        return bytes(packet)
class DHCPAck:
    def __init__(self,data,xid):
        self.data = data
        self.xid = xid
        self.offerIP = ''
        self.dhcpServer = ''
        self.nextServerIP = ''
        self.unPack()
    def unPack(self):
        print('********** Receive DHCP ACK **********')
        if self.data[4:8] == self.xid :
            #print("xid: "+':'.join(map(lambda x:str(x), data[4:8])))
            #print(binascii.hexlify(self.xid))
            
            key = ['opcode', 'htype', 'hlen', 'hops', 'TranscationID', 'secs', 'flags', 'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'client MAC address','Option(53)']
            val = [data[0], data[1], data[2], data[3], data[4:8], data[8:10], data[10:12], data[12:16], data[16:20], data[20:24], data[24:28], data[28:34], data[243:246]]
            
            for i in range (0, 4, 1):
                print(' {0:20s} : {1:15s}'.format(key[i], str(val[i])))
                
            showID = ''.join(map(lambda x: "%02x" % x, data[4:8]))
            print (' {0:20s} : 0x{1:15s}'.format(key[4], showID))
            
            for i in range (5, 11, 1):
                print(' {0:20s} : {1:15s}'.format(key[i], '.'.join(map(lambda x:str(x), val[i]))))
            showMAC = ':'.join(map(lambda x: "%02x" % x, data[28:34]))
            print (' {0:20s} : {1:15s}'.format(key[11], showMAC))
            
            print('\n close connection')
if __name__ == '__main__':
    s = socket(AF_INET, SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1) 
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', 68))
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
        requestPacket = DHCPRequest(discoverPacket.xid, discoverPacket.mac, offerPacket.nextServerIP, offerPacket.dhcpServer, offerPacket.offerIP)
        s.sendto(requestPacket.sendPacket(),('<broadcast>',67))
        data = s.recv(1024)
        ackPacket = DHCPAck(data,discoverPacket.xid)
    except timeout as msg:
        stderr.write("[DBG] %s\n"+'\033[40m' % msg)
    
    s.close()

    exit()
