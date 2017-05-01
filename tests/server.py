#!/usr/bin/python
from __future__ import print_function
from pyrad import dictionary, packet,server
import logging
import socket
from bs4 import BeautifulSoup

class Server(server.Server):

    def HandleAuthPacket(self, pkt):

        print("Received an authentication request")
	temp = pkt
	replay = temp
	#replay = self.RequestPacket()
	
        print("Attributes: ")
        for attr in pkt.keys():
            
	    print("%s: %s" % (attr, pkt[attr]))

	    replay = self.CreateReplyPacket(pkt, **{
	    #"User-Name" : "aa",
	    #"NAS-IP-Address" : "192.168.1.1",
         #   "Service-Type": 1,
         #   "Framed-IP-Address": '0xFFFFFFFF',
	    #"Framed-IP-Netmask": "255.255.255.0",
           # "Framed-IPv6-Prefix": "fc66::1/64",
	    #"Framed-MTU": "1400",
        #    "Framed-Protocol": "PPP",
	    #"Framed-Routing": "3",
	    "EAP-Message": "0x03090004",
	    "MS-MPPE-Encryption-Policy": "Encryption-Allowed",
	    #"Calling-Station-Id" : "c49a02570def",
	    #"Called-Station-Id" : "60e327e83998",
	    #"NAS-Port-Type" : 19,
	    "MS-MPPE-Encryption-Types" : "RC4-40or128-bit-Allowed",
	    #"MS-MPPE-Send-Key" : req.PwDecrypt("aa"),
	    "MS-MPPE-Send-Key" : "0x796ee09db470a883c4621e8b5ff08919",
	    "MS-MPPE-Recv-Key" : "0x9c88acc82ec687eb8ca9cec964c91dd4",
            #"Packet-Type" : "Access-Challenge",
	    #"Class" : "0x20",
	    "Message-Authenticator" : "0x00000000000000000000000000000000",
            #"Vendor-Specific" : "Microsoft" AVP: l=18 t=Message-Authenticator(80): 5ee1617c9061372a4edb29e77a9500b7
	    #"Authenticator": "0x23191919191919191919191919"
        })

        replay.code = packet.AccessAccept
        #req.code = packet.AccessChallenge
	#req = self.CreateAuthPacket()
	#reqlay = self.CreateAuthPacket()
        
        self.SendReplyPacket(pkt.fd, replay)
        
	

if __name__ == '__main__':
    # create server and read dictionary
    srv = Server(dict=dictionary.Dictionary("dictionary"), coa_enabled=False)

    # add clients (address, secret, name)
    #srv.hosts["192.168.1.1"] = server.RemoteHost("127.0.0.1", b"2ZzMNRpKf574rGW", "localhost")
    srv.hosts["192.168.1.1"] = server.Server(["127.0.0.1"])

    srv.BindToAddress("")

    print("start server")
    srv.Run()
    #srv._GrabPacket()
