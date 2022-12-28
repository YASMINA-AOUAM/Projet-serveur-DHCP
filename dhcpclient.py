
from scapy.all import *
from time import sleep
from threading import Thread
import logging
import sys
import json
import ipaddress

from random import randint


class DHCPclient(object):
	def get_option(self,dhcp_options, key):
		must_decode = ['hostname', 'domain', 'vendor_class_id']
		try:
			for i in dhcp_options:
				if i[0] == key:
					# If DHCP Server Returned multiple name servers 
					# return all as comma seperated string.
					if key == 'name_server' and len(i) > 2:
						return ",".join(i[1:])
					# domain and hostname are binary strings,
					# decode to unicode string before returning
					elif key in must_decode:
						return i[1].decode()
					else: 
						return i[1]        
		except:
			pass
	def handle_dhcp(self, pkt):
		# Match DHCP offer
		if DHCP in pkt and pkt[DHCP].options[0][1] == 2:
			print('---')
			print('New DHCP Offer')
			#print(pkt.summary())
			#print(ls(pkt))
			#pkt.display()
			subnet_mask = self.get_option(pkt[DHCP].options, 'subnet_mask')
			lease_time = self.get_option(pkt[DHCP].options, 'lease_time')
			router = self.get_option(pkt[DHCP].options, 'router')
			name_server = self.get_option(pkt[DHCP].options, 'name_server')
			domain = self.get_option(pkt[DHCP].options, 'domain')

			print(f"DHCP Server {pkt[IP].src} ({pkt[Ether].src}) "
				  f"offered {pkt[BOOTP].yiaddr}")

			print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
				  f"{lease_time}, router: {router}, name_server: {name_server}, "
				  f"domain: {domain}")
			print("okey here")
			req_pkt=Ether(src='5c:96:9e:76:2c:1c',dst="ff:ff:ff:ff:ff:ff")
			req_pkt/=IP(src='0.0.0.0', dst="255.255.255.255")
			req_pkt/= UDP(sport=68, dport=67)
			req_pkt/=BOOTP(op=1,yiaddr=pkt[BOOTP].yiaddr,siaddr=pkt[BOOTP].siaddr,giaddr=pkt[BOOTP].giaddr,chaddr='5c:96:9e:76:2c:1c',xid=pkt[BOOTP].xid)
			req_pkt/=DHCP(options=
				[
				('message-type',3),
				('subnet_mask',subnet_mask),
				('server_id',pkt[BOOTP].siaddr),
				"end"])
			req_pkt.display()

			sendp(req_pkt,monitor=False)
			print("Request pkt sent")

	def listen(self):
		#sniff DHCP pkts
		sniff(filter="udp and (port 67 or port 68)",
			  prn=self.handle_dhcp,
			  store=0)
	def start(self):
		#start packet listening thread
		thread = Thread(target=self.listen)
		#thread.daemon=True
		thread.start()




	def scapy_send_dhcp_discover_requests(self,number_of_packets):
		for _ in range(number_of_packets):
			dhcp_discover_request = Ether(src='5c:96:9e:76:2c:1c', dst='ff:ff:ff:ff:ff:ff') /\
									IP(src='0.0.0.0', dst='255.255.255.255') /\
									UDP(dport=67, sport=68) /\
									BOOTP(chaddr='5c:96:9e:76:2c:1c', xid=randint(1, 4294967295)) /\
									DHCP(options=[('message-type', 1),('requested_addr','20.20.20.20'),'end'])
			sendp(dhcp_discover_request,count=1,verbose=False)
			#print("Sent DISCOVER")
		#dhcp_discover_request.display()

if __name__ == '__main__':
	client=DHCPclient()
	client.scapy_send_dhcp_discover_requests(1)
	client.start()
