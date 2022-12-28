
from scapy.all import *
from time import sleep
from threading import Thread
import logging
import sys
import json
import ipaddress
import os

class DHCPServer(object):
	def __init__(self,server_mac,server_ip,subnet_mask,gateway,DNS,pool,lease_time):
		self.allocated_ip = [server_ip,gateway]
		self.pool=pool
		self.network_ip=network_ip
		self.server_mac=server_mac
		self.server_ip=server_ip
		self.gateway=gateway
		self.DNS=DNS
		self.subnet_mask=subnet_mask
		self.lease_time=lease_time
		self.cache={}
		self.poll_len=len(self.pool)
		self.requested='0.0.0.0'
		#server state
		if os.path.exists("server_satatus.txt"):
		  os.remove("server_satatus.txt")
		self.status_file=open("server_satatus.txt","w")
		self.status_file.write("server status : running\nTaken address:\n")
		self.status_file.close()
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
		if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
			options=[ option[0] for option in pkt[DHCP].options]
			logging.info('---')
			logging.info('New DHCP Discover')
			#print(packet.summary())
			#print(ls(packet))
			if 'requested_addr' in options:
				self.requested=pkt[DHCP].options[options.index("requested_addr")][1]
				if self.requested in pool :
					client_ip=self.pool.pop(self.pool.index(self.requested))
					logging.info("Couldn't satisfy client request for the {} ip addres request".format(self.requested))
				else:
					client_ip=self.pool.pop()
			else:
				self.requested="0.0.0.0"
				client_ip=self.pool.pop()
			hostname =self.get_option(pkt[DHCP].options, 'hostname')

			logging.info(f"Host {hostname} ({pkt[Ether].src}) asked for an IP")
			logging.info(f"server is offering {client_ip}")

			#generating orer_pkt
			order_pkt=Ether(src=self.server_mac,dst="ff:ff:ff:ff:ff:ff")
			order_pkt/=IP(src=self.server_ip, dst="255.255.255.255")
			order_pkt/= UDP(sport=67, dport=68)
			order_pkt/=BOOTP(op=2,yiaddr=client_ip,siaddr=self.server_ip,giaddr=self.gateway,chaddr=pkt[Ether].src,xid=pkt[BOOTP].xid)
			order_pkt/=DHCP(options=
				[
				('message-type',2),
				('name_server',self.DNS[0]),
				('requested_addr',self.requested),
				('subnet_mask',self.subnet_mask),
				("lease_time",self.lease_time),
				('server_id',self.server_ip),
				"end"])

			#sending order_pkt
			sendp(order_pkt,verbose=False)
			logging.info("DHCP Offer pkt sent\n")
			#order_pkt.display()
		# Match DHCP offer		
		elif DHCP in pkt and pkt[DHCP].options[0][1] == 2:
			logging.info('---')
			logging.info('New DHCP Offer')
			#print(pkt.summary())
			#print(ls(pkt))
			#pkt.display()
			name_server = self.get_option(pkt[DHCP].options, 'name_server')
			domain = self.get_option(pkt[DHCP].options, 'domain')

			logging.info(f"DHCP Server {pkt[IP].src} ({pkt[Ether].src}) "
				  f"offered {pkt[BOOTP].yiaddr}")

			logging.info(f"DHCP Options: subnet_mask: {self.subnet_mask}, lease_time: "
				  f"{self.lease_time}, router: {self.gateway}, name_server: {name_server}, "
				  f"domain: {domain}")

		if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
			logging.info('---')
			logging.info('New DHCP Request')
			#print(pkt.summary())
			#print(ls(pkt))
			#pkt.display()
			hostname = self.get_option(pkt[DHCP].options, 'hostname')
			logging.info(f"Host {hostname} ({pkt[Ether].src}) requested {pkt[BOOTP].yiaddr}")
			#print("DHCP Request pkt detected")

			ack_pkt=Ether(src=server_mac,dst="ff:ff:ff:ff:ff:ff")
			ack_pkt/=IP(src=server_ip, dst="255.255.255.255")
			ack_pkt/= UDP(sport=67, dport=68)
			ack_pkt/=BOOTP(op=2,yiaddr=pkt[BOOTP].yiaddr,siaddr=server_ip,giaddr=self.gateway,chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)
			ack_pkt/=DHCP(options=[
				("message-type", 5),
				('subnet_mask',self.subnet_mask),
				('requested_addr',self.requested),
				('name_server',self.DNS[0]),
				('server_id',self.server_ip),
				'end'])
			#ack_pkt.display()
			sendp(ack_pkt,verbose=False)
			logging.info("DHCP Ack pkt sent , moving allocate mac/ip to cache\n")
			self.cache[pkt[BOOTP].chaddr]=pkt[BOOTP].yiaddr
			with open("server_satatus.txt","a") as f:
				f.write(pkt[BOOTP].chaddr.decode("utf-8") +"="+str(pkt[BOOTP].yiaddr)+"\n")
			logging.info("saved to cache")
		# Match DHCP ack
		elif DHCP in pkt and pkt[DHCP].options[0][1] == 5:
			logging.info('---')
			logging.info('New DHCP Ack')
			#print(pkt.summary())
			#print(ls(pkt))
			name_server =self.get_option(pkt[DHCP].options, 'name_server')

			logging.info(f"DHCP Server {pkt[IP].src} ({pkt[Ether].src}) "
				  f"acked {pkt[BOOTP].yiaddr}")

			logging.info(f"DHCP Options: subnet_mask: {self.subnet_mask}, lease_time: "
				  f"{self.lease_time}, router: {self.gateway}, name_server: {name_server}")
	def listen(self):
		#sniff DHCP pkts
		sniff(filter="udp and (port 67 or port 68)",prn=self.handle_dhcp,
			  store=0)
	def start(self):
		try:
			#start packet listening thread
			thread = Thread(target=self.listen)
			#thread.daemon=True
			pid=os.getpid()
			self.pid=pid
			print("Starting DHCP server...")
			time.sleep(5)
			thread.start()
			print("DHCP server is up")
			logging.info("DHCP server is up")
			logging.debug(f"PID -> {pid}")
			print("Press Ctrl + C to shutdown the server")
			while thread.is_alive():
				thread.join(1)
		except (KeyboardInterrupt):
			print("\nDHCP server going Down")
			logging.info("DHCP server going Down")
			os.remove("server_satatus.txt")
			time.sleep(2)
			print("Server Down")
			logging.info("Server Down")
			sys.exit(0)
		except SystemExit:
			print("Press Ctrl + C again to leave")
			sys.exit(0)




def server_state():
	if os.path.isfile("server_satatus.txt"):
		with open("server_satatus.txt","r") as f:
			for line in f:
				print(line.strip())
	else :	
		print("server status : down")
def show_config(server_interface,server_mac,network_ip,subnet_mask,server_ip,pool,Gateway,DNS,lease_time):
		print("server_interface :",server_interface)
		print("server mac",server_mac)
		print("network_ip is :",network_ip)
		print("subnet_mask is : ",subnet_mask)
		print("server_ip is :",server_ip)
		print("pool is {}-{}".format(pool[-1],pool[0]))
		print("DNS servers are",DNS)
		print("gateway is :",Gateway)
		print("dhcp lease time :",lease_time)
def config_pool(server_ip,network,pool,subnet_mask):
	while 1:
		print("Enter network ip address (CIDR)  (format x.x.x.x/x)")
		ip=input()
		if '/' not in ip:
			continue
		try:
			ipaddress.ip_network(ip)
		except Exception as e:
			print(e)	
			print("retry")
		else:
			network=ipaddress.ip_network(ip)
			pool=list(network.hosts())
			if len(pool)<2 :
				continue
			print("pool range is set to {} - {}".format(pool[0],pool[-1]))
			pool.reverse()
			while 1:
				try:
					server_ip=input("Enter the new server_ip address : ")
					server_ip=ipaddress.ip_address(server_ip)
					if server_ip in pool:
						print("the new server ip is : ",server_ip)
						break
					else : print("The ip addres is not in the pool")
				except Exception as e:
					print(e)
					print("Retry")
			subnet_mask=str(ipaddress.IPv4Interface(network).netmask)
			print("Config has been changed")
			return server_ip,network,pool,subnet_mask
def config_gateway(gateway,network):
	while 1:
		print("Enter gateway address")
		gateway=input()
		if gateway in str(ipaddress.ip_network(network)):
			return gateway
		else :
			print(f"This ip is not in the network {network}")
def config_DNS(DNS):
	while 1:
		DNS1=input("Enter primary DNS address :")
		try: 
			ipaddress.ip_address(DNS1)
			break
		except Exception as e:
			print(e)
			print("try again")
	while 1:
		DNS2=input("Enter secondary DNS address :")
		try: 
			ipaddress.ip_address(DNS2)
			break
		except Exception as e:
			print(e)
			print("try again")
	return DNS1,DNS2

def menu(pre_config=False):
	print("--------Dashboard----------")
	print("(1)start server")
	print("(2)Config address pool & netmask (CIDR IPV4) manually")
	print("(3)Config Gateway address manually")
	print("(4)Config DNS servers manually ")
	print("(5)Config lease time manually")
	print("(6)Show config ")
	print("(7)Quiter")
#Main Programm
if __name__ == "__main__":
	print(" *************************************************")
	print(" *            // DHCP Python3  \\\                *")
	print(" *            ||  server    ||            	 *")
	print(" *             \\\ ---------- //                	 *")
	print(" *************************************************\n")
	#verifier si il y'a des arguments 
	if len(sys.argv)>2:
			print("Usage:\nsudo python3 {}\nsudo python3 {} [config_file.json]\nsudo python3 {} info".format(sys.argv[0],sys.argv[0],sys.argv[0]))
	if len(sys.argv)==2 and sys.argv[1]=="info":
			server_state()
	else:
		"""	
		Default config :
		addres Pool    = 192.168.100.1-192.168.1.254  
		Gateway        = 192.168.100.1
		DNS            = 8.8.8.8  8.8.4.4
		server address = 192.168.100.100
		"""
		logging.basicConfig(filename="DHCP.log",level=logging.INFO,format='%(asctime)s Log: %(message)s')
		server_interface=conf.iface
		server_mac=get_if_hwaddr(server_interface)
		network_ip="192.168.100.0/24"
		subnet_mask=str(ipaddress.IPv4Interface(network_ip).netmask)
		server_ip ="192.168.100.100"
		pool=[str(ip) for ip in ipaddress.ip_network(network_ip)][2:]
		pool.pop()
		pool.reverse()
		DNS=("8.8.8.8","8.8.4.4")
		Gateway="192.168.100.1"
		lease_time=86400 #(1 day)
		if len(sys.argv)==2 and os.path.isfile(sys.argv[1]):
			config_file=sys.argv[1]
			print("loading config file")
			time.sleep(4)
			"""
			Json file format exemple:
			{
				"interface"   :"eth0",
				"server_ip"   :"192.168.100.99",
			   	"network_ip"  :"192.168.100.0/24",
				"subnet_mask" :"255.255.255.0",
				"DNS1"        :"8.8.8.8",
				"DNS2"        :"8.8.4.4",
			    	"Gateway"     :"192.168.100.1",
			   	"lease_time" :"1000"
			}
			"""
			with open(config_file) as file:
				data = json.load(file)
				if len(data)<8:
					print("wron config file format")
				else:
					server_interface=data["interface"]
					server_mac=get_if_hwaddr(server_interface)
					network_ip=data["network_ip"]
					subnet_mask=data["subnet_mask"]
					server_ip =data["server_ip"]		
					pool=[str(ip) for ip in ipaddress.ip_network(network_ip)][2:]
					pool.pop()
					pool.reverse()
					DNS=(data["DNS1"],data["DNS2"])
					Gateway=data["Gateway"]
					lease_time=data["lease_time"]
					print(server_interface)
					print("loaded")
		else:
			print("NB:default config is loaded (check option 6)")
		while 1:
			while 1:
				menu()
				while 1:
					choice=int(input("Enter your choice: "))
					print("------------------")
					if choice in range(1,8):
						break
					print("Wrong entry")
				if choice == 1:
					server = DHCPServer(server_mac,server_ip,subnet_mask,Gateway,DNS,pool,lease_time)
					server.start()
					break
				elif choice ==2:
					server_ip,network_ip,pool,subnet_mask=config_pool(server_ip,network_ip,pool,subnet_mask)
				elif choice ==3:
					Gateway=config_gateway(Gateway,network_ip)
				elif choice ==4:
					DNS=config_DNS(DNS)
				elif choice ==5:
					lease_time=input("Enter lease time in seconds")
				elif choice ==6:
					show_config(server_interface,server_mac,network_ip,subnet_mask,server_ip,pool,Gateway,DNS,lease_time)
				elif choice == 7:
					print("Bye")
				break







