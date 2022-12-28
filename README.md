# Projet-serveur-DHCP

Explication du code source du dhcp_server.py
Nous avons conçu un serveur DHCP qui permet de distribuer dynamiquement les informations d'adresse IP et de configuration à n’importe quel client.
Il va donc fournir au client : 
-Une Adresse IP
-Un Masque de sous-réseau
-La gateway
-Les adresses du DNS primaire et secondaire

Nous expliquons les différentes fonctions utilisées dans le code du serveur :
def start(self):
		try:
			#start packet listening thread
			(1) thread = Thread(target=self.listen)
			#thread.daemon=True
			(2)pid=os.getpid()
			self.pid=pid
			print("Starting DHCP server...")
			time.sleep(5)
			thread.start()
			print("DHCP server is up")
			(4)logging.info("DHCP server is up")
			(5)logging.debug(f"PID -> {pid}")
			print("Press Ctrl + C to shutdown the server")
			(6)while thread.is_alive():
				(7)thread.join(1)
		(8)except (KeyboardInterrupt):
			print("\nDHCP server going Down")
			logging.info("DHCP server going Down")
			(9) os.remove("server_satatus.txt")
			(3)time.sleep(2)
			print("Server Down")
			logging.info("Server Down")
			(10) sys.exit(0)
		(11) except SystemExit:
			print("Press Ctrl + C again to leave")
			sys.exit(0)
Dans la fonction def start(self) : nous créons un thread pour activer l'écoute de paquets.   Le threading est utile pour que 2 processus s'exécutent en même temps avec chacun sa tâche.
La biblio qui fournit des thread, pour créer un thread par exemple dans (1) nous utilisons thread(target = self.listen)
dans (2) cette méthode est utilisé pour obtenir l'ID du processus en cours. Cette méthode est issu de la biblio OS, qui est un module qui fournit des fonctions d'interactions avec le système d'exploitation.
dans (3) time.sleep() c'est une fonction du module time qui met le programme en pause ( le serveur)
dans (4) logging.info, le module logging fournit une fonction de commodité pour une utilisation simple, tels que .info, logging.info apporte les évènements qui ont eu lieu au cours du fonctionnement du programme. Par exemple, pour voir le statut du serveur.
dans (5) .debug est également un module comme info mais pour une sortie plus détaillée.
dans (6) thread.is_alive est une méthode qui retourne un booléen, en fonction de si le thread est up ou down (status du serveur) pour savoir si on peut envoyer un signal.
dans (7) thread.join() cette methode attend que le thread se finisse et bloque les autres.
dans (8) except (KeyboardInterrupt) ferme le programme en appuyant sur la touche Crtl + C
dans (9) os.remove supprime le fichier déjà crée pour voir le status du serveur. donc si le fichier n'existe pas, le serveur est down.
dans (10) .exit(0) sert à quitter le programme avec succès
dans (11) SystemExit provoque la fermeture de l'interrupteur, cette exception se produit lorsque on veut arrêter le programme et produit une erreur.

def listen(self):
		#sniff DHCP pkts
		sniff(filter="udp and (port 67 or port 68)",prn=self.handle_dhcp,
			  store=0)
Sniff est une fonction de Scapy, qui sert à renifler (sniffer en anglais) pour retirer des paquets du thread. L'argument prn permet de passer la fonction handle_dhcp qui s'execute avec chaque paquet reniflé. Cette fonction contrôle la façon dont le paquet s'imprime.
on a mis en argument comme filtre le port 67 et 68 (ports de UDP). Pour écouter tout paquets intervenant sur ces ports-là.

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
		#server state
		(1)if os.path.exists("server_satatus.txt"):
		  os.remove("server_satatus.txt")
		self.status_file=open("server_satatus.txt","w")
		self.status_file.write("server status : running\nTaken address:\n")
		self.status_file.close()
def __init__ est une méthode appelé constructeur, il est appelé automatiquement lorsque un objet est créé. 
On a défini dans le constructeur les différentes méthodes qui représentent les différents paramètres d'un serveur DHCP. ( exemple :adresse mac, adresse IP, masque sous réseau, la passerelle etc.)

dans (1) si le fichier existe déjà, on le supprime à nouveau, et on le re ouvre et on écrit dedans l'état du serveur ainsi que l'adresse ip déjà prise pour le serveur (taken address).

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

Dans cette fonction def get_option nous vérifions si le serveur retourne plusieurs noms. 
avec la méthode .join, nous ajoutons des virgules entre les noms.
on décode avec .decode les noms de domaine et hostname en chaine originales comme initialement ils sont en binaires.

def handle_dhcp(self, pkt):
		if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
			logging.info('---')
			logging.info('New DHCP Discover')
			#print(packet.summary())
			#print(ls(packet))
			hostname =self.get_option(pkt[DHCP].options, 'hostname')
			client_ip=self.pool.pop()

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
				('subnet_mask',self.subnet_mask),
				("lease_time",self.lease_time),
				('server_id',self.server_ip),
				"end"])

			#sending order_pkt
			sendp(order_pkt,verbose=False)
			logging.info("DHCP Offer pkt sent\n")
			#order_pkt.display()
		# Match DHCP offer		
		(4) elif DHCP in pkt and pkt[DHCP].options[0][1] == 2:
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

		(5)if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
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
				('server_id',self.server_ip),
				'end'])
			#ack_pkt.display()
			(6)sendp(ack_pkt,verbose=False)
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

le Bootstrap protocole est un protocole de communication permet d'obtenir en plus de l'adresse IP des info telles que la passerelle, l'adresse du serveur au démarrage,. 
Udp ports 67 68 est utilisé pour le transport de paquets de données correspondants.
UDP est la seule option pour l'acquisition automatique de l'adresse, dans le cas où le client ne connait si sa propre adresse ni celle du serveur.
L'attribution d'une adresse via BOOTP est basée sur une communication simple en deux étapes entre le client et le serveur. 
Le client prend l'initiative, comme il connait pas son adresse IP, il envoie une requête générale 'BOOTREQUEST' à l'adresse de diffusion 255.255.255.255.
le serveur qui écoute sur le port UDP 67 reçoit et traite cette requête.
Dans ce cas sa tâche c'est d'attribuer une adresse IP adéquate à l'adresse MAC du système du client.
par diffusion, 'BOOTREPLY', est renvoyé avec les infos au clients.

la structure des messages envoyé par le client et le serveur lors de la communication Bootstrap Protocol :
chaque message BOOTP commence avec le champ op de 8 bits, qui définit le 
dans la suite du code en (2)  DHCP(option = ) remplie les champs BOOTP, pour indiquer en premier argument op=2 pour désigner une réponse du serveur, ainsi que le réseau, le bail, et l’IP du serveur. Cette réponse sera envoyée au client.

dans (3)  sendp() c'est une fonction escapy, une méthode pour envoyer des paquets sous controle de la couche 2. 
dans (4) si le champs de l'option correspond à2 , c'est à dire que un offer doit être attribué, un paquet offer va être envoyé du serveur où l'on notera le nom du server et le domaine. Encore une fois tout les infos sont mit dans le fichier logging grâce à logging.info.
dans (5) même chose que précedemment, seulement si l'option = 3, donc c'est un DHCP request. c'est à dire le client demande au serveur de lui attribuer l'adresse qu'il lui a pérécédement proposé. 
dans (6) la fonction sendp() réponds par un paquet ack où grâce à la méthoe .cache 
dans le (7) l'option est 5 donc c'est un DHCP Ack.

def server_state():
	if os.path.isfile("server_satatus.txt"):
		with open("server_satatus.txt","r") as f:
			for line in f:
				print(line.strip())
	else :	
		print("server status : down")
Dans ce code, on crée le fichier qui affiche le status du serveur, pour affficher l'état du serveur. 

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
cette fonction sert à afficher la configuration actuelle du serveur.

def config_pool(network,pool,subnet_mask):
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
			subnet_mask=str(ipaddress.IPv4Interface(network).netmask)
			print("Config has been changed")
			return network,pool,subnet_mask
dans cette fonction, grâce au input on fait rentrer les adresses IP sous le format préalablement configuré. si on rentre l'adresse dans un mauvais format y aura donc une erreur, on nous demande de re entrer l'adresse à nouveau dans le bon format.
Pour le pool, il est défini selon la longueur de l'adresse et de son MSR.
Après avoir rentré l'adresse, on affiche que la configuration a bien était changé.
def config_gateway(gateway,network):
	while 1:
		hosts=[str(ip) for ip in ipaddress.ip_network(network)]
		print("Enter gateway address")
		gateway=input()
		if gateway in hosts:
			return gateway
		else :
			print(f"This ip is not in the network {network}")
Dans la fonction Gateway, on fait entrer l'adresse de la Gateway, si elle fait partis du pool de l'adresse réseau, la configuration s'applique, sinon on nous dit qu'elle n'est pas du même réseau.

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
Dans cette fonction on insère l'adresse du DNS1 et du DNS2.

def menu(pre_config=False):
	print("--------Dashboard----------")
	print("(1)start server")
	print("(2)Config address pool & netmask (CIDR IPV4) manually")
	print("(3)Config Gateway address manually")
	print("(4)Config DNS servers manually ")
	print("(5)Config lease time manually")
	print("(6)Show config ")
	print("(7)Quiter")
celle-ci représente le menu affiché en lançant le serveur.
#Main Programm
if __name__ == "__main__":
	print(" *************************************************")
	print(" *            // DHCP Python3  \\\                *")
	print(" *            ||  server    ||            	 *")
	print(" *             \\\ ---------- //                	 *")
	print(" *************************************************\n")
	#verifier si il y'a des arguments 
	if len(sys.argv)>2: #Usage
			print("Usage:\nsudo python3 {}\nsudo python3 {} [config_file.json]\nsudo python3 {} info".format(sys.argv[0],sys.argv[0],sys.argv[0]))
	if len(sys.argv)==2 and sys.argv[1]=="info": # vois l'info l'etat du serveur
			server_state()
	else:
		"""	
		Default config :
		addres Pool    = 192.168.100.1-192.168.1.254  
		Gateway        = 192.168.100.1
		DNS            = 8.8.8.8  8.8.4.4
		server address = 192.168.100.100
		"""
		logging.basicConfig(filename="DHCP.log",level=logging.INFO,format='%(asctime)s Log: %(message)s') # configuration de fichier de log 
		# Configuration par defaut du serveur 
		server_interface=conf.iface # interface active 
		server_mac=get_if_hwaddr(server_interface) # addresse mac de l'interfece active 
		network_ip="192.168.100.0/24"#addresse réseau
		subnet_mask=str(ipaddress.IPv4Interface(network_ip).netmask) #sous masqk
		server_ip ="192.168.100.100" #l'adress ipv4 du serveur
		pool=[str(ip) for ip in ipaddress.ip_network(network_ip)][2:] #plage d'adresses 
		pool.pop()
		pool.reverse()
		DNS=("8.8.8.8","8.8.4.4")
		Gateway="192.168.100.1"
		lease_time=10000
		if len(sys.argv)==2 and os.path.isfile(sys.argv[1]): # configuration avec un fichier json
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
Dans ce dernier bout de code, nous voyons l'état du serveur, la configuration par défaut, ainsi que le fichier LOG, les différentes adresses ( adresse réseau, masque sous réseau,  adresse DNS, plage d'adresse) ainsi que l'interface active.
Nous constatons aussi la configuration à effectuer avec le fichier json.
Nous ouvrons le fichier json déjà écrit dans un dossier et on l'upload avec la méthode init.load
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
				network_ip,pool,subnet_mask=config_pool(network_ip,pool,subnet_mask)
			elif choice ==3:
				Gateway=config_gateway(Gateway,network_ip)
			elif choice ==4:
				DNS=config_DNS(DNS)
			elif choice ==5:
				lease_time=input("Enter lease time in seconds : ")
			elif choice ==6:
				show_config(server_interface,server_mac,network_ip,subnet_mask,server_ip,pool,DNS,Gateway,lease_time)
			elif choice == 7:
				print("Bye")
				break
Pour cette boucle while, c'est lors de l'exécution du serveur qu'on a un menu, où on choisit l'option selon ce qu'on souhaite faire (changer l'adresse réseau, lancer le serveur, configurer la Gateway, configurer le DNS, le bail, mais aussi afficher la configuration active. Ou encore quitter le serveur.



