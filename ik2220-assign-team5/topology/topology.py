"""Group 5 topology
Bilal, Abdulrahman
Kostina, Olga
Omer Mahgoub Saied, Khalid
Puri, Gaurav
"""



from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.net import Mininet
from mininet.util import quietRun
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import OVSSwitch
import sys



LOG_FILE = 'test_report.log'



class G5Topo( Topo ):

    def __init__( self ):
        Topo.__init__( self )
    
    def build( self ):
        # Adding hosts
        h1 = self.addHost('h1',ip='100.0.0.10/24')
        h2 = self.addHost('h2',ip='100.0.0.11/24')
        h3 = self.addHost('h3',ip='10.0.0.50/24',defaultRoute='via 10.0.0.1')
        h4 = self.addHost('h4',ip='10.0.0.51/24',defaultRoute='via 10.0.0.1')
    
    
        # Adding DNS Servers
        ds1 = self.addHost('ds1',ip='100.0.0.20/24',defaultRoute='via 100.0.0.1')
        ds2 = self.addHost('ds2',ip='100.0.0.21/24',defaultRoute='via 100.0.0.1')
        ds3 = self.addHost('ds3',ip='100.0.0.22/24',defaultRoute='via 100.0.0.1')
    
        # adding Web Servers
        ws1 = self.addHost('ws1',ip='100.0.0.40/24')
        ws2 = self.addHost('ws2',ip='100.0.0.41/24')
        ws3 = self.addHost('ws3',ip='100.0.0.42/24')
    
        # Adding IDS inspection server
        insp = self.addHost('insp',ip='100.0.0.30/24')
        
        # Adding main switches
        sw1 = self.addSwitch('s1',dpid='1')
        sw2 = self.addSwitch('s2',dpid='2')
        sw3 = self.addSwitch('s3',dpid='3')
        sw4 = self.addSwitch('s4',dpid='4')
        sw5 = self.addSwitch('s5',dpid='5')
    
        # Adding loadbalancers, firewalls, NAPT and ids switches
        fw1 = self.addSwitch('fw1',dpid='11')
        fw2 = self.addSwitch('fw2',dpid='12')
        lb1 = self.addSwitch('lb1',dpid='21')
        lb2 = self.addSwitch('lb2',dpid='22')
        ids = self.addSwitch('ids',dpid='31')
        napt = self.addSwitch('napt',dpid='41')    
    
        # Add links
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )
        self.addLink( sw1, fw1 )
        self.addLink( fw1, sw2 )
        self.addLink( sw2, fw2 )
        self.addLink( fw2, napt )
        self.addLink( napt, sw5 )
        self.addLink( sw3, lb1 )
        self.addLink( lb1, sw2 )
        self.addLink( sw2, ids )
        self.addLink( ids, lb2 )
        self.addLink( lb2, sw4 )
        self.addLink( insp, ids )
    
        self.addLink( ds1, sw3 )
        self.addLink( ds2, sw3 )
        self.addLink( ds3, sw3 )
    
        self.addLink( ws1, sw4 )
        self.addLink( ws2, sw4 )
        self.addLink( ws3, sw4 )
    
        self.addLink( h3, sw5 )
        self.addLink( h4, sw5 )

		
def start_topo():
    controller = RemoteController('controller', '0.0.0.0', 6633)
    net = Mininet(topo=G5Topo(), host=CPULimitedHost, controller=controller, autoSetMacs=True, switch=OVSSwitch)
    #net.addController(controller)
    net.start()
    
    # Start DNS server
    net.get('ds1').cmd('python /var/dns.py 100.0.0.20 &')
    net.get('ds2').cmd('python /var/dns.py 100.0.0.21 &')
    net.get('ds3').cmd('python /var/dns.py 100.0.0.22 &')
    
    # Set the name server for all the hosts to the DNS loadbalancer IP address
    net.get('h1').cmd('echo "nameserver 100.0.0.25" >> /etc/resolv.conf &');
    
    net.get('ws1').cmd('cd /var/www/ ; python -m CGIHTTPServer 80 &')
    net.get('ws2').cmd('cd /var/www/ ; python -m CGIHTTPServer 80 &')
    net.get('ws3').cmd('cd /var/www/ ; python -m CGIHTTPServer 80 &')
    
    CLI(net)
	
    #======================================= Testing =======================================#

    log = open(LOG_FILE,'w')
    
    
    #Test 1: PrZ_Hosts --- ping test from Pbz to PrZ
    log.write('====================================================================================\n')
    log.write('Test 1: PrZ_Hosts --- ping test from PbZ to PrZ 	>>> Blocked by FW \n\n')
    log.write('h1 ping h3 \n'+net.get('h1').cmd('ping -c 2 10.0.0.50')+'\n')
    log.write('h1 ping h4 \n'+net.get('h1').cmd('ping -c 2 10.0.0.51')+'\n')
    log.write('h2 ping h3 \n'+net.get('h2').cmd('ping -c 2 10.0.0.50')+'\n')
    log.write('h2 ping h4 \n'+net.get('h2').cmd('ping -c 2 10.0.0.51')+'\n\n\n')
	

	
    #Test 2: PbZ_Hosts --- ping test from PrZ to PbZ
    log.write('====================================================================================\n')
    log.write('Test 2: PbZ_Hosts --- ping test from PrZ to PbZ 	>>> Successful Through NAPT \n\n')
    log.write('h3 ping h1 \n'+net.get('h3').cmd('ping -c 2 100.0.0.10')+'\n')
    log.write('h3 ping h2 \n'+net.get('h3').cmd('ping -c 2 100.0.0.11')+'\n')
    log.write('h4 ping h1 \n'+net.get('h4').cmd('ping -c 2 100.0.0.10')+'\n')
    log.write('h4 ping h2 \n'+net.get('h4').cmd('ping -c 2 100.0.0.11')+'\n\n\n')


	
    #Test 3: ping hosts to LB2
    log.write('====================================================================================\n')
    log.write('Test 3: ping PbZ_Hosts and PrZ_Hosts -> LB2 		>>> Successful \n\n')
    log.write('h1 ping LB2 \n'+net.get('h1').cmd('ping -c 3 100.0.0.45')+'\n')
    log.write('h2 ping LB2 \n'+net.get('h2').cmd('ping -c 3 100.0.0.45')+'\n')
    log.write('h3 ping LB2 \n'+net.get('h3').cmd('ping -c 3 100.0.0.45')+'\n')
    log.write('h4 ping LB2 \n'+net.get('h4').cmd('ping -c 3 100.0.0.45')+'\n\n\n')


    
    #Test 4: ping hosts to LB1
    log.write('====================================================================================\n')
    log.write('Test 4: ping PbZ_Hosts and PrZ_Hosts -> LB1 		>>> Successful \n\n')
    log.write('h1 ping LB1 \n'+net.get('h1').cmd('ping -c 3 100.0.0.25')+'\n')
    log.write('h2 ping LB1 \n'+net.get('h2').cmd('ping -c 3 100.0.0.25')+'\n')
    log.write('h3 ping LB1 \n'+net.get('h3').cmd('ping -c 3 100.0.0.25')+'\n')
    log.write('h4 ping LB1 \n'+net.get('h4').cmd('ping -c 3 100.0.0.25')+'\n\n\n')

	
    
    #Test 5: ping hosts to DNS
    log.write('====================================================================================\n')
    log.write('Test 5: ping PbZ_Hosts and PrZ_Hosts -> DNS 		>>> Blocked by LB1 \n\n')
    log.write('h1 ping ds1 \n'+net.get('h1').cmd('ping -c 2 100.0.0.20')+'\n')
    log.write('h1 ping ds2 \n'+net.get('h1').cmd('ping -c 2 100.0.0.21')+'\n')
    log.write('h1 ping ds3 \n'+net.get('h1').cmd('ping -c 2 100.0.0.22')+'\n')
	
    log.write('h2 ping ds1 \n'+net.get('h2').cmd('ping -c 2 100.0.0.20')+'\n')
    log.write('h2 ping ds2 \n'+net.get('h2').cmd('ping -c 2 100.0.0.21')+'\n')
    log.write('h2 ping ds3 \n'+net.get('h2').cmd('ping -c 2 100.0.0.22')+'\n')
	
    log.write('h3 ping ds1 \n'+net.get('h3').cmd('ping -c 2 100.0.0.20')+'\n')
    log.write('h3 ping ds2 \n'+net.get('h3').cmd('ping -c 2 100.0.0.21')+'\n')
    log.write('h3 ping ds3 \n'+net.get('h3').cmd('ping -c 2 100.0.0.22')+'\n')

    log.write('h4 ping ds1 \n'+net.get('h4').cmd('ping -c 2 100.0.0.20')+'\n')
    log.write('h4 ping ds2 \n'+net.get('h4').cmd('ping -c 2 100.0.0.21')+'\n')
    log.write('h4 ping ds3 \n'+net.get('h4').cmd('ping -c 2 100.0.0.22')+'\n\n\n')
    
	
	
    #Test 6: ping hosts to WS
    log.write('====================================================================================\n')
    log.write('Test 6: ping PbZ_Hosts and PrZ_Hosts -> WS 		>>> Blocked by LB2 \n\n')
    log.write('h1 ping ws1 \n'+net.get('h1').cmd('ping -c 2 100.0.0.40')+'\n')
    log.write('h1 ping ws2 \n'+net.get('h1').cmd('ping -c 2 100.0.0.41')+'\n')
    log.write('h1 ping ws3 \n'+net.get('h1').cmd('ping -c 2 100.0.0.42')+'\n')

    log.write('h2 ping ws1 \n'+net.get('h2').cmd('ping -c 2 100.0.0.40')+'\n')
    log.write('h2 ping ws2 \n'+net.get('h2').cmd('ping -c 2 100.0.0.41')+'\n')
    log.write('h2 ping ws3 \n'+net.get('h2').cmd('ping -c 2 100.0.0.42')+'\n')
	
    log.write('h3 ping ws1 \n'+net.get('h3').cmd('ping -c 2 100.0.0.40')+'\n')
    log.write('h3 ping ws2 \n'+net.get('h3').cmd('ping -c 2 100.0.0.41')+'\n')
    log.write('h3 ping ws3 \n'+net.get('h3').cmd('ping -c 2 100.0.0.42')+'\n')
	
    log.write('h4 ping ws1 \n'+net.get('h4').cmd('ping -c 2 100.0.0.40')+'\n')
    log.write('h4 ping ws2 \n'+net.get('h4').cmd('ping -c 2 100.0.0.41')+'\n')
    log.write('h4 ping ws3 \n'+net.get('h4').cmd('ping -c 2 100.0.0.42')+'\n\n\n')	
	
    
	
	#Test 7: DNS nslookup
    log.write('====================================================================================\n')
    log.write('Test 7: PbZ_Hosts and PbZ_Hosts -> nslookup 		>>> DNS round-robin \n\n')
    log.write('h1 nslookup \n'+net.get('h1').cmd('nslookup kth.se 100.0.0.25')+'\n')
    log.write('h2 nslookup \n'+net.get('h2').cmd('nslookup kth.se 100.0.0.25')+'\n')
    log.write('h3 nslookup \n'+net.get('h3').cmd('nslookup kth.se 100.0.0.25')+'\n')
    log.write('h4 nslookup \n'+net.get('h4').cmd('nslookup kth.se 100.0.0.25')+'\n\n\n')
    
	
    
    #Test 8: WS echo
    log.write('====================================================================================\n')
    log.write('Test 8: PbZ_Hosts and PbZ_Hosts -> echo  \n\n')
    log.write('h1 echo \n'+net.get('h1').cmd('echo abs | netcat 100.0.0.45 80')+'\n')
    log.write('h2 echo \n'+net.get('h2').cmd('echo abs | netcat 100.0.0.45 80')+'\n')
    log.write('h3 echo \n'+net.get('h3').cmd('echo abs | netcat 100.0.0.45 80')+'\n')
    log.write('h4 echo \n'+net.get('h4').cmd('echo abs | netcat 100.0.0.45 80')+'\n\n\n')
    
	    
	
	#Test 9: Test UDP connection
    log.write('====================================================================================\n')
    log.write('Test 9: Test UDP connection   \n\n')
    log.write('Open iperf h1   >>> Successful PrZ to PbZ \n'+net.get('h1').cmd('iperf -s -u -p 1053 &')+'\n')
    log.write('h3 iperf h1 \n'+net.get('h3').cmd('iperf -p 1053 -c 100.0.0.10 -u -t 1')+'\n')
	
    log.write('Open iperf h3   >>> Restricted PbZ to PrZ Blocked by NAPT \n'+net.get('h3').cmd('iperf -s -u -p 1053 &')+'\n')
    log.write('h1 iperf h3 \n'+net.get('h1').cmd('iperf -p 1053 -c 10.0.0.50 -u -t 1')+'\n')
	
    log.write('Open iperf ds1   >>> Successful Through LB1 \n'+net.get('ds1').cmd('iperf -s -u -p 53 &')+'\n')
    log.write('Open iperf ds2   >>> Successful Through LB1 \n'+net.get('ds2').cmd('iperf -s -u -p 53 &')+'\n')
    log.write('Open iperf ds3   >>> Successful Through LB1 \n'+net.get('ds3').cmd('iperf -s -u -p 53 &')+'\n')

    log.write('h2 iperf DNS \n'+net.get('h2').cmd('iperf -p 53 -c 100.0.0.25 -u -t 1')+'\n')
    log.write('h4 iperf DNS \n'+net.get('h4').cmd('iperf -p 53 -c 100.0.0.25 -u -t 1')+'\n\n\n')
    
       
	
	#Test 10: Test TCP connection
    log.write('====================================================================================\n')	
    log.write('Test 10: Test TCP connection   \n\n')
    log.write('Open nc h2   >>> Successful PrZ to PbZ \n'+net.get('h2').cmd('nc -l 1080 &')+'\n')
    log.write('h4 nc h2 \n'+net.get('h4').cmd('nc -v -z -w 2 100.0.0.11 1080 &> /dev/null && echo "Up" || echo "Down"')+'\n')
	
    log.write('Open nc h4   >>> Restricted PbZ to PrZ Blocked by NAPT \n'+net.get('h4').cmd('nc -l 1080 &')+'\n')
    log.write('h2 nc h4 \n'+net.get('h2').cmd('nc -v -z -w 2 10.0.0.51 1080 &> /dev/null && echo "Up" || echo "Down"')+'\n')
	
    log.write('Open nc ws1   >>> Successful Through LB2 \n'+net.get('ws1').cmd('nc -l 80 &')+'\n')
    log.write('Open nc ws2   >>> Successful Through LB2 \n'+net.get('ws2').cmd('nc -l 80 &')+'\n')
    log.write('Open nc ws3   >>> Successful Through LB2 \n'+net.get('ws3').cmd('nc -l 80 &')+'\n')

    log.write('h2 nc DNS \n'+net.get('h2').cmd('nc -v -z -w 2 100.0.0.45 80 &> /dev/null && echo "Up" || echo "Down"')+'\n')
    log.write('h4 nc DNS \n'+net.get('h4').cmd('nc -v -z -w 2 100.0.0.45 80 &> /dev/null && echo "Up" || echo "Down"')+'\n\n\n')
	
	
	
	#Test 11: IDS HTTP PUT and POST Allowed
    log.write('====================================================================================\n')
    log.write('Open Inspector \n'+net.get('insp').cmd('tcpdump -eni insp-eth0 -w insp.pcap &')+'\n\n')
    log.write('Test 11: IDS allows POST & PUT	>>>	Successful  \n\n')
    log.write('h1 POST 100.0.0.45 \n'+net.get('h1').cmd('curl -X POST 100.0.0.45 &')+'\n')
    log.write('h3 POST 100.0.0.45 \n'+net.get('h3').cmd('curl -X POST 100.0.0.45 &')+'\n')
    log.write('h1 PUT  100.0.0.45 \n'+net.get('h1').cmd('curl -X PUT 100.0.0.45 &')+'\n')
    log.write('h3 PUT  100.0.0.45 \n'+net.get('h3').cmd('curl -X PUT 100.0.0.45 &')+'\n\n\n')

	
	
	#Test 12: IDS HTTP PUT Linux and SQL code injection Blocked
    log.write('====================================================================================\n')
    log.write('Test 12: IDS Inspcts PUT	>>>	Linux and SQL code injection Blocked \n\n')
    log.write('h1 PUT cat /var/log/ 100.0.0.45	\n'+net.get('h1').cmd('curl -X PUT -d "cat /var/log/" 100.0.0.45 &')+'\n')
    log.write('h1 PUT cat /etc/passwd 100.0.0.45 \n'+net.get('h1').cmd('curl -X PUT -d "cat /etc/passwd" 100.0.0.45 &')+'\n')
    log.write('h1 PUT INSERT 100.0.0.45 \n'+net.get('h1').cmd('curl -X PUT -d "INSERT" 100.0.0.45 &')+'\n')
    log.write('h1 PUT UPDATE 100.0.0.45 \n'+net.get('h1').cmd('curl -X PUT -d "UPDATE" 100.0.0.45 &')+'\n')
    log.write('h1 PUT DELETE 100.0.0.45 \n'+net.get('h1').cmd('curl -X PUT -d "DELETE" 100.0.0.45 &')+'\n\n\n')
	
	
	
	#Test 13: IDS HTTP other Methods are Blocked
    log.write('====================================================================================\n')
    log.write('Test 13: IDS Inspcts HTTP Methods >>> Blocked \n\n')
    log.write('h4 GET 		\n'+net.get('h4').cmd('curl -X GET 100.0.0.45 &')+'\n')
    log.write('h4 HEAD 		\n'+net.get('h4').cmd('curl -X HEAD 100.0.0.45 &')+'\n')
    log.write('h4 OPTIONS 	\n'+net.get('h4').cmd('curl -X OPTIONS 100.0.0.45 &')+'\n')
    log.write('h4 TRACE 	\n'+net.get('h4').cmd('curl -X TRACE 100.0.0.45 &')+'\n')
    log.write('h4 DELETE 	\n'+net.get('h4').cmd('curl -X DELETE 100.0.0.45 &')+'\n')
    log.write('h4 CONNECT 	\n'+net.get('h4').cmd('curl -X CONNECT 100.0.0.45 &')+'\n')
	
	
	
    net.stop()

start_topo()

