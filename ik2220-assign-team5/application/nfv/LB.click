


define(

        $iface0      lb2-eth1,
        $iface1      lb2-eth2,					
		
		$Host_side_mac		00:00:00:00:00:44,		// MAC address for LB facing Hosts,
        $Server_side_mac	00:00:00:00:00:66,		// MAC address for LB facing Servers,
		
		$V_IPAddr	100.0.0.45,				// VIP for LB1
      
		$Server1_IPAddr     100.0.0.40,		// servers
		$Server2_IPAddr     100.0.0.41,		// servers
		$Server3_IPAddr     100.0.0.42,		// servers
		
        $servicePort   80,
		$LB_number		2,
    
		$NETWORK    100.0.0.0/24,
		
        $queueSize   2000, 		// Argument for your queue elements (size of the queue)
        $mtuSize     2000,   	// MTU
        $burst       8,      	// This is the number of packets you can transmit/receive at a time (batching)
        $io_method   LINUX,  	// You always use Linux driver
		);
		

AddressInfo(
  Host_area 	$V_IPAddr $NETWORK $Host_side_mac,
  Server_area	$V_IPAddr $NETWORK $Server_side_mac,
  );


// Counters
From_AvgCtr :: AverageCounter;
To_AvgCtr	:: AverageCounter;

arpQ_Ctr	:: Counter;
arpR_Ctr	:: Counter;

service_Ctr :: Counter;
icmp_Ctr	:: Counter;
drop_Ctr	:: Counter;


Host_side_Source	:: FromDevice($iface0, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//LB facing Hosts
Server_side_Source	:: FromDevice($iface1, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//LB facing Servers

Host_side_output	:: Queue($queueSize)																		//LB facing Hosts
											-> IPPrint(LB_Towards_Hosts)										
											-> ToDevice($iface0, METHOD $io_method, BURST $burst); 				
											
Server_side_output	:: Queue($queueSize) 																		//LB facing Servers
											-> To_AvgCtr
											-> IPPrint(LB_Towards_Servers)
											-> ToDevice($iface1, METHOD $io_method, BURST $burst); 	


//---------------------------------Start handling packets---------------------------------//


// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
Host_c0, Server_c0 :: Classifier(
		12/0806 20/0001,
        12/0806 20/0002,
        12/0800,
        -);

LB_ip_classifier :: IPClassifier(
		icmp and dst host $V_IPAddr,
		dst host $V_IPAddr,
		-);
		

//Round Robin Mapper Pattern
RRB :: RoundRobinIPMapper(
		$V_IPAddr - $Server1_IPAddr - 0 1,
		$V_IPAddr - $Server2_IPAddr - 0 1,
		$V_IPAddr - $Server3_IPAddr - 0 1);


iprw :: IPRewriter(RRB, pattern $V_IPAddr - - - 0 1);		
		
		
//"ARP querier" for each interface
Host_side_arpQ		:: ARPQuerier(Host_area); 
Server_side_arpQ	:: ARPQuerier(Server_area); 

//"ARP querier" Handling
Host_dst_ip :: GetIPAddress(16)                        
        -> CheckIPHeader
        -> [0]Host_side_arpQ;
		
Server_dst_ip :: GetIPAddress(16)
		-> CheckIPHeader
        -> [0]Server_side_arpQ;   
		
//"ARP Responder" for each interface
Host_side_arpR 		:: ARPResponder(Host_area);
Server_side_arpR 	:: ARPResponder(Server_area);		

//"ARP Responder" Handling		
Host_side_Source -> From_AvgCtr -> Host_c0;

Host_c0[0] 
		-> Host_side_arpR
		-> arpR_Ctr
		-> Host_side_output;

Server_side_Source -> Server_c0;		
Server_c0[0]
		-> Server_side_arpR
		-> Server_side_output;
				
Host_c0[1]			-> [1]Host_side_arpQ;
Server_c0[1]		-> [1]Server_side_arpQ;

Host_side_arpQ		-> arpQ_Ctr	-> Host_side_output;
Server_side_arpQ	-> Server_side_output;



// Load Blancer towards the Servers
Host_c0[2]
		-> Strip(14)
		-> CheckIPHeader
		-> LB_ip_classifier;

LB_ip_classifier[0] -> icmp_Ctr		-> ICMPPingResponder()  -> Host_dst_ip;				
LB_ip_classifier[1] -> service_Ctr	-> [0]iprw;

				
// Load Blancer towards the Hosts
Server_c0[2]
		-> Strip(14)
		-> CheckIPHeader
		-> [1]iprw;

		
iprw[0] -> Server_dst_ip;
iprw[1] -> Host_dst_ip;


Host_c0[3], Server_c0[3], LB_ip_classifier[2] -> drop_Ctr -> Discard;


//Write Counter in file
DriverManager(wait, print > lb$LB_number.report "

	================== LB"$LB_number "Report =================

	Input Packet rate 	(pps)	: " $(From_AvgCtr.byte_rate)	"
	Output Packet rate	(pps)	: " $(To_AvgCtr.byte_rate)		"
	
	Total # of input packets	: " $(From_AvgCtr.count)		"
	Total # of output packets	: " $(To_AvgCtr.count)			"
	
	Total # of ARP requests		: " $(arpQ_Ctr.count) 			"
	Total # of ARP responses	: " $(arpR_Ctr.count)			"
	
	Total # of service packets	: " $(service_Ctr.count)  		"
	Total # of ICMP packets		: " $(icmp_Ctr.count)			"
	Total # of dropped packets	: " $(drop_Ctr.count)			"
	
	===============================================" , stop);





