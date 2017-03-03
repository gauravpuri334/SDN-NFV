


define(

        $iface0      		napt-eth2,				// NAPT facing PrZ
        $iface1      		napt-eth1,				// NAPT facing DemZ
        $inside_mac    		00:00:00:00:00:11,		// MAC address for NAPT facing PrZ,
        $outside_mac    	00:00:00:00:00:22,		// MAC address for NAPT facing DemZ,
		
        $INSIDE_IPAddr    	10.0.0.1,				// Host PrZ
        $OUTSIDE_IPAddr   	100.0.0.1,				// Network DemZ
     
        $INSIDE_NETWORK    	10.0.0.0/24,
        $OUTSIDE_NETWORK    100.0.0.0/24,
     
        $queueSize   2000, 							// Argument for your queue elements (size of the queue)
        $mtuSize     2000,   						// MTU
        $burst       8,      						// This is the number of packets you can transmit/receive at a time (batching)
        $io_method   LINUX,  						// You always use Linux driver
		);


AddressInfo(
			internal 	$INSIDE_IPAddr	$INSIDE_NETWORK	$inside_mac,
			external	$OUTSIDE_IPAddr $OUTSIDE_NETWORK $outside_mac,
			);

			
// Counters
From_AvgCtr :: AverageCounter;
To_AvgCtr	:: AverageCounter;

arpQ_Ctr	:: Counter;
arpR_Ctr	:: Counter;

service_Ctr :: Counter;
icmp_Ctr	:: Counter;
drop_Ctr	:: Counter;
			
			
inside_source 	:: FromDevice($iface0, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//napt-eth2
outside_source 	:: FromDevice($iface1, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//napt-eth1

inside_output 	:: Queue($queueSize) 																		//napt-eth2
										-> IPPrint(NAPT_Towards_PrZ)				
										-> ToDevice($iface0, METHOD $io_method, BURST $burst); 				
										
outside_output 	:: Queue($queueSize) 																		//napt-eth1
										-> To_AvgCtr 
										-> IPPrint(NAPT_Towards_DemZ)
										-> ToDevice($iface1, METHOD $io_method, BURST $burst); 	



//---------------------------------Start handling packets------------------------------//

// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
inside_c0, outside_c0 :: Classifier(
									12/0806 20/0001,
									12/0806 20/0002,
									12/0800,
									-);

inside_ip_classifier, outside_ip_classifier :: IPClassifier(
									icmp,
									tcp,
									udp,
									-);

									
IPRewriterPatterns(to_external_pat1 external 40000-50000 - - ); 
iprw :: IPRewriter(pattern to_external_pat1 0 1, drop);  

pingrw :: ICMPPingRewriter(pattern to_external_pat1 0 1, drop);


// An "ARP querier" for each interface.
inside_querier 	:: ARPQuerier(internal); 
outside_querier :: ARPQuerier(external); 

//"ARP querier" Handling               
to_outside :: GetIPAddress(16)                        
        -> CheckIPHeader
        -> [0]outside_querier;

to_inside :: GetIPAddress(16)                        
        -> CheckIPHeader
        -> [0]inside_querier;


// An "ARP Responder" for each interface.
inside_reponder		:: ARPResponder(internal);
outside_reponder	:: ARPResponder(external);

//"ARP Responder" handling
// packets from PrZ
inside_source           -> From_AvgCtr -> inside_c0;

inside_c0[0]            
                        -> inside_reponder
						-> arpR_Ctr
                        -> inside_output;

// packets from DemZ
outside_source          -> outside_c0;
outside_c0[0]           
                        -> outside_reponder
                        -> outside_output;

inside_c0[1]            -> [1]inside_querier;
outside_c0[1]           -> [1]outside_querier;

inside_querier     		-> arpQ_Ctr -> inside_output;
outside_querier    		-> outside_output;


// NAPT towards the DemZ packets from PrZ
inside_c0[2]       
						-> Strip(14)
						-> CheckIPHeader
						-> inside_ip_classifier;
					     

inside_ip_classifier[1],inside_ip_classifier[2]		-> service_Ctr -> [0]iprw;

inside_ip_classifier[0]	-> icmp_Ctr -> [0]pingrw;


// NAPT towards the PrZ packets from DemZ
outside_c0[2]       
						-> Strip(14)
						-> CheckIPHeader
						-> outside_ip_classifier;
					        

outside_ip_classifier[1],outside_ip_classifier[2]	-> [1]iprw;

outside_ip_classifier[0]-> [1]pingrw;



        
iprw[0]     	-> to_outside;
iprw[1]     	-> to_inside;
pingrw[0]   	-> to_outside;
pingrw[1]   	-> to_inside;


inside_c0[3], outside_c0[3], inside_ip_classifier[3], outside_ip_classifier[3]
				-> drop_Ctr
				-> Discard; 


//Write Counter in file
DriverManager(wait, print > napt.report "

	=================== NAPT Report ===================

	Input Packet rate 	(pps)	: " $(From_AvgCtr.byte_rate)	"
	Output Packet rate	(pps)	: " $(To_AvgCtr.byte_rate)		"
	
	Total # of input packets	: " $(From_AvgCtr.count)		"
	Total # of output packets	: " $(To_AvgCtr.count)			"
	
	Total # of ARP requests		: " $(arpQ_Ctr.count) 			"
	Total # of ARP responses	: " $(arpR_Ctr.count)			"
	
	Total # of service packets	: " $(service_Ctr.count)  		"
	Total # of ICMP packets		: " $(icmp_Ctr.count)			"
	Total # of dropped packets	: " $(drop_Ctr.count)			"
	
	===================================================" , stop);

