/************************** IDS **************************/


define(

        $iface0      ids-eth1,
        $iface1      ids-eth2,					
        $iface2      ids-eth3,					
		
        $macAddr0    6e:71:6c:d7:b2:a1,		// MAC address for LB1 facing Host,
        $macAddr1    86:83:f5:cb:97:10,		// MAC address for LB1 facing Servers,
        $macAddr2    86:83:f5:cb:97:11,		// MAC address for LB1 facing insp,
				 
        $queueSize   2000, 	 // Argument for your queue elements (size of the queue)
        $mtuSize     2000,   // MTU
        $burst       8,      // This is the number of packets you can transmit/receive at a time (batching)
        $io_method   LINUX,  // You always use Linux driver
);


// Counters
From_AvgCtr		:: AverageCounter;
To_AvgCtr_lb	:: AverageCounter;
To_AvgCtr_insp	:: AverageCounter;

arp_Ctr		:: Counter;
icmp_Ctr		:: Counter;
tcp_Ctr			:: Counter;

service_Ctr 	:: Counter;
drop_Ctr		:: Counter;


src0 :: FromDevice($iface0, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//eth1 towards sw2
src1 :: FromDevice($iface1, METHOD $io_method, BURST $burst, SNAPLEN $mtuSize, SNIFFER false);	//eth2 towards lb2

out0 :: Queue($queueSize)	-> ToDevice($iface0, METHOD $io_method, BURST $burst); 					//eth1 towards sw2
out1 :: Queue($queueSize)
							-> To_AvgCtr_lb
							-> IPPrint(IDS_Towards_LB)
							-> ToDevice($iface1, METHOD $io_method, BURST $burst); 	//eth2 towards lb2
out2 :: Queue($queueSize)
							-> To_AvgCtr_insp
							-> IPPrint(IDS_Towards_INSP)
							-> ToDevice($iface2, METHOD $io_method, BURST $burst); 	//eth3 towards insp


//---------------------------------Start handling packets---------------------------------//


// 0. ARP queries
// 1. ARP replies
// 2. IP
// 3. Other
c0 :: Classifier(
				12/0806,
                12/0800,
                -);

c1 :: IPClassifier(
				icmp,
                syn,
                ack and ip[2:2] < 67,
                fin,
                tcp,
                -);


                
c2 :: Classifier(
                0/505554 143/636174202f6574632f706173737764,					// [0]cat /etc/passwd
                0/505554 143/636174202f7661722f6c6f672f,						// [1]cat /var/log/
                0/505554 142/494e53455254,										// [2]INSERT
                0/505554 142/555044415445,										// [3]UPDATE
                0/505554 142/44454c455445,										// [4]DELETE
                0/504f5354,								                        // [5]HTTP POST
                0/505554,									                    // [6]HTTP PUT
				-);																// [7]
				


//-------------------------Start handling packets--------------------------//


src0	-> From_AvgCtr	-> c0;

c0[0]	-> arp_Ctr		-> out1;

// Handling IP packets
c0[1]
        -> Strip(14)                                                  // Remove Ethernet Header // Use this to get rid of the Ethernet header:
        -> CheckIPHeader[0]                                           // Check IP Header & Push valid IP packets to IPClassifier
        -> c1;

//c0[2]	-> drop_Ctr		-> Discard					                  // Drop non IP or ARP packets
        

c1[0]
		-> Unstrip(14)												  // pass ICMP
		-> icmp_Ctr 
        -> out1;

c1[1],c1[2],c1[3]													  // pass TCP signaling
        -> Unstrip(14)
		-> tcp_Ctr
        -> out1;
		
		
c1[4]
        -> Unstrip(14)
        -> Strip(66)
        -> c2;


c2[0],c2[1],c2[2],c2[3],c2[4],c2[7]  
        -> Unstrip(66)
        -> out2;                                                       // Send to inspection

		
c2[5],c2[6]
        -> Unstrip(66)
		-> service_Ctr
        -> out1;



// trasnapearent from server to host 		
src1    -> out0;


c0[2],c1[5]	-> drop_Ctr		-> Discard					               // Drop non IP or ARP packets // Drop if packet is not ICMP or TCP



//Write Counter in file
DriverManager(wait, print > ids.report "

	=================== IDS Report ===================

	Input Packet rate 		(pps)	: " $(From_AvgCtr.byte_rate)	"
	Output Packet rate		(pps)	: " $(To_AvgCtr_lb.byte_rate)	"
	Instpected Packet rate		(pps)	: " $(To_AvgCtr_insp.byte_rate)	"
	
	Total # of input packets		: " $(From_AvgCtr.count)		"
	Total # of output packets		: " $(To_AvgCtr_lb.count)		"
	Total # of inspected packets		: " $(To_AvgCtr_insp.count)		"
	
	Total # of ARP packets			: " $(arp_Ctr.count) 			"
	Total # of ICMP packets			: " $(icmp_Ctr.count) 			"
	Total # of TCP Signaling packets	: " $(tcp_Ctr.count) 			"
	
	Total # of service packet		: " $(service_Ctr.count)  		"
	Total # of drpped packets		: " $(drop_Ctr.count) 			"
	
	=================================================" , stop);

