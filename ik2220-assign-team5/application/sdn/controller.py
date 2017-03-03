from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
import os

log = core.getLogger()

_flood_delay = 0
"""
These are the firewall rules, They are totally configurable by adding more IP addresses to the list
ALL is used to allow for all port numbers in one direction
100.0.0.1 represet the IP address of the private zone hosts after NAPT
"""
fw2_rules = [
(['100.0.0.1'],['100.0.0.25', '100.0.0.45','100.0.0.10','100.0.0.11'],'ICMP')
,(['100.0.0.1'],['100.0.0.25'],'UDP','53')
,(['100.0.0.1'],['100.0.0.45'],'TCP','80')
,(['100.0.0.1'],['100.0.0.10','100.0.0.11'],'UDP','ALL')
,(['100.0.0.1'],['100.0.0.10','100.0.0.11'],'TCP','ALL')
]

fw1_rules = [
(['100.0.0.10','100.0.0.11','100.0.0.1'],['100.0.0.25','100.0.0.45','100.0.0.10','100.0.0.11'],'ICMP')
,(['100.0.0.10','100.0.0.11'],['100.0.0.25'],'UDP','53')
,(['100.0.0.10','100.0.0.11'],['100.0.0.45'],'TCP','80')
,(['100.0.0.25', '100.0.0.45','100.0.0.1'],['100.0.0.10','100.0.0.11'],'UDP','ALL')
,(['100.0.0.25', '100.0.0.45','100.0.0.1'],['100.0.0.10','100.0.0.11'],'TCP','ALL')
]

# The learning switch functionality is left as is
class LearningSwitch (object):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    packet = event.parsed
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)

        

class Firewall (object):
  def __init__ (self, connection,fw_rules):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)
    
    # Established sessions
    self.udp_established_sessions = []
    self.tcp_established_sessions = []
    self.icmp_established = []
    
    self.myrules = fw_rules
    self.buffer_id = 0

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    firewall_packet = event.parsed
    
    self.buffer_id = event.ofp.buffer_id
    

    """
    Forward install rule for the packet pointing to the other port. since the firewall has two ports
    the ports has id of (1 and 2)
    """
    def forward():
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(firewall_packet, event.port)
      msg.idle_timeout = 5
      msg.hard_timeout = 15
      msg.actions.append(of.ofp_action_output(port = ((event.port % 2) +1))) 
      msg.data = event.ofp # 6a
      self.connection.send(msg)
    
    """
    ### This was supposed to simplify the code by just installing the opposite direction rules, but I got first
    ### an error regarding the buffer ID and it installs wild card rules instead regardless of my match conditions
    ### which means huge security breach. Instead I am using local buffer 
    def install_opposite_rule():
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.in_port = ((event.port % 2) +1)
      msg.dl_src = firewall_packet.dst
      msg.dl_dst = firewall_packet.src
      msg.nw_src = firewall_packet.payload.dstip
      msg.nw_dst = firewall_packet.payload.srcip
      msg.tp_dst = firewall_packet.payload.payload.srcport
      msg.tp_src = firewall_packet.payload.payload.dstport
      msg.idle_timeout = 5
      msg.hard_timeout = 15
      log.warn(msg.buffer_id)
      msg.actions.append(of.ofp_action_output(port = event.port )) 
      msg.data = event.ofp # 6a
      self.connection.send(msg)
    """
    
    def install_drop_rules():
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(firewall_packet, event.port)
      msg.idle_timeout = 5
      msg.hard_timeout = 15
      msg.buffer_id = event.ofp.buffer_id
      self.connection.send(msg)

    """
    to make this function reusable for ICMP,UDP and TCP this function matches based on IP addresses only
    while part of the matching is done on the other UDP/ICMP/TCP functions.
    this function will return one record only but I left the for loop for now. The first Idea was to do all the 
    matching here and hence the for loop
    """
    def is_pkt_allowed(service_rules):
      for rules in service_rules:
        if(ip_pkt.srcip in rules[0] and ip_pkt.dstip in rules[1]):
          return True
        return False
          
    def pkt_part_of_icmp_session():
      if (ip_pkt.dstip,ip_pkt.srcip) in self.icmp_established :
        return True
      return False
      
    def pkt_part_of_udp_session():
      if ((ip_pkt.dstip,ip_pkt.srcip,ip_pkt.payload.dstport,ip_pkt.payload.srcport)) in self.udp_established_sessions :
        return True
      return False
      
    def pkt_part_of_tcp_session():
      if (ip_pkt.dstip,ip_pkt.srcip,ip_pkt.payload.dstport,ip_pkt.payload.srcport) in self.tcp_established_sessions :
        return True
      return False
      
    def handle_icmp():
      service_rules = [ x for x in self.myrules if x[2] == 'ICMP' ]
      icmp_pkt = ip_pkt.payload
      if (pkt_part_of_icmp_session() and icmp_pkt.type == 0 ):
        forward()
        self.icmp_established.remove((ip_pkt.dstip,ip_pkt.srcip))
      elif (is_pkt_allowed(service_rules) and icmp_pkt.type == 8):
        forward()
        self.icmp_established.append((ip_pkt.srcip,ip_pkt.dstip))
      else:
        install_drop_rules()
        
    def handle_udp():
      service_rules = []
      udp_pkt = ip_pkt.payload
      dport = udp_pkt.dstport;
      service_rules = [ x for x in self.myrules if x[2] == 'UDP' and x[3] == str(dport)]
      if not service_rules:
        service_rules = [ x for x in self.myrules if x[2] == 'UDP' and x[3] == 'ALL']
      if (pkt_part_of_udp_session()):
        forward()
        self.udp_established_sessions.remove((ip_pkt.dstip,ip_pkt.srcip,ip_pkt.payload.dstport,ip_pkt.payload.srcport))
      elif(is_pkt_allowed(service_rules)): 
        forward()
        self.udp_established_sessions.append((ip_pkt.srcip,ip_pkt.dstip,ip_pkt.payload.srcport,ip_pkt.payload.dstport))
        #install_opposite_rule()
      else:
        install_drop_rules()   

    def handle_tcp():
      service_rules = []
      tcp_pkt = ip_pkt.payload
      dport = tcp_pkt.dstport;
      service_rules = [ x for x in self.myrules if x[2] == 'TCP' and x[3] == str(dport)]
      if not service_rules:
        service_rules = [ x for x in self.myrules if x[2] == 'TCP' and x[3] == 'ALL']      
      if (pkt_part_of_tcp_session()):
        forward()
        self.tcp_established_sessions.remove((ip_pkt.dstip,ip_pkt.srcip,ip_pkt.payload.dstport,ip_pkt.payload.srcport))
      elif (tcp_pkt.SYN):
        if(is_pkt_allowed(service_rules)):
          forward()
          self.tcp_established_sessions.append((ip_pkt.srcip,ip_pkt.dstip,ip_pkt.payload.srcport,ip_pkt.payload.dstport))
          #install_opposite_rule()
      else:
        install_drop_rules()
        
    
    if firewall_packet.type == firewall_packet.ARP_TYPE:
      forward()
    elif firewall_packet.type == firewall_packet.IP_TYPE:
        ip_pkt = firewall_packet.payload
        if ip_pkt.protocol == ip_pkt.ICMP_PROTOCOL:
          handle_icmp() # come back later to this partition
        elif ip_pkt.protocol == ip_pkt.TCP_PROTOCOL:  
          handle_tcp()
        elif ip_pkt.protocol == ip_pkt.UDP_PROTOCOL:  
          handle_udp()
        else:
          install_drop_rules()
      

class controller (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    if dpid_to_str(event.dpid)[15] == "0":
        log.warn("Condition executed for the switches")
        LearningSwitch(event.connection, self.transparent)
    if dpid_to_str(event.dpid)[15] == "1":
        if dpid_to_str(event.dpid)[16] == "1":
          Firewall(event.connection, fw1_rules)
        elif dpid_to_str(event.dpid)[16] == "2":
          Firewall(event.connection, fw2_rules)
    if dpid_to_str(event.dpid)[15] == "2":
        if dpid_to_str(event.dpid)[16] == "1":
          os.system("sudo /usr/local/bin/click /opt/ik2220/click/conf/LB.click iface0=lb1-eth2 iface1=lb1-eth1 V_IPAddr=100.0.0.25  Server1_IPAddr=100.0.0.20  Server2_IPAddr=100.0.0.21  Server3_IPAddr=100.0.0.22 Host_side_mac=00:00:00:00:00:55 Server_side_mac=00:00:00:00:00:77 LB_number=1 &")
        elif dpid_to_str(event.dpid)[16] == "2":
          os.system("sudo /usr/local/bin/click /opt/ik2220/click/conf/LB.click &")
    if dpid_to_str(event.dpid)[15] == "3":
        os.system("sudo /usr/local/bin/click /opt/ik2220/click/conf/IDS.click &")
    if dpid_to_str(event.dpid)[15] == "4":
        os.system("sudo /usr/local/bin/click /opt/ik2220/click/conf/NAPT.click &")
		

        
def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(controller, str_to_bool(transparent))
  