from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.controller import dpset

from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
 
class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}
 
    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        self.dpset = kwargs['dpset']
        self.switch_data = {}
        self.macports = {}
  
    # Handy function that lists all attributes in the given object
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))
 
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser      
        match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
        datapath.send_msg(mod)
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
        datapath=datapath, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
        datapath.send_msg(mod)
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
 
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #print "nodes"
        #print self.net.nodes()
        #print "edges"
        #print self.net.edges()
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
               
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)
        if dst in self.net:
            #print (src in self.net)
            #print nx.shortest_path(self.net,1,4)
            #print nx.shortest_path(self.net,4,1)
            #print nx.shortest_path(self.net,src,4)
 
            path=nx.shortest_path(self.net,src,dst)  
            next=path[path.index(dpid)+1]
            out_port=self.net[dpid][next]['port']
        else:
            out_port = ofproto.OFPP_FLOOD
 
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)
 
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)
   
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def get_topology_data(self, ev):    
        #print ev.switch
        switch_list = get_switch(self.topology_api_app, None)
        print "Switch List"
        #print switch_list[0].dp   
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        
        print "**********List of switches"
        for switch in switch_list:
          #self.ls(switch)
          print switch
          #self.nodes[self.no_of_nodes] = switch
          #self.no_of_nodes += 1
          datapath = switch.dp
          dpid = datapath.id
          #print "dpid",dpid
          ports = self.dpset.get_ports(int(dpid))
          self.switch_data[dpid] = {}
          for port in ports:
              self.switch_data[dpid][port.port_no] = port.hw_addr
              self.macports[port.hw_addr] = (dpid,port.port_no)
       
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()
