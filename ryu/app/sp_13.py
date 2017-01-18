from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac,hub
from ryu.controller import dpset
from ryu.lib import dpid as dpid_lib

from ryu.app.sdnhub_apps import host_tracker
from ryu.topology.switches import Switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
import time
from threading import Lock

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'host_tracker':host_tracker.HostTracker,
                 'top_switches':Switches}
 
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
        self.top_switches = kwargs['top_switches']
        self.dpset = kwargs['dpset']
        self.host_tracker = kwargs['host_tracker']
        self.switch_data = {}
        self.port_macs = {}
        self.host_macs = {}
        self.dpdic = {}
        self.desc_request_semaphore = {}
        self.RTT = {}
        self.start_time = {}
        self.datapath_RTT_thread = hub.spawn(self._get_datapath_RTT)
        #self.mon_thread = hub.spawn(self.broadcast_mon_packet)
        #self.link_delay_thread = hub.spawn(self.update_graph_using_delay)
  
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
    
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        dp = ev.datapath
        if dp.id is None:
            return
        if ev.state == MAIN_DISPATCHER:
            self.dpdic[dp.id] = dp
            self.desc_request_semaphore[dp.id] = Lock()
            self.RTT[dp.id] = 0
            self.start_time[dp.id] = 0
            msg = 'Join SW.'
        elif ev.state == DEAD_DISPATCHER:
            ret = self.dpdic.pop(dp.id, None)
            if ret is None:
                msg = 'Leave unknown SW.'
            else:
                msg = 'Leave SW.'
        self.logger.info('dpid=%s : %s %s', dpid_lib.dpid_to_str(dp.id), msg, self.dpdic)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_MON:
            self.handle_mon_packet(eth,datapath)
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        if not eth.ethertype == ether_types.ETH_TYPE_LLDP:
            #print eth            
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            #print self.net[1]
            #print self.net[2]

        #Add to graph
        if src not in self.net and src not in self.port_macs.keys():
            print "Adding new node",src,"to",str(dpid)
            self.host_macs[src] = {'dpid':dpid,'port_no':in_port}
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)

        if dst in self.net:
            self.update_graph_using_delay()
            path=nx.shortest_path(self.net,src,dst,weight = 'delay')              
            self.install_flows_in_path(path,in_port)
            next=path[path.index(dpid)+1]
            out_port=self.net[dpid][next]['port']
        else:
            out_port = ofproto.OFPP_FLOOD
 
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
         
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)
   
    @set_ev_cls(event.EventSwitchEnter)
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
              self.port_macs[port.hw_addr] = {'dpid':dpid,'port_no':port.port_no}
       
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        # links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        # #print links
        # self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()

    def install_flows_in_path(self,path,in_port):
        print "Installing flows in Path:",path
        switch_path = path[1:]
        src = path[0]
        dst = path[-1]
        path_length = len(switch_path) - 1
        in_port = in_port 
        for i in range(path_length):
            cur_node = switch_path[i]
            next_node = switch_path[i+1]
            #print "cur_node:",cur_node,"next_node:",next_node
            out_port=self.net[cur_node][next_node]['port']
            #print out_port
            datapath = self.dpdic[cur_node]
            print "Installing flow rull to %d"%datapath.id
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, in_port, dst, actions)
            if i != path_length -1:
                in_port = self.net[next_node][cur_node]['port']

    # def send_desc_stats_request(self,datapath):
    #     print "sending request"
    #     dpid = datapath.id
    #     self.desc_request_semaphore[dpid].acquire()          
    #     #datapath = self.dpdic[dpid]
    #     ofp_parser = datapath.ofproto_parser
    #     req = ofp_parser.OFPDescStatsRequest(datapath, 0)            
    #     self.logger.debug('desc request')
    #     datapath.send_msg(req)
    #     self.start_time[dpid] = time.time()

    # @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    # def desc_stats_reply_handler(self, ev):
    #     print "got a Reply"
    #     #dpid = ev.datapath.id 
    #     dpid = ev.msg.datapath.id
    #     self.RTT[dpid] = time.time() - self.start_time[dpid]
    #     print "RTT",dpid,self.RTT[dpid]
    #     self.logger.debug('desc reply')
    #     self.desc_request_semaphore[dpid].release()

    def _send_echo_request(self):
        for datapath in self.dpdic.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)
            # Important! Don't send echo request together, Because it will
            # generate a lot of echo reply almost in the same time.
            # which will generate a lot of delay of waiting in queue
            # when processing echo reply in echo_reply_handler.

            hub.sleep(0.05)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        recv_timestamp = time.time()
        try:
            latency = recv_timestamp - eval(ev.msg.data)
            self.RTT[ev.msg.datapath.id] = latency
        except:
            return

    def _get_datapath_RTT(self):
        while True:
            #print "Getting RTT"
            self._send_echo_request()
            hub.sleep(5)

    def create_mon_packet(self,src):
        pkt = packet.Packet()
        eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                      src=src,
                      ethertype=ether_types.ETH_TYPE_MON,timestamp = time.time())
        pkt.add_protocol(eth)
        return pkt

    def broadcast_mon_packet(self):
        while True:
            print self.host_tracker.hosts
            for dp in self.dpdic.values():
                port_addr_dic = self.switch_data[dp.id]
                for port_no in port_addr_dic.keys():
                    src_addr = port_addr_dic[port_no]
                    pkt = self.create_mon_packet(src_addr)
                    self._send_packet(dp,port_no,pkt)
            hub.sleep(5)
    
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def handle_mon_packet(self,eth,datapath):
        print "handle mon called"
        print datapath.id, eth

    def update_graph_using_delay(self):        
        print "Updating graph edge weights"
        links_list = get_link(self.topology_api_app, None)
        all_ports = self.top_switches.ports
        for link in links_list:
            src_port = link.src
            dst_port = link.dst
            lldp_delay = all_ports[src_port].delay
            self.update_link_weight(src_port.dpid,dst_port.dpid,lldp_delay)
    
    def update_link_weight(self,src_dpid,dst_dpid,lldp_delay):
        src_delay = self.RTT[src_dpid]
        dst_delay = self.RTT[dst_dpid]
        link_delay = lldp_delay - src_delay/2 - dst_delay/2

        ## Update Graph weight
        self.net[src_dpid][dst_dpid]['delay'] = max(0,link_delay)