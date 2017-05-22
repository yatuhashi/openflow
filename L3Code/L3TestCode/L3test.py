from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3


class AddFlowEntry(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AddFlowEntry, self).__init__(*args, **kwargs)
        self.gateway_mac = '11:11:11:11:11:11'
        self.gateway_port = 3

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(datapath.id)
        self.tmpl3_entry('172.16.1.1', 1, ev)
        self.tmpl3_entry('172.16.2.1', 2, ev)

    def tmpl3_entry(self, dst_ip, out, ev):  # VM to VM
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_typ=0x0800, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out)]
        self.add_flow(datapath, 29995, match, actions, 0)

    def add_flow(self, datapath, priority, match, actions, idle_timeout):
        """
        datapath : Datapath
        priority : 最大65535 大きいほど優先される
        match : 来たパケットのマッチ条件
        actions : マッチしたパケットをどうするか
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
