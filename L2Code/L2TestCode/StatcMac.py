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
        mac = ''
        out = 1
        self.create_entry(mac, out, ev)
        mac = ''
        out = 2
        self.create_entry(mac, out, ev)
        self.flood_entry(ev)
        self.nomatch_entry(ev)
        self.l3out_entry(ev)

    def create_entry(self, mac, out, ev):  # VM to VM
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=mac)
        actions = [parser.OFPActionOutput(out)]
        self.add_flow(datapath, 30000, match, actions, 0)

    def flood_entry(self, ev):  # Flood
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)]
        self.add_flow(datapath, 30000, match, actions, 0)

    def nomatch_entry(self, ev):  # L2 out
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=('172.16.1.0', '255.255.255.0'))
        actions = [parser.OFPActionOutput(self.gateway_port)]
        self.add_flow(datapath, 29999, match, actions, 0)

    # def l3in_entry(self, mac, ev):  # L3 packet In from Gateway Larning IP
    #     datapath = ev.msg.datapath
    #     parser = datapath.ofproto_parser
    #     match = parser.OFPMatch(eth_src=self.gateway_mac)
    #     rewrite_mac = parser.OFPMatchField.make(ofproto_v1_3.OXM_OF_ETH_DST, haddr_to_bin(mac))
    #     actions = [rewrite_mac, parser.OFPActionOutput(1)]
    #     self.add_flow(datapath, 29999, match, actions, 0)

    def l3out_entry(self, ev):  # L3 packet Out to Gateway
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.gateway_mac)
        actions = [parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(self.gateway_port)]
        self.add_flow(datapath, 29998, match, actions, 0)

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
