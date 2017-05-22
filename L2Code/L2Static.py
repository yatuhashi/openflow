from ryu.ofproto import ofproto_v1_3


class L2StaticEntry():

    def __init__(self, *args, **kwargs):
        self.gateway_mac = kwargs["mac"]
        self.gateway_port = int(kwargs["port"])
        self.gateway_subnet_ip = kwargs["subnet_ip"]  # 172.16.0.1
        self.gateway_subnet_mask = kwargs["subnet_mask"]  # 255.255.255.0
        self.switch_ev = kwargs["ev"]
        self.flood_entry(self.switch_ev)
        self.nomatch_entry(self.switch_ev)
        self.l3out_entry(self.switch_ev)

    def register_vm(self, mac, port, ev):  # VM to VM
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=mac)
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(datapath, 30000, match, actions, 0)

    def flood_entry(self, ev):  # L2 Flood
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)]
        self.add_flow(datapath, 30000, match, actions, 0)

    def nomatch_entry(self, ev):  # L2 out
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(self.gateway_subnet_ip, self.gateway_subnet_mask))
        actions = [parser.OFPActionOutput(self.gateway_port)]
        self.add_flow(datapath, 29999, match, actions, 0)

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
