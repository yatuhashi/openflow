from ryu.ofproto import ofproto_v1_3


class L2StaticEntry():

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs["datapath"]
        self.gateway_mac = kwargs["mac"]
        self.gateway_port = int(kwargs["port"])
        self.gateway_subnet_ip = kwargs["subnet_ip"]  # 172.16.0.1
        self.gateway_subnet_mask = kwargs["subnet_mask"]  # 255.255.255.0
        self.flood_entry()
        if(kwargs["L2out"]):
            self.nomatch_entry()

    def register_vm(self, mac, port):  # VM to VM
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=mac)
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(30000, match, actions, 0)

    def flood_entry(self):  # L2 Flood
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)]
        self.add_flow(30000, match, actions, 0)

    def nomatch_entry(self):  # L2 out
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(self.gateway_subnet_ip, self.gateway_subnet_mask))
        actions = [parser.OFPActionOutput(self.gateway_port)]
        self.add_flow(29999, match, actions, 0)

    def add_flow(self, priority, match, actions, idle_timeout):
        """
        datapath : Datapath
        priority : 最大65535 大きいほど優先される
        match : 来たパケットのマッチ条件
        actions : マッチしたパケットをどうするか
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        self.datapath.send_msg(mod)
