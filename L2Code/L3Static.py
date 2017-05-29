class L3StaticEntry():

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs["datapath"]
        self.host_outport = kwargs["port"]

    def in_to_in(self, src_port, dst_port, src_ipsub, dst_ipsub):  # VM to VM in L3
        parser = self.datapath.ofproto_parser
        # src_ipsub = ('172.16.0.1', '255.255.255.0')
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionOutput(dst_port)]
        self.add_flow(30005, match, actions, 0)
        match = parser.OFPMatch(in_port=dst_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionOutput(src_port)]
        self.add_flow(30005, match, actions, 0)

    def in_vlan_Host(self, src_port, dst_port, src_ipsub, dst_ipsub, vid):  # VM to another Host VM in L3 using VLAN
        # 別ホスト向け vlan 処理 外部機器に対しては宛先macアドレスを処理する機構ができていない
        parser = self.datapath.ofproto_parser
        # src_ipsub = ('172.16.0.1', '255.255.255.0')
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionOutput(dst_port)]
        self.add_flow(30005, match, actions, 0)
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(src_port)]
        self.add_flow(30005, match, actions, 0)

    def in_to_other(self):
        return

    def in_to_global(self):  # NAVT
        return

    def L2_vlan_L2(self, src_port, dst_port, vid):
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port)
        #  vid == 0x000a   #VLAN10
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionOutput(dst_port)]
        self.add_flow(20000, match, actions, 0)
        # return entry
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port)
        # vid == 0x000a   #VLAN10
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(src_port)]
        self.add_flow(20000, match, actions, 0)

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
