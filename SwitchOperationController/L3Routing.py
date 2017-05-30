from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, vlan, arp, ipv4, icmp


class L3RouteEntry():

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs["datapath"]
        self.host_outport = kwargs["port"]
        self.gateway_mac = kwargs["mac"]
        self.method = [self._arp_reply, self._arp_request, self._handle_icmp,
                       self._register_mac, self._register_navt_in, self._register_navt_out]
        self.vlan_to_port = {}
        self.port_to_gvlan = {}
        self.vlan_interface = {}
        self.buffer = {}

    def in_to_in(self, src_port, dst_port, src_ipsub, dst_ipsub):  # VM to VM in L3
        """
        src_port : int
        dst_port : int
        src_ipsub : ('172.16.1.1', '255.255.255.0')
        dst_ipsub : ('172.16.2.1', '255.255.255.0')
        """
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionOutput(dst_port)]
        self.add_flow(0, 30005, match, actions, 0)
        match = parser.OFPMatch(in_port=dst_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionOutput(src_port)]
        self.add_flow(0, 30005, match, actions, 0)

    def in_vlan_Host(self, src_port, dst_port, dst_mac, src_ipsub, dst_ipsub, vid):  # VM to another Host VM in L3 using VLAN
        """
        src_port : int
        dst_port : int
        dst_mac : '11:11:11:11:11:12'
        src_ipsub : ('172.16.1.1', '255.255.255.0')
        dst_ipsub : ('172.16.2.1', '255.255.255.0')
        vid : '0x000a'
        """
        # 別ホスト向け vlan 処理
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(dst_port)]
        self.add_flow(0, 30005, match, actions, 0)
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(src_port)]
        self.add_flow(0, 30005, match, actions, 0)

    def in_to_other(self,  src_port, dst_port, gateway_ip, src_ipsub, dst_ipsub, vid):
        """
        192.168.0.0/16 <---> 192.168.0.0/16
        src_port : int
        dst_port : int
        gateway_ip : '192.168.10.1'
        src_ipsub : ('192.168.1.1', '255.255.255.0')
        dst_ipsub : ('192.168.20.1', '255.255.255.0')
        vid : '0x000a'
        ##################################################
        outer
        table_id = 0 で、宛先ipsubと送信元をマッチし、table_1へ。なかったら、宛先マッチしてコントローラーへ
        table_id = 1 で、宛先ipと送信元ポートをマッチし、dst_macとvlanを書き換える
        internal
        table_id = 0 で、vlanと送信元をマッチし、macとvlanを書き換える
        """
        # register map vlan to port
        self.vlan_to_port[vid] = src_port
        self.vlan_interface[vid] = gateway_ip
        if vid not in self.buffer:
            self.buffer[vid] = {}
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        # packetIn -> ARP request -> register from ARP reply
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPInstructionGotoTable(table_id=1)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        self.add_flow(0, 30004, match, actions, 0)
        # cookie 1 : arp request
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        self.t_add_flow(1, 2, 30000, match, actions, 0)
        # cookie 3 : _register_mac from arp_reply
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst=self.gateway_mac, eth_type=0x0806, arp_tpa=gateway_ip)
        self.add_flow(3, 30000, match, actions, 0)
        # other to in
        actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(src_port)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        self.add_flow(0, 30004, match, actions, 0)

    def in_to_wan(self, src_port, gateway_ip, src_ipsub, dst_ipsub, vid):  # NAVT
        """
        10.0.0.0/8 <---> 192.168.0.0/16
        src_port : int
        gateway_ip : '10.port.0.1'
        src_ipsub : ('10.port.0.0', '255.255.255.0')  変換後のサブネット
        dst_ipsub : ('10.0.0.0', '255.255.255.0')
        vid : '0x000a'   #VLAN10
        """
        # register map vlan to port
        self.vlan_to_port[vid] = src_port
        self.port_to_gvlan[src_port] = vid
        self.vlan_interface[vid] = gateway_ip
        if vid not in self.buffer:
            self.buffer[vid] = {}
        self.port_to_gvlan[src_port] = vid
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        # #############################port + 192.168.0.0/16 -> vlan + 10.0.0.0/8#############################################
        # cookie 4 : _register_navt_in
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac)
        self.add_flow(4, 30000, match, actions, 0)
        # cookie 1 : arp request
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        self.t_add_flow(1, 2, 30000, match, actions, 0)
        # cookie 3 : _register_mac from arp_reply
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst=self.gateway_mac, eth_type=0x0806, arp_tpa=gateway_ip)
        self.add_flow(3, 30000, match, actions, 0)
        # ##############################other to in   10.0.0.0/8 -> port + 192.168.0.0/16######################################
        # cookie 5 : _register_navt_out
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=self.host_outport, eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        self.add_flow(5, 30000, match, actions, 0)

    def in_to_global(self, src_port, gr_mac):
        """
        src_port : int
        gr_mac : '11:11:11:11:11:00'
        """
        # 外側にある global行きのルーターになげる
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionSetField(eth_dst=gr_mac), parser.OFPActionOutput(self.host_outport)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800)
        self.t_add_flow(1, 0, 29999, match, actions, 0)

    def _register_navt_out(self, msg, port, data):
        """
        送信元を書き換えるエントリーを登録する
        このエントリーがない時に、宛先をみてから、コントローラーに送り、この関数を呼び出し登録する
        10.0.0.0/8 orグローバル行きなので宛先は他のサブネット行きを全部マッチしたあとに送る
        """
        parser = self.datapath.ofproto_parser
        pkt = packet.Packet(data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not pkt_ipv4:
            return
        src_ip = pkt_ipv4.src
        vid = self.port_to_gvlan[port]
        # 送信元を書き換えておく
        IpSeg = src_ip.split('.')
        NatIP = "10." + port + "." + IpSeg[2] + "." + IpSeg[3]
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(ipv4_src=NatIP), parser.OFPInstructionGotoTable(table_id=1)]
        match = parser.OFPMatch(in_port=port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_src=src_ip)
        self.add_flow(0, 30001, match, actions, 0)

    def _register_navt_in(self, msg, port, data):
        """
        宛先を書き換えるエントリーを登録する
        このエントリーがない時に、宛先をみてから、コントローラーに送り、この関数を呼び出し登録する
        """
        parser = self.datapath.ofproto_parser
        pkt = packet.Packet(data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not pkt_ipv4:
            return
        dst_ip = pkt_ipv4.dst
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        outport = self.vlan_to_port[vid]
        # 送信元を書き換えておく
        IpSeg = dst_ip.split('.')
        NatIP = "192.168." + IpSeg[2] + "." + IpSeg[3]
        actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(ipv4_src=NatIP), parser.OFPActionOutput(outport)]
        match = parser.OFPMatch(in_port=port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ip)
        self.add_flow(0, 30001, match, actions, 0)

    def _register_mac(self, msg, port, data):
        """
        宛先ipと送信元ポートをマッチしdst_mac・vlan書き換え
        このエントリーがなかったら、まずarp requestを送る
        arp replyが帰ってきた時にこの関数を呼び出す
        """
        pkt = packet.Packet(data)
        pkt_arp = pkt.get_protocol(arp.arp)
        if not pkt_arp:
            return
        if pkt_arp.opcode != arp.ARP_REPLY:
            return
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        dst_ip = pkt_arp.src_ip
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.src), parser.OFPActionOutput(self.host_outport)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ip)
        self.t_add_flow(1, 0, 30001, match, actions, 0)

    def other_to_global(self):
        return

    def register_out_interface(self, gateway_ip, vid, cookie):
        # arp_request がきたら arp_replyをつくるエントリーを登録
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0806, arp_tpa=gateway_ip)
        # cookie 0 : arp reply
        self.add_flow(0, 30000, match, actions, 0)
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=gateway_ip)
        self.add_flow(2, 30000, match, actions, 0)

    def L2_vlan_L2(self, src_port, dst_port, vid):
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port)
        #  vid == 0x000a   #VLAN10
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionOutput(dst_port)]
        self.add_flow(0, 20000, match, actions, 0)
        # return entry
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port)
        # vid == 0x000a   #VLAN10
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(src_port)]
        self.add_flow(0, 20000, match, actions, 0)

    def _arp_reply(self, msg, port, data):
        # ARPリプライを生成する
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            pass
        else:
            return
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        # dst_mac, src_mac, dst_ip, src_ip
        dst_mac = pkt_arp.src_mac
        src_mac = self.gateway_mac
        dst_ip = pkt_arp.src_ip
        src_ip = pkt_arp.dst_ip
        print('ARP Reply : ', src_ip, ' > ', dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac=dst_mac,
                                 dst_ip=dst_ip))
        # パケットを送信する
        self.send_packet(port, vid, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def _arp_request(self, msg, port, data):
        # ARPリクエストを生成する creste from icmp or v4 packet
        pkt = packet.Packet(data)
        src_mac = self.gateway_mac
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not pkt_ipv4:
            return
        dst_ip = pkt_ipv4.dst
        src_ip = pkt_ipv4.src
        # Buffer IDを控えておく
        if dst_ip in self.buffer[vid]:
            self.buffer[vid][dst_ip].append(msg.buffer_id)
        else:
            self.buffer[vid][dst_ip] = [msg.buffer_id]
        print('ARP Request : ', src_ip, ' > ', dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                           dst='ff:ff:ff:ff:ff:ff',
                                           src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac='ff:ff:ff:ff:ff:ff',
                                 dst_ip=dst_ip))
        # パケットを送信する
        self.send_packet(self.gateway_port, vid, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def _handle_icmp(self, msg, port, data):
        # パケットがICMP ECHOリクエストでなかった場合はすぐに返す
        # 自分のゲートウェイIPアドレスをもっているグループでなかったら終了
        pkt = packet.Packet(data)
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            pass
        else:
            return
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST or pkt_ipv4.dst != self.gateway_ip:
            return
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        src_mac = self.gateway_mac
        src_ip = self.gateway_ip
        dst_mac = pkt_ethernet.src
        dst_ip = pkt_ipv4.src
        print('ICMP : ', src_ip, ' >> ', dst_ip)
        # ICMPを作成して返す
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=dst_mac,
                                           src=src_mac))  # ゲートウェイのmac
        pkt.add_protocol(ipv4.ipv4(dst=dst_ip,
                                   src=src_ip,  # ゲートウェイのIP
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self._send_packet(port, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def add_flow(self, cookie, priority, match, actions, idle_timeout):
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
        mod = parser.OFPFlowMod(datapath=self.datapath, priority=priority, cookie=cookie,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        self.datapath.send_msg(mod)

    def t_add_flow(self, table_id, cookie, priority, match, actions, idle_timeout):
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
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=table_id, priority=priority, cookie=cookie,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        self.datapath.send_msg(mod)

    def send_packet(self, port, vid, pkt, buffer_id):
        # 作られたパケットをOut-Packetメッセージ送り送信する
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        # buffer を使う場合は、dataを省略する
        data = pkt.data
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=self.datapath,
                                  buffer_id=buffer_id,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        self.datapath.send_msg(out)
