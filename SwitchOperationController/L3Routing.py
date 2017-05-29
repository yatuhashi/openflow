from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.ofproto import ether


class L3RouteEntry():

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs["datapath"]
        self.host_outport = kwargs["port"]
        self.gateway_mac = kwargs["mac"]
        self.method = [self._arp_reply, self._arp_request, self._handle_icmp, self._register_route, self._register_navt]
        self.vlan_to_port = {}
        self.vlan_interface = {}
        self.buffer = {}

    def in_to_in(self, src_port, dst_port, src_ipsub, dst_ipsub):  # VM to VM in L3
        parser = self.datapath.ofproto_parser
        # src_ipsub = ('172.16.0.1', '255.255.255.0')
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionOutput(dst_port)]
        self.add_flow(30005, match, actions, 0)
        match = parser.OFPMatch(in_port=dst_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionOutput(src_port)]
        self.add_flow(30005, match, actions, 0)

    def in_vlan_Host(self, src_port, dst_port, dst_mac, src_ipsub, dst_ipsub, vid):  # VM to another Host VM in L3 using VLAN
        # 別ホスト向け vlan 処理 外部機器に対しては宛先macアドレスを処理する機構ができていない
        parser = self.datapath.ofproto_parser
        # src_ipsub = ('172.16.0.1', '255.255.255.0')
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(eth_dst=self.dst_mac), parser.OFPActionOutput(dst_port)]
        self.add_flow(30005, match, actions, 0)
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(src_port)]
        self.add_flow(30005, match, actions, 0)

    def in_to_other(self,  src_port, dst_port, gateway_ip, src_ipsub, dst_ipsub, vid):
        # register map vlan to port
        self.vlan_to_port[vid] = src_port
        self.vlan_interface[vid] = gateway_ip
        if vid not in self.buffer:
            self.buffer[vid] = {}
        # 宛先 IP でmacが不明の場合、controllerに飛ばすエントリーを登録
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        # remain buffer  先にvidをつけておくことでarp requestの時に宛先ごとにvid情報を探さなくて済む  ipv4_srcも同様
        # packetIn -> ARP request -> register from ARP reply
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(ipv4_src=gateway_ip), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        # cookie 1 : arp request
        self.add_flow(1, 30004, match, actions, 0)
        # other to in
        actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(src_port)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        self.add_flow(0, 30004, match, actions, 0)

    def in_to_global(self, src_port, dst_port, gateway_ip, src_ipsub, dst_ipsub, vid):  # NAVT
        # register map vlan to port
        self.vlan_to_port[vid] = src_port
        self.vlan_interface[vid] = gateway_ip
        if vid not in self.buffer:
            self.buffer[vid] = {}
        # 宛先 IP でmacが不明の場合、controllerに飛ばすエントリーを登録
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        # remain buffer  先にvidをつけておくことでarp requestの時に宛先ごとにvid情報を探さなくて済む  ipv4_srcも同様
        # packetIn -> ARP request -> register from ARP reply
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(ipv4_src=gateway_ip), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ipsub)
        # cookie 1 : arp request
        self.add_flow(1, 30000, match, actions, 0)
        # other to in   10.0.0.0/8 -> port + 192.168.0.0/16
        actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), in_port=dst_port, eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=src_ipsub)
        self.add_flow(2, 30000, match, actions, 0)

    def _register_navt(self):
        return

    def other_to_global(self):
        return

    def _register_interface(self, gateway_ip, vid, cookie):
        # arp_request を送ったあと arp_replyをうけとる機構
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst=self.gateway_mac, eth_type=0x0806, arp_tpa=gateway_ip)
        # cookie 3 : _register_route
        # cookie 4 : _register_navt
        self.add_flow(cookie, 30000, match, actions, 0)
        # arp_request がきたら arp_replyをつくるエントリーを登録
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid), eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0806, arp_tpa=gateway_ip)
        # cookie 0 : arp reply
        self.add_flow(0, 30000, match, actions, 0)

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
        self.send_packet(ofproto_v1_3.OFPP_FLOOD, vid, pkt, self.datapath.ofproto.OFP_NO_BUFFER)
        self.send_packet(self.gateway_port, vid, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def _register_route(self, msg, port, data):
        # arp reply
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        vid = pkt.get_protocol(vlan.vlan)
        if not vid:
            return
        src_port = self.vlan_to_port[vid]
        print("Register IP : ", pkt_arp.src_ip, "--", pkt_arp.opcode)
        if pkt_arp:
            pass
        else:
            return
        if pkt_arp.opcode != arp.ARP_REPLY:
            return
        dst_ip = pkt_arp.src_ip
        # 溜まってるbuffer_idのパケットを全部出す
        for i in self.buffer[vid][dst_ip]:
            self._send_rewrite_packet(pkt_ethernet.src, port, i)
        self.buffer[vid] = []
        print("Register IP : ", pkt_ethernet.src, "--", dst_ip)
        parser = self.datapath.ofproto_parser
        # port unknown
        match = parser.OFPMatch(in_port=src_port, eth_dst=self.gateway_mac, eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ip)
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vid)), parser.OFPActionSetField(eth_dst=pkt_ethernet.src), parser.OFPActionOutput(port)]
        self.add_flow(0, 30006, match, actions, 120)

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
