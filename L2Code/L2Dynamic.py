from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import ether


class L2DynamicEntry(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs["datapath"]
        self.gateway_ip = kwargs["ip"]
        self.gateway_mac = kwargs["mac"]
        self.gateway_port = int(kwargs["port"])
        self.gateway_subnet_ip = kwargs["subnet_ip"]  # 172.16.0.1
        self.gateway_subnet_mask = kwargs["subnet_mask"]  # 255.255.255.0
        self.method = [self._arp_reply, self._handle_icmp, self._arp_request, self._register_ip]
        self.l3out_entry()
        # 溜まっていったbuffer をいつ消すか？
        self.buffer = {}
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # Gateway へのarp
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0806, arp_tpa=self.gateway_ip)
        self.add_flow(0, 30004, match, actions, 0)
        # Gateway へのicmp
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=self.gateway_ip)
        self.add_flow(1, 30004, match, actions, 0)
        # LAN from L3. remain packet buffer
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        match = parser.OFPMatch(eth_src=self.gateway_mac, eth_dst=self.gateway_mac)
        self.add_flow(2, 30005, match, actions, 0)
        # register Reply to request LAN from L3
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0806, arp_tpa=self.gateway_ip)
        self.add_flow(3, 30005, match, actions, 0)

    def _register_ip(self, msg, port, data):
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        print("Register IP : ", pkt_arp.src_ip, "--", pkt_arp.opcode)
        if pkt_arp:
            pass
        else:
            return
        if pkt_arp.opcode != arp.ARP_REPLY:
            return
        dst_ip = pkt_arp.src_ip
        # 溜まってるbuffer_idのパケットを全部出す
        # for i in self.buffer[dst_ip]:
        #     self._send_packet(datapath, port, pkt, i)
        print("Register IP : ", pkt_ethernet.src, "--", dst_ip)
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=dst_ip)
        actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.src), parser.OFPActionOutput(port)]
        self.add_flow(3, 30006, match, actions, 60)

    def l3out_entry(self):  # L3 packet Out to Gateway
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.gateway_mac)
        actions = [parser.OFPActionSetField(eth_src=self.gateway_mac), parser.OFPActionOutput(self.gateway_port)]
        self.add_flow(0, 29998, match, actions, 0)

    def _arp_reply(self, msg, port, data):
        # ARPリプライを生成する
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
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
        self._send_packet(port, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def _arp_request(self, msg, port, data):
        # ARPリクエストを生成する creste from icmp or v4 packet
        pkt = packet.Packet(data)
        src_mac = self.gateway_mac
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            dst_ip = pkt_ipv4.dst
        else:
            return
        # Buffer IDを控えておく
        if dst_ip in self.buffer:
            self.buffer[dst_ip].append(msg.buffer_id)
        else:
            self.buffer[dst_ip] = [msg.buffer_id]
        src_ip = self.gateway_ip
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
        self._send_packet(ofproto_v1_3.OFPP_FLOOD, pkt, self.datapath.ofproto.OFP_NO_BUFFER)
        self._send_packet(self.gateway_port, pkt, self.datapath.ofproto.OFP_NO_BUFFER)

    def _handle_icmp(self, msg, port, data):
        # パケットがICMP ECHOリクエストでなかった場合はすぐに返す
        # 自分のゲートウェイIPアドレスをもっているグループでなかったら終了
        pkt = packet.Packet(data)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            pass
        else:
            return
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST or pkt_ipv4.dst != self.gateway_ip:
            return
        src_mac = self.gateway_mac
        src_ip = self.gateway_ip
        dst_mac = pkt_ethernet.src
        dst_ip = pkt_ipv4.src
        print('ICMP : ', self.gateway_ip, ' > ', dst_ip)
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
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, cookie=cookie, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        self.datapath.send_msg(mod)

    def _send_packet(self, port, pkt, buffer_id):
        # 作られたパケットをOut-Packetメッセージ送り送信する
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        # buffer を使う場合は、dataを省略する
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=self.datapath,
                                  buffer_id=buffer_id,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        self.datapath.send_msg(out)
