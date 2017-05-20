from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


class BAKAHUB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BAKAHUB, self).__init__(*args, **kwargs)
        self.gateway_mac = '11:11:11:11:11:11'
        self.gateway_ip = '172.16.0.1'
        self.gateway_port = 3

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Gateway へのarp
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800, arp_spa=self.gateway_ip)
        self.add_flow(datapath, 1, 0, match, actions, 0)
        # Gateway へのicmp
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=self.gateway_ip)
        self.add_flow(datapath, 2, 0, match, actions, 0)
        # LAN from L3
        match = parser.OFPMatch(eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=('172.16.0.1', '255.255.255.0'))
        self.add_flow(datapath, 3, 0, match, actions, 0)
        # Reply to request LAN from L3
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0800, arp_spa=self.gateway_ip)
        self.add_flow(datapath, 3, 0, match, actions, 0)

    def add_flow(self, datapath, cookie, priority, match, actions, idle_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        cookie = msg.cookie
        print(cookie)
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", dpid, port)
        # ARP処理
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            # ARP情報があった場合、ARPリクエストだった場合はARPリクエストを返す
            self._handle_arp(datapath, port, pkt_ethernet, pkt_arp)
            return
        # ICMP処理
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            # ICMP情報があった場合、ICMPリクエストだった場合はICMPを返す
            self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp)
            return
        # ARP rquest search IP from L3

    def _arp_reply(self, datapath, port, pkt_ethernet, dst_mac, src_mac, dst_ip, src_ip):
        # ARPリプライを生成する
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
        self._send_packet(datapath, port, pkt)

    def _arp_request(self, datapath, port, pkt_ethernet, src_mac, dst_ip, src_ip):
        # ARPリクエストを生成する
        print('ARP Request : ', src_ip, ' > ', dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.dst,
                                           src=pkt_ethernet.src))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac='ff:ff:ff:ff:ff:ff',
                                 dst_ip=dst_ip))
        # パケットを送信する
        self._send_packet(datapath, port, pkt)

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp, SrcGroup):
        # パケットがICMP ECHOリクエストでなかった場合はすぐに返す
        # 自分のゲートウェイIPアドレスをもっているグループでなかったら終了
        print('ICMP : ', pkt_ipv4.src, ' > ', pkt_ipv4.dst)
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST or pkt_ipv4.dst != self.group_mac[SrcGroup][0][0]:
            return
        # ICMPを作成して返す
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.gateway_mac))  # ゲートウェイのmac
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=self.group_mac[SrcGroup][0][0],  # ゲートウェイのIP
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)
