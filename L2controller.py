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


class L2C(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2C, self).__init__(*args, **kwargs)
        self.gateway_mac = '11:11:11:11:11:11'
        self.gateway_ip = '172.16.1.254'
        self.gateway_port = 3
        self.method = [self._arp_reply, self._handle_icmp, self._arp_request]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # Gateway へのarp
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800, arp_spa=self.gateway_ip)
        self.add_flow(datapath, 0, 30000, match, actions, 0)
        # Gateway へのicmp
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0800, ipv4_dst=self.gateway_ip)
        self.add_flow(datapath, 1, 30000, match, actions, 0)
        # LAN from L3
        match = parser.OFPMatch(eth_src=self.gateway_mac, eth_type=0x0800, ipv4_dst=(self.gateway_ip, '255.255.255.0'))
        self.add_flow(datapath, 2, 30005, match, actions, 0)
        # register Reply to request LAN from L3
        match = parser.OFPMatch(eth_dst=self.gateway_mac, eth_type=0x0800, arp_spa=self.gateway_ip)
        self.add_flow(datapath, 3, 30005, match, actions, 0)

    def add_flow(self, datapath, cookie, priority, match, actions, idle_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        # 作られたパケットをOut-Packetメッセージ送り送信する
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        cookie = msg.cookie
        port = msg.match['in_port']
        data = msg.data
        print("ck : ", cookie)
        self.method[cookie](datapath, port, data)

    def _arp_reply(self, datapath, port, data):
        # ARPリプライを生成する
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt.get_protocol(arp.arp):
            return
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        # dst_mac, src_mac, dst_ip, src_ip
        dst_mac = pkt_arp.src_mac
        src_mac = self.gateway_mac
        dst_ip = pkt_arp.dst_ip
        src_ip = pkt_arp.src_ip
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

    def _arp_request(self, datapath, port, data):
        # ARPリクエストを生成する creste from icmp or v4 packet
        pkt = packet.Packet(data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        src_mac = self.gateway_mac
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            dst_ip = pkt_ipv4.dst_ip
        else:
            return
        src_ip = self.gateway_ip
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
        self._send_packet(datapath, ofproto_v1_3.OFPP_FLOOD, pkt)

    def _handle_icmp(self, datapath, port, data):
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
        dst_ip = pkt_ipv4.src_ip
        print('ICMP : ', pkt_ipv4.src, ' > ', pkt_ipv4.dst)
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
        self._send_packet(datapath, port, pkt)
