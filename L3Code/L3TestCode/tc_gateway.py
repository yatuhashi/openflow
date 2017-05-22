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


class GateWay(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(GateWay, self).__init__(*args, **kwargs)
        # ゲートウェイのMacアドレス
        self.gateway_mac = '0a:e4:1c:d1:3e:44'
        # ポートがポートVLANなのかトランクVLANなのか  True = トランク
        self.port_vlan = {'1': False, '2': False, '3': False}
        # チームごとのポートグループ
        self.group_port = {"T1": [1, 2], "T2": [3]}
        # そのチームのトランク用のVLAN
        self.group_vlan = {"T1": 100, "T2": 200}
        # チームごとのIP,Macとそれが所属しているポート
        self.group_mac = {"T1": [['172.16.0.1', '0a:e4:1c:d1:3e:44', 0]], "T2": [['172.16.1.1', '0a:e4:1c:d1:3e:44', 0]]}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(datapath.id, ': 1')
        # if(datapath.id != 1):
        #    return
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='172.16.0.3')
        out_port = 2
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 30000, match, actions, 0)

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='172.16.0.2')
        out_port = 1
        actions = [parser.OFPActionOutput(out_port)]
        print(datapath.id)
        self.add_flow(datapath, 30001, match, actions, 0)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # バッファしないでコントローラーに送るエントリーを追加
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)
        print('Initialze End')

    # フローエントリ追加メッセージ送信処理
    def add_flow(self, datapath, priority, match, actions, idle_timeout):
        """
        datapath : Datapath
        priority : 最大65535 大きいほど優先される
        match : 来たパケットのマッチ条件
        actions : マッチしたパケットをどうするか
        idle_timeout : 登録したフローエントリがマッチしなくなってから消える時間,0だと消えない
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # インストラクションを設定する
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        # フローエントリを追加する
        datapath.send_msg(mod)

    # スイッチが聞きに来た時
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # そのパケットが来たポート
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        # self.logger.info("packet-in %s" % (pkt,))
        # Macアドレス情報
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        # 送信元ポートで判断する トランクの時は複数のグループが入る
        SrcGroup = [i for i in self.group_port if port in self.group_port[i]]
        # 登録されていないおかしなポートから来たら破棄
        if len(SrcGroup) == 0:
            return
        # トランクポートの時にどこのチームVLANに所属しているかを確認する
        # if self.port_vlan[port] is not False:
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        # SrcVlan = parser.
        # ここでグループが一つになっているはず
        # SrcGroup = [i for i in self.group_vlan if i is SrcVlan]
        SrcGroup = SrcGroup[0]
        # Arp情報
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            # ARP情報があった場合、ARPリクエストだった場合はARPリクエストを返す
            self._handle_arp(datapath, port, pkt_ethernet, pkt_arp, SrcGroup)
            return
        # IP情報を取得する
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            # ICMP情報があった場合、ICMPリクエストだった場合はICMPを返す
            self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp, SrcGroup)
            return

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp, SrcGroup):
        # 送信元Mac,IPアドレスがすでに登録されているか探す
        SrcIP = [i for i in self.group_mac[SrcGroup] if pkt_arp.src_ip == i[0]]
        # なかった場合は登録する
        if len(SrcIP) == 0:
            self.group_mac[SrcGroup].append([pkt_arp.src_ip, pkt_arp.src_mac, port])
        # 宛先IPを探す
        DstIPMAC = [i for i in self.group_mac[SrcGroup] if i[0] == pkt_arp.dst_ip]
        print('DstIPMAC :', DstIPMAC)
        # パケットがARPリクエストの場合の処理
        if pkt_arp.opcode == arp.ARP_REQUEST:
            if len(DstIPMAC) == 0:
                # IPがなかった時はFlood処理をしてあげる
                for port in self.group_port[SrcGroup]:
                    self._arp_request(datapath, port, pkt_ethernet, pkt_arp.src_mac, pkt_arp.dst_ip, pkt_arp.src_ip, SrcGroup)
                return
            else:
                DstIPMAC = DstIPMAC[0]
                # IPを知っている場合は代わりにarpリプライを返す
                # ゲートウェイに対するARPリクエストもARPリプライを返してあげる
                self._arp_reply(datapath, port, pkt_ethernet, pkt_arp.src_mac, DstIPMAC[1], pkt_arp.src_ip, DstIPMAC[0], SrcGroup)
                return
        # パケットがARPリプライの場合の処理
        # L3のreply先がゲートウェイである場合は返す必要がない
        if pkt_arp.opcode == arp.ARP_REPLY and pkt_arp.dst_mac != self.gateway_mac:
            # ARPリプライで学習されているはずなのに宛先が見つからないおかしなパケットの処理
            if len(DstIPMAC) == 0:
                return
            DstIPMAC = DstIPMAC[0]
            # ARPリプライの場合すでに宛先は学習されている
            self._arp_reply(datapath, DstIPMAC[2], pkt_ethernet, pkt_arp.dst_mac, pkt_arp.src_mac, pkt_arp.dst_ip, pkt_arp.src_ip, SrcGroup)
            return
        return

    def _arp_reply(self, datapath, port, pkt_ethernet, dst_mac, src_mac, dst_ip, src_ip, SrcGroup):
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
        # 送るportがSrcGroupによってどのVLANがつくかどうか調べてあげる必要がある
        self._send_packet(datapath, port, pkt)

    def _arp_request(self, datapath, port, pkt_ethernet, src_mac, dst_ip, src_ip, DstGroup):
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
        # 送るportがDstGroupによってどのVLANがつくかどうか調べてあげる必要がある
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
