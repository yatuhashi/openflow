from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class BAKAHUB(app_manager.RyuApp):
    # OpenFlowのバージョン指定
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # 初期化
    def __init__(self, *args, **kwargs):
        super(BAKAHUB, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}

    # 初期エントリ追加
    # ryu.controller.handler.CONFIG_DISPATCHER : SwitchFeaturesメッセージの受信待ち
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # OpenFlowスイッチとの実際の通信処理や受信メッセージに対応したイベントの発行など
        datapath = ev.msg.datapath
        # 使用しているOpenFlowバージョンに対応したofprotoモジュールを示します
        ofproto = datapath.ofproto
        # ofprotoと同様に、ofproto_parserモジュール
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        # アクションの指定・どのエントリにもマッチしなかった場合コントローラーにPacket-Inを送る
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # 送信処理を行う
        self.add_flow(datapath, 0, match, actions, 0)

    # フローエントリ追加メッセージ送信処理
    def add_flow(self, datapath, priority, match, actions, idle_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # Packet-Inメッセージが届いた時の処理
    # ryu.controller.handler.MAIN_DISPATCHER : 通常状態
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Packet-Inメッセージから届いたデータを取り出していく
        msg = ev.msg
        # ryu.controller.controller.py
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # 自分の情報を書き出す
        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # 自分のがいるポートを[自分のスイッチ][自分のmacアドレス]に登録する
        self.mac_to_port[dpid][src] = in_port
        print(self.mac_to_port)

        # コントローラーが持っているmacテーブルと照合する
        # どこのポートに送るか決める, 見つかってなければ FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # 見つけた宛先ポートをアクションに追加
        actions = [parser.OFPActionOutput(out_port)]

        # 宛先ポートがFloodになっていなければ、新しくエントリを追加し、次回からの処理を任せる
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # 30秒間エントリにマッチする通信が行われなかった場合は自動的に消える
            self.add_flow(datapath, 1, match, actions, 30)

        # 最後に未知だったパケットをどう処理するのか教えてあげる
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        # Packet-Outメッセージの送信
        datapath.send_msg(out)
