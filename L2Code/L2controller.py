from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from .L2Static import L2StaticEntry
from .L2dynamic import L2DynamicEntry


class L2Operation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Operation, self).__init__(*args, **kwargs)
        self.SwichOperation = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(datapath.id)
        self.SwichOperation[str(datapath.id)] = [
            L2StaticEntry(mac="11:11:11:11:11:11",
                          port=3,
                          subnet_ip="172.16.1.1",
                          subnet_mask="255.255.255.0",
                          ev=ev),
            L2DynamicEntry(ip="172.16.1.1",
                           mac="11:11:11:11:11:11",
                           port=3,
                           subnet_ip="172.16.1.1",
                           subnet_mask="255.255.255.0",
                           ev=ev),
        ]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        cookie = msg.cookie
        port = msg.match['in_port']
        data = msg.data
        self.SwichOperation[str(datapath.id)][1].method[cookie](msg, datapath, port, data)
