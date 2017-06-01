from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from L2Internal import L2InEntry
from L2External import L2ExEntry
from L3Routing import L3RouteEntry
import sys


class Operation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Operation, self).__init__(*args, **kwargs)
        self.SwichOperation = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        did = ev.msg.datapath.id
        print(did)
        if(did == 1):
            self.register_swex(datapath, "11:11:11:11:11:11", 1)
            self.SwichOperation[1]["dynamic"].in_to_in(1, 2, ('172.16.1.1', '255.255.255.0'), ('172.16.2.1', '255.255.255.0'))
        if(did == 4097):
            self.register_swin_d(datapath, "172.16.1.1", "11:11:11:11:11:11", "172.16.1.1", "255.255.255.0", 1, True)
            # self.SwichOperation[4097]["static"].register_vm("1a:d0:63:c3:9e:2d", 3)
        if(did == 4098):
            self.register_swin(datapath, "172.16.2.1", "11:11:11:11:11:11", "172.16.2.1", "255.255.255.0", 1, True)
            self.SwichOperation[4098]["static"].register_vm("56:0a:9c:e6:86:3e", 2)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        cookie = msg.cookie
        port = msg.match['in_port']
        data = msg.data
        sys.stdout.write("\n" + str(datapath.id) + "-" + str(cookie) + "-" + str(port) + " : ")
        self.SwichOperation[datapath.id]["dynamic"].method[cookie](msg, port, data)

    def register_swin(self, datapath, ip, mac, subnet_ip, subnet_mask, port, L2out):
        self.SwichOperation[datapath.id] = {
            "static": L2InEntry(datapath=datapath, mac=mac, port=port, subnet_ip=subnet_ip, subnet_mask=subnet_mask, L2out=L2out),
            "dynamic": L2ExEntry(datapath=datapath, ip=ip, mac=mac, port=port, subnet_ip=subnet_ip, subnet_mask=subnet_mask),
        }

    def register_swin_d(self, datapath, ip, mac, subnet_ip, subnet_mask, port, L2out):
        self.SwichOperation[datapath.id] = {
            "dynamic": L2ExEntry(datapath=datapath, ip=ip, mac=mac, port=port, subnet_ip=subnet_ip, subnet_mask=subnet_mask),
        }

    def register_swex(self, datapath, mac, port):
        self.SwichOperation[datapath.id] = {
            "dynamic": L3RouteEntry(datapath=datapath, mac=mac, port=port),
        }

    def register_in_to_in(self, swex_id, swin1_id, swin2_id):
        swin1_port = self.SwichOperation[swin1_id]["dynamic"].gateway_port
        swin1_ipsub = (self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_mask)
        swin2_port = self.SwichOperation[swin2_id]["dynamic"].gateway_port
        swin2_ipsub = (self.SwichOperation[swin2_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin2_id]["dynamic"].gateway_subnet_mask)
        self.SwichOperation[swex_id]["dynamic"].in_to_in(swin1_port, swin2_port, swin1_ipsub, swin2_ipsub)

    def register_in_vlan_Host(self, swex1_id, swin1_id, swex2_id, swin2_id, vid):
        swin1_port = self.SwichOperation[swin1_id]["dynamic"].gateway_port
        swin1_ipsub = (self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_mask)
        swin1_mac = self.SwichOperation[swin1_id]["dynamic"].gateway_mac
        swin2_port = self.SwichOperation[swin2_id]["dynamic"].gateway_port
        swin2_ipsub = (self.SwichOperation[swin2_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin2_id]["dynamic"].gateway_subnet_mask)
        swin2_mac = self.SwichOperation[swin2_id]["dynamic"].gateway_mac
        self.SwichOperation[swex1_id]["dynamic"].in_vlan_Host(swin1_port, swin1_mac, swin1_ipsub, swin2_ipsub, vid)
        self.SwichOperation[swex2_id]["dynamic"].in_vlan_Host(swin2_port, swin2_mac, swin2_ipsub, swin1_ipsub, vid)

    def register_in_to_other(self, swex_id, swin1_id, gateway_ip, dst_ipsub, vid):
        self.SwichOperation[swex_id]["dynamic"].register_out_interface(gateway_ip, vid)
        swin1_port = self.SwichOperation[swin1_id]["dynamic"].gateway_port
        swin1_ipsub = (self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_mask)
        self.SwichOperation[swex_id]["dynamic"].in_to_other(swin1_port, gateway_ip, swin1_ipsub, dst_ipsub, vid)

    def register_in_to_wan(self, swex_id, swin1_id, gateway_ip, dst_ipsub, vid):
        self.SwichOperation[swex_id]["dynamic"].register_out_interface(gateway_ip, vid)
        swin1_port = self.SwichOperation[swin1_id]["dynamic"].gateway_port
        swin1_ipsub = (self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_mask)
        self.SwichOperation[swex_id]["dynamic"].in_to_wan(swin1_port, gateway_ip, swin1_ipsub, dst_ipsub, vid)

    def register_in_to_global(self, swex_id, swin1_id, gateway_ip, dst_ipsub, vid, gr_mac):
        self.SwichOperation[swex_id]["dynamic"].register_out_interface(gateway_ip, vid)
        swin1_port = self.SwichOperation[swin1_id]["dynamic"].gateway_port
        swin1_ipsub = (self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_ip,  self.SwichOperation[swin1_id]["dynamic"].gateway_subnet_mask)
        self.SwichOperation[swex_id]["dynamic"].in_to_wan(swin1_port, gateway_ip, swin1_ipsub, dst_ipsub, vid)
        self.SwichOperation[swex_id]["dynamic"].in_to_global(swin1_port, gr_mac)
