
# mike
L2 FlowEntry


###Example

```
        if(datapath.id==4097):
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
```

```
 cookie=0x2, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,ip,dl_src=11:11:11:11:11:11,nw_dst=172.16.1.0/24 actions=CONTROLLER:65509
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30004,arp,dl_dst=ff:ff:ff:ff:ff:ff,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x1, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30004,ip,dl_dst=11:11:11:11:11:11,nw_dst=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x3, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,arp,dl_dst=11:11:11:11:11:11,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30000,dl_dst=ff:ff:ff:ff:ff:ff actions=FLOOD
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29998,dl_dst=11:11:11:11:11:11 actions=set_field:11:11:11:11:11:11->eth_src,output:3
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29999,ip,nw_dst=172.16.1.0/24 actions=output:3
```

