
# mike

L2 FlowEntry

### Example Code

L2controller.py

```
        if(did == 4097):
            self.register_switch(did, "172.16.1.1", "11:11:11:11:11:11", "172.16.1.1", "255.255.255.0", 1, True, True, ev)
```

Registered Flow

```
 cookie=0x2, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,ip,dl_src=11:11:11:11:11:11,nw_dst=172.16.1.0/24 actions=CONTROLLER:65509
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30004,arp,dl_dst=ff:ff:ff:ff:ff:ff,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x1, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30004,ip,dl_dst=11:11:11:11:11:11,nw_dst=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x3, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,arp,dl_dst=11:11:11:11:11:11,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30000,dl_dst=ff:ff:ff:ff:ff:ff actions=FLOOD
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29998,dl_dst=11:11:11:11:11:11 actions=set_field:11:11:11:11:11:11->eth_src,output:3
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29999,ip,nw_dst=172.16.1.0/24 actions=output:3
```

### Arp Request from L3

```
 cookie=0x2, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,ip,dl_src=11:11:11:11:11:11,nw_dst=172.16.1.0/24 actions=CONTROLLER:65509
```

### Register IP Reply from Request
 
```
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30004,arp,dl_dst=ff:ff:ff:ff:ff:ff,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
```

### ICMP to Gateway

```
 cookie=0x1, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30004,ip,dl_dst=11:11:11:11:11:11,nw_dst=172.16.1.1 actions=CONTROLLER:65535
```

### ARP to Gateway
 
```
 cookie=0x3, duration=11.952s, table=0, n_packets=0, n_bytes=0, priority=30005,arp,dl_dst=11:11:11:11:11:11,arp_tpa=172.16.1.1 actions=CONTROLLER:65535
```

### Flood Packet (arp,dhcp,etc...)

```
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=30000,dl_dst=ff:ff:ff:ff:ff:ff actions=FLOOD
```

### Routing Packet to Gateway

```
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29998,dl_dst=11:11:11:11:11:11 actions=set_field:11:11:11:11:11:11->eth_src,output:3
```

### L2 out

```
 cookie=0x0, duration=11.953s, table=0, n_packets=0, n_bytes=0, priority=29999,ip,nw_dst=172.16.1.0/24 actions=output:3
```
