
# mike

L2 FlowEntry

### 設計思想

スイッチ登録時に各機能を有効にするかを容易にする

#### L2の機能を大きく二つに分けた


* L2Dynamic.py
L3スイッチsw-exに渡す機能(gatewayインターフェースに対する挙動)

* L2Static.py
L2で完結する時に必要な機能(L2を外に引っ張るか否かの機能を含む)  

これら二つをswitchを登録する時に選択可能にする. 以下のコードでは両方の機能を登録している.
```
    def register_switch(self, datapath, did, ip, mac, subnet_ip, subnet_mask, port, L2out, L3):
        self.SwichOperation[did] = {
            "static": L2StaticEntry(datapath=datapath, mac=mac, port=port, subnet_ip=subnet_ip, subnet_mask=subnet_mask, L2out=L2out, L3=L3),
            "dynamic": L2DynamicEntry(datapath=datapath, ip=ip, mac=mac, port=port, subnet_ip=subnet_ip, subnet_mask=subnet_mask),
        }
```

* L2Staticの機能  
引数によって以下の機能の有無を選択可能  
L2out : L2を外に出す機能   
L3 : L3にパケットを出す機能 ( Dynamicに移行予定？  
```
"static": L2StaticEntry(datapath=datapath, mac=mac, port=port, subnet_ip=subnet_ip, s    ubnet_mask=subnet_mask, L2out=L2out, L3=L3)
```

* 任意のタイミングでFlowをスイッチに書き込むために各スイッチのインスタンスにdatapathを持たせている。このdatapathに各スイッチへのソケットなどの接続情報が入っているため。  

この実装より、
```
self.SwichOperation[4097]["static"].register_vm("1a:d0:63:c3:9e:2d", 3)
```
など、スイッチのIDより、最初の通信以降で、任意のタイミングでスイッチの操作が可能になる。  

* PacketInに対して、動的に各処理を選択する。SwitchのID、ヒットしたエントリーのcookieより、処理を選択できる。

```
self.SwichOperation[datapath.id]["dynamic"].method[cookie](msg, port, data)
```


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
