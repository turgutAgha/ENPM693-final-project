from struct import *
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
import xml.etree.ElementTree as ET

class InitLearnRules(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(InitLearnRules, self).__init__(*args, **kwargs)
        self.switch_addresses = self._parse_switches('/home/ubuntu/Documents/final_project/lab/sdn.xml')
        self.routing_table = {
            11141120: {
                1: ["10.0.0.0"],
                2: ["10.0.4.0", "10.0.1.0"],
                3: ["10.0.6.0", "10.0.2.0"],
                4: ["10.0.8.0"]
            },
            11141121: {
                1: ["10.0.1.0"],
                2: ["10.0.4.0", "10.0.0.0", "10.0.6.0", "10.0.2.0"],
                3: ["10.0.8.0"],
                4: []
            },
            11141122: {
                1: ["10.0.2.0"],
                2: ["10.0.6.0", "10.0.0.0", "10.0.4.0", "10.0.1.0"],
                3: ["10.0.8.0"],
                4: []
            },
        }
        self.arp_table = {}

    # handler for switches connecting controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        par = dp.ofproto_parser
        act = [par.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
        dp.send_msg(par.OFPFlowMod(datapath=dp, priority=0, match=par.OFPMatch(), instructions=inst))

    # handler for PacketIn requests by switches
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _pkt_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        pkt_eth = pkt.get_protocol(ethernet.ethernet) 
        
        if not pkt_eth:
            return
        
        if dp.id not in self.arp_table:
            self.arp_table[dp.id] = {}

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._arp_in(dp, in_port, pkt_eth, pkt_arp)
        
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
                
        if pkt_icmp:
            self._icmp_in(dp, in_port, pkt_eth, pkt_ipv4, pkt_icmp)
            return
        if pkt_tcp:
            self._tcp_in(dp, in_port, pkt_eth, pkt_ipv4, pkt_tcp, pkt)
            return
            
    # helper function to handle ARP packets
    def _arp_in(self, dp, in_port, pkt_eth, pkt_arp):
        src_ip = pkt_arp.src_ip
        dst_ip = pkt_arp.dst_ip
        par = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id
    
        if in_port not in self.arp_table[dpid]:
            self.arp_table[dpid][in_port] = {}
            self.arp_table[dpid][in_port]['eth'] = [pkt_eth.src]
            self.arp_table[dpid][in_port]['ip'] = [src_ip]
        elif src_ip not in self.arp_table[dpid][in_port]['ip']:
            self.arp_table[dpid][in_port]['eth'].append(pkt_eth.src)
            self.arp_table[dpid][in_port]['ip'].append(src_ip)
        
        if pkt_arp.opcode == arp.ARP_REQUEST:
            print(f"[i] PKT_IN: ARP_REQUEST: {src_ip} -> {dst_ip}")
            for port in self.switch_addresses[dpid]:
                if dst_ip == self.switch_addresses[dpid][port]['ip']:
                    print(f"[i] PKT_OUT: ARP_REPLY")

                    match = par.OFPMatch(in_port=in_port,
                                         eth_type=0x0806,
                                         arp_op=arp.ARP_REQUEST,
                                         eth_src=pkt_eth.src,
                                         arp_tpa=self.switch_addresses[dp.id][in_port]['ip'])
                    act = [par.OFPActionSetField(eth_dst=pkt_eth.src),
                           par.OFPActionSetField(eth_src=self.switch_addresses[dp.id][in_port]['eth']),
                           par.OFPActionSetField(arp_op=arp.ARP_REPLY),
                           par.OFPActionSetField(arp_tha=pkt_eth.src),
                           par.OFPActionSetField(arp_sha=self.switch_addresses[dp.id][in_port]['eth']),
                           par.OFPActionSetField(arp_tpa=src_ip),
                           par.OFPActionSetField(arp_spa=self.switch_addresses[dp.id][in_port]['ip']),
                           par.OFPActionOutput(ofp.OFPP_IN_PORT)]
                    inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
                        
                    dp.send_msg(par.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst))

                    break
            
        elif pkt_arp.opcode == arp.ARP_REPLY:
            print(f"[i] PKT_IN: ARP_REPLY: {src_ip} -> {dst_ip}")
    
    
    # helper function to handle PacketIn requests for ICMP packets
    def _icmp_in(self, dp, in_port, pkt_eth, pkt_ipv4, pkt_icmp):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        
        dpid = dp.id
        
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST and pkt_icmp.type != icmp.ICMP_ECHO_REPLY:
            return
        
        if in_port not in self.arp_table[dpid]:
            self.arp_table[dpid][in_port] = {}
            self.arp_table[dpid][in_port]['eth'] = [pkt_eth.src]
            self.arp_table[dpid][in_port]['ip'] = [src_ip]
        elif src_ip not in self.arp_table[dpid][in_port]['ip']:
            self.arp_table[dpid][in_port]['eth'].append(pkt_eth.src)
            self.arp_table[dpid][in_port]['ip'].append(src_ip)
        
        print(f"[i] ARP TABLE: {self.arp_table}\n")
        
        if pkt_icmp.type == icmp.ICMP_ECHO_REPLY:
            print(f"[i] PKT_IN: ICMP_ECHO_REPLY: {src_ip} -> {dst_ip}")
        
        elif pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            print(f"[i] PKT_IN: ICMP_ECHO_REQUEST: {src_ip} -> {dst_ip}")

            for port in self.switch_addresses[dpid]:
                if dst_ip == self.switch_addresses[dpid][port]['ip']:
                    pkt_icmp_reply = packet.Packet()
                    next_src_ip = self.switch_addresses[dp.id][port]['ip']
                    pkt_icmp_reply.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                                                  dst=pkt_eth.src,
                                                                  src=self.switch_addresses[dpid][in_port]['eth']))
                    pkt_icmp_reply.add_protocol(ipv4.ipv4(dst=src_ip,
                                                          src=next_src_ip,
                                                          proto=pkt_ipv4.proto))
                    pkt_icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                                          code=icmp.ICMP_ECHO_REPLY_CODE,
                                                          csum=0,
                                                          data=pkt_icmp.data))
                    self._pkt_out(dp, in_port, pkt_icmp_reply)
                    print(f"[i] PKT_OUT: ICMP_ECHO_REPLY: {next_src_ip} -> {src_ip}")
                    return
        
        icmp_octets = pkt_ipv4.dst.split('.')
        icmp_octets[-1] = '0'
        icmp_subnet = '.'.join(icmp_octets)
        switch_octets = self.switch_addresses[dpid][in_port]['ip'].split('.')
        switch_octets[-1] = '0'
        sw_subnet = '.'.join(switch_octets)
        
        if icmp_subnet != sw_subnet:
            dst_mac = 'ff:ff:ff:ff:ff:ff'
            out_port = 0
            dpid = dp.id
            
            for port in self.routing_table[dpid]:
                if icmp_subnet in self.routing_table[dpid][port]:
                    out_port = port
                    break

            if out_port == 0:
                print("[x] No route found!")
                return
                
            pkt_icmp_fwd = packet.Packet()    
            if out_port in self.arp_table[dpid] and pkt_ipv4.dst in self.arp_table[dpid][out_port]['ip']:
                index = self.arp_table[dpid][out_port]['ip'].index(pkt_ipv4.dst)
                dst_mac = self.arp_table[dpid][out_port]['eth'][index]
            
            pkt_icmp_fwd.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype, 
                                                        dst=dst_mac, 
                                                        src=self.switch_addresses[dp.id][out_port]['eth']))
            pkt_icmp_fwd.add_protocol(ipv4.ipv4(dst=pkt_ipv4.dst,
                                                src=src_ip,
                                                proto=pkt_ipv4.proto))
            pkt_icmp_fwd.add_protocol(icmp.icmp(type_=pkt_icmp.type,
                                                code=pkt_icmp.code,
                                                csum=0,
                                                data=pkt_icmp.data))
            
            print(f"[i] PKT_OUT: FORWARDED ICMP_ECHO_REQUEST: {src_ip} -> {pkt_ipv4.dst}")
            self._pkt_out(dp, out_port, pkt_icmp_fwd)
            return

    # helper function to handle PacketIn requests for ICMP packets
    def _tcp_in(self, dp, in_port, pkt_eth, pkt_ipv4, pkt_tcp, pkt):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        
        print(f"[i] PKT_IN: TCP: {src_ip}:{pkt_tcp.src_port} -> {dst_ip}:{pkt_tcp.dst_port}")
        
        dpid = dp.id

        if in_port not in self.arp_table[dpid]:
            self.arp_table[dpid][in_port] = {}
            self.arp_table[dpid][in_port]['eth'] = [pkt_eth.src]
            self.arp_table[dpid][in_port]['ip'] = [src_ip]
        elif src_ip not in self.arp_table[dpid][in_port]['ip']:
            self.arp_table[dpid][in_port]['eth'].append(pkt_eth.src)
            self.arp_table[dpid][in_port]['ip'].append(src_ip)
        
        tcp_octets = dst_ip.split('.')
        tcp_octets[-1] = '0'
        tcp_subnet = '.'.join(tcp_octets)
        dst_mac = 'ff:ff:ff:ff:ff:ff'
        out_port = 0
        
        for port in self.routing_table[dpid]:
            if tcp_subnet in self.routing_table[dpid][port]:
                out_port = port
                break

        if out_port == 0:
            print("[x] No route found!")
            return
          
        pkt_tcp_fwd = packet.Packet()

        if out_port in self.arp_table[dpid] and dst_ip in self.arp_table[dpid][out_port]['ip']:
            index = self.arp_table[dpid][out_port]['ip'].index(dst_ip)
            dst_mac = self.arp_table[dpid][out_port]['eth'][index]
        
        pkt_tcp_fwd = packet.Packet()
        pkt_tcp_fwd.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                                    dst=dst_mac,
                                                    src=self.switch_addresses[dp.id][out_port]['eth']))
        pkt_tcp_fwd.add_protocol(ipv4.ipv4(dst=dst_ip,
                                            src=src_ip,
                                            proto=pkt_ipv4.proto))
        pkt_tcp_fwd.add_protocol(tcp.tcp(src_port=pkt_tcp.src_port, dst_port=pkt_tcp.dst_port, seq=pkt_tcp.seq, ack=pkt_tcp.ack,
                                            offset=pkt_tcp.offset, bits=pkt_tcp.bits, window_size=pkt_tcp.window_size, csum=0,
                                            urgent=pkt_tcp.urgent, option=pkt_tcp.option))

        payload = None
        for p in pkt.protocols:
            if isinstance(p, bytes):
                payload = p
                break
        if payload:
            pkt_tcp_fwd.add_protocol(payload)
        
        self._pkt_out(dp, out_port, pkt_tcp_fwd)
        
    # helper function to send PacketOut messages telling a switch what to do with a packet
    def _pkt_out(self, dp, prt, pkt):
        ofp = dp.ofproto
        par = dp.ofproto_parser
        pkt.serialize()
        dp.send_msg(par.OFPPacketOut(datapath=dp,
                                     buffer_id=ofp.OFP_NO_BUFFER,
                                     in_port=ofp.OFPP_CONTROLLER,
                                     actions=[par.OFPActionOutput(port=prt)],
                                     data=pkt.data))
                                     
    
    # helper function to parse switches from the given xml file                                    
    def _parse_switches(self, xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        switch_addresses = {}
        dpid_list = [11141120, 11141121, 11141122]

        for device in root.findall('.//device[@type="router"]'):
            device_id = dpid_list[int(device.get('id'))-1]
            switch_addresses[device_id] = {}

        for link in root.findall('.//link'):
            node_1 = link.get('node1')
            node_2 = link.get('node2')
            
            if len(dpid_list) >= int(node_1):
                dpid_1 = dpid_list[int(node_1)-1]
                iface = link.find('.//iface1')
                interface = {
                    int(iface.get('id'))+1: {
                        'eth': iface.get('mac'),
                        'ip': iface.get('ip4')
                    }
                }

                switch_addresses[dpid_1].update(interface) 
            
            if len(dpid_list) >= int(node_2):
                dpid_2 = dpid_list[int(node_2)-1]
                iface = link.find('.//iface2')
                interface = {
                    int(iface.get('id'))+1: {
                        'eth': iface.get('mac'),
                        'ip': iface.get('ip4')
                    }
                }
                
                switch_addresses[dpid_2].update(interface)

        return switch_addresses
