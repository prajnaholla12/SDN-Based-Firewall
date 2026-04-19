from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # RULES
        self.block_ip = "10.0.0.4"                   # h4
        self.block_mac = "00:00:00:00:00:02"         # h2
        self.block_port = 22                         # SSH

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=[
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]
        ))

        print("Switch connected: 1")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # Ignore IPv6
        if eth.ethertype == 0x86DD:
            return

        # Ignore multicast noise
        if dst.startswith("33:33"):
            return

        # MAC BLOCK (ANY → h2)
        if dst == self.block_mac or src == self.block_mac:
            print(f"[BLOCKED MAC] {src} -> {dst}")
            return

        # Learning switch
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            #ICMP BLOCK (ANY → h4)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and dst_ip == self.block_ip:
                print(f"[BLOCKED ICMP] {src_ip} -> {dst_ip}")
                return

            # TCP PORT BLOCK (ANY → ANY on port 22)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt and tcp_pkt.dst_port == self.block_port:
                print(f"[BLOCKED TCP] {src_ip} -> {dst_ip} PORT {tcp_pkt.dst_port}")
                return

        # NORMAL FORWARDING
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=[
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)
                ],
                idle_timeout=5
            ))

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        ))
