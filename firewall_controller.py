from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
import logging
import datetime

class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # ── FIREWALL RULES ──────────────────────────────────────────
        # Block by IP address
        self.blocked_ips = {'10.0.0.4'}

        # Block by MAC address
        self.blocked_macs = set()

        # Block by destination port (e.g., block HTTP port 80)
        self.blocked_ports = {80}

        # Allow list (whitelist overrides block list if needed)
        self.allowed_ips = {'10.0.0.1', '10.0.0.2', '10.0.0.3'}
        # ────────────────────────────────────────────────────────────

        # Set up logging to file
        logging.basicConfig(
            filename='firewall_log.txt',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        self.fw_logger = logging.getLogger('firewall')

    def log_blocked(self, reason, src, dst, extra=''):
        msg = f"[BLOCKED] {reason} | src={src} dst={dst} {extra}"
        self.fw_logger.info(msg)
        self.logger.info(msg)

    def log_allowed(self, src, dst):
        msg = f"[ALLOWED] src={src} dst={dst}"
        self.fw_logger.info(msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a table-miss flow: send unknown packets to controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Switch connected: %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    def drop_flow(self, datapath, priority, match, idle_timeout=10):
        """Install a drop rule (empty actions = drop)."""
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, []
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        # Learn MAC → port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # ── FIREWALL CHECK 1: Block by MAC ───────────────────────────
        if src_mac in self.blocked_macs:
            self.log_blocked("MAC", src_mac, dst_mac)
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac)
            self.drop_flow(datapath, priority=20, match=match)
            return

        # ── FIREWALL CHECK 2: Block by IP / port ─────────────────────
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Block source IP
            if src_ip in self.blocked_ips:
                self.log_blocked("IP", src_ip, dst_ip)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                self.drop_flow(datapath, priority=30, match=match)
                return

            # Block destination port (TCP)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt and tcp_pkt.dst_port in self.blocked_ports:
                self.log_blocked(
                    f"TCP port {tcp_pkt.dst_port}", src_ip, dst_ip,
                    f"dst_port={tcp_pkt.dst_port}"
                )
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=6,
                    tcp_dst=tcp_pkt.dst_port
                )
                self.drop_flow(datapath, priority=25, match=match)
                return

        # ── FORWARDING LOGIC (learning switch) ───────────────────────
        self.log_allowed(src_mac, dst_mac)

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule so future packets don't hit the controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, priority=10, match=match,
                          actions=actions, idle_timeout=30)

        # Send the current packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)