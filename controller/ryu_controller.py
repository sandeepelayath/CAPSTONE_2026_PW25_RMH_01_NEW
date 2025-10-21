"""
Intelligent SDN Controller with ML-based Anomaly Detection

Features:
- Real-time OpenFlow 1.3 monitoring
- ML-based anomaly detection (RaNN+LSTM)
- Risk-based mitigation with escalating actions
- Whitelist/Blacklist management
- Honeypot integration
- Administrative interface
- Production-ready logging and error handling
"""

import ssl
import sys
import os
import logging
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib import hub
from mitigation_manager import RiskBasedMitigationManager

# SSL Context Fix for containerized deployment
if not hasattr(ssl.SSLContext, "_fixed_minimum_version"):
    def safe_get_minimum_version(self):
        return getattr(self, "_min_version", ssl.TLSVersion.TLSv1_2)

    def safe_set_minimum_version(self, value):
        if isinstance(value, ssl.TLSVersion):
            self._min_version = value

    ssl.SSLContext.minimum_version = property(safe_get_minimum_version, safe_set_minimum_version)
    ssl.SSLContext._fixed_minimum_version = True

# Module path configuration for flexible deployment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ML-based Flow Classification
try:
    from flow_classifier import FlowClassifier
    print("✅ FlowClassifier loaded")
except ImportError:
    print("⚠️ FlowClassifier import failed. Using fallback classifier.")
    class FlowClassifier:
        def classify_flow(self, flow_stats):
            pps = getattr(flow_stats, 'packet_count', 0) / max(getattr(flow_stats, 'duration_sec', 1), 1)
            return (pps > 200, 0.6 if pps > 200 else 0.1)

class AnomalyDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.mac_to_ip = {}
        self.flow_classifier = FlowClassifier()
        self.mitigation_manager = RiskBasedMitigationManager(
            controller_ref=self,
            low_risk_threshold=0.08,
            medium_risk_threshold=0.15,
            high_risk_threshold=0.30,
            base_rate_limit_pps=1000,
            base_rate_limit_bps=1000000,
            base_blacklist_timeout=60,
            max_blacklist_timeout=3600
        )
        self.whitelist = set()
        self.blacklist = set()
        self.server_ips = set()
        hub.spawn(self._monitor)

    # ---------------- Switch Handling ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto, parser = dp.ofproto, dp.ofproto_parser
        self.logger.info(f"✅ Switch {dp.id} connected")
        dp.send_msg(parser.OFPSetConfig(dp, ofproto.OFPC_FRAG_NORMAL, 65535))
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.datapaths[dp.id] = dp

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        )
        datapath.send_msg(mod)

    def remove_flow(self, datapath, match):
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        match_dict = getattr(match, 'oxm_fields', {}) or {}
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(**match_dict)
        )
        datapath.send_msg(mod)
        self.logger.info(f"🚫 Flow removed on switch {datapath.id}")

    # ---------------- Packet Handling ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg, dp, ofproto, parser = ev.msg, ev.msg.datapath, ev.msg.datapath.ofproto, ev.msg.datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self.mac_to_ip[arp_pkt.src_mac] = arp_pkt.src_ip

        dst, src, dpid = eth.dst, eth.src, dp.id
        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions, msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))

    # ---------------- Monitoring ----------------
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)

    def _request_stats(self, dp):
        dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        for stat in sorted([f for f in ev.msg.body if f.priority == 1], key=lambda f: (f.match['in_port'], f.match['eth_dst'])):
            src_ip, dst_ip = self._extract_source_ip(stat), self._extract_dest_ip(stat)
            if not src_ip:
                continue
            if src_ip in self.whitelist:
                continue
            elif src_ip in self.blacklist:
                self.remove_flow(ev.msg.datapath, stat.match)
                continue
            elif dst_ip in self.mitigation_manager.honeypot_ips:
                self._handle_honeypot_interaction(ev.msg.datapath, stat, src_ip, dst_ip)
                continue
            if not self._should_analyze_flow_for_attacks(src_ip, dst_ip):
                continue
            is_anomaly, confidence = self.flow_classifier.classify_flow(stat)
            self.mitigation_manager.risk_based_mitigation(stat, confidence, src_ip, dst_ip)
            if confidence > 0.9:
                self.remove_flow(ev.msg.datapath, stat.match)

    def _handle_honeypot_interaction(self, dp, stat, src_ip, dst_ip):
        parser, ofproto = dp.ofproto_parser, dp.ofproto
        match = parser.OFPMatch(ipv4_src=src_ip, ipv4_dst=dst_ip, eth_type=0x0800)
        actions = [parser.OFPActionSetField(ipv4_dst=dst_ip),
                   parser.OFPActionSetField(tcp_dst=2222),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(dp, 10, match, actions)

    # ---------------- Helper Methods ----------------
    def _should_analyze_flow_for_attacks(self, src_ip, dst_ip):
        if src_ip in self.server_ips:
            return False
        return True

    def _extract_source_ip(self, stat):
        match = stat.match
        return match.get('ipv4_src') or self.mac_to_ip.get(self._extract_source_mac(stat))

    def _extract_dest_ip(self, stat):
        return stat.match.get('ipv4_dst')

    def _extract_source_mac(self, stat):
        match = stat.match
        return match.get('eth_src')

    # ---------------- Admin Interfaces ----------------
    def admin_add_server(self, ip): self.server_ips.add(ip)
    def admin_remove_server(self, ip): self.server_ips.discard(ip)
    def admin_list_servers(self): return list(self.server_ips)
    def get_risk_analytics(self): return self.mitigation_manager.get_risk_analytics()
    def get_source_analysis(self, ip): return self.mitigation_manager.get_source_detailed_analysis(ip)
    def manual_whitelist_source(self, ip, reason="Manual"): self.mitigation_manager.manual_whitelist(ip, reason)
    def manual_blacklist_source(self, ip, duration=3600, reason="Manual"): self.mitigation_manager.manual_blacklist(ip, duration, reason)
    def remove_all_mitigations(self, ip): return self.mitigation_manager.manual_remove_mitigation(ip)
