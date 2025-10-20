"""
Intelligent SDN Controller with ML-based Network Anomaly Detection

This module implements a production-ready Software-Defined Networking (SDN) controller
that integrates machine learning-based anomaly detection with advanced risk mitigation
strategies. The controller provides real-time network security monitoring using hybrid
RaNN+LSTM models and implements sophisticated threat response mechanisms.

Key Features:
- Real-time network flow monitoring and analysis
- ML-based anomaly detection using hybrid RaNN+LSTM models
- Risk-based mitigation with escalating response mechanisms
- Comprehensive whitelist/blacklist management
- Honeypot integration for advanced threat detection
- Production-ready error handling and logging
- Administrative interface for security operations

Architecture:
- OpenFlow 1.3 protocol support for switch communication
- Multi-threaded monitoring with configurable intervals
- Intelligent flow direction analysis for accurate threat assessment
- Scalable mitigation management with persistent state tracking

Author: Network Security Team
Version: 1.0 (Production)
Date: 2025
"""

import ssl
import time
import sys
import os

# SSL Context Fix for Production Deployment Stability
# Addresses SSL recursion issues that can occur in containerized environments
if not hasattr(ssl.SSLContext, "_fixed_minimum_version"):
    original_minimum_version = getattr(ssl.SSLContext, 'minimum_version', None)
    
    def safe_get_minimum_version(self):
        """Safe getter for SSL minimum version to prevent recursion"""
        return getattr(self, '_min_version', ssl.TLSVersion.TLSv1_2)
    
    def safe_set_minimum_version(self, value):
        """Safe setter for SSL minimum version with validation"""
        if not isinstance(value, ssl.TLSVersion):
            return
        self._min_version = value
    
    ssl.SSLContext.minimum_version = property(safe_get_minimum_version, safe_set_minimum_version)
    ssl.SSLContext._fixed_minimum_version = True

# Module Path Configuration for Flexible Deployment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib import hub
import logging
import json
import threading
import time
from datetime import datetime
from mitigation_manager import RiskBasedMitigationManager

# ML-based Flow Classification Module with Graceful Fallback
try:
    from flow_classifier import FlowClassifier
    print("✅ Successfully imported FlowClassifier from flow_classifier module")
except ImportError as e:
    print(f"⚠️ FlowClassifier import failed: {e}. Using fallback classifier.")
    
    class FlowClassifier:
        """
        Fallback Flow Classifier for Deployment Resilience
        
        Provides basic anomaly detection capabilities when the main ML classifier
        is unavailable. Uses simple heuristics based on packet rates to maintain
        basic security monitoring functionality during classifier failures.
        """
        
        def classify_flow(self, flow_stats):
            """
            Simple rate-based anomaly detection fallback.
            
            Args:
                flow_stats: OpenFlow statistics object
                
            Returns:
                tuple: (is_anomaly: bool, confidence: float)
            """
            packet_count = getattr(flow_stats, 'packet_count', 0)
            duration_sec = getattr(flow_stats, 'duration_sec', 1)
            
            packets_per_second = packet_count / max(duration_sec, 1)
            if packets_per_second > 200:  # Conservative high-rate threshold
                return True, 0.6
            return False, 0.1

class AnomalyDetectionController(app_manager.RyuApp):
    """
    Production SDN Controller with Intelligent Network Security Monitoring
    
    This controller implements a comprehensive network security solution that combines
    Software-Defined Networking with machine learning-based threat detection. It provides
    real-time monitoring, advanced threat analysis, and automated response mechanisms
    for protecting network infrastructure against sophisticated attacks.
    
    Core Capabilities:
    - OpenFlow 1.3 switch management and flow control
    - Real-time traffic analysis using ML-based anomaly detection
    - Risk-based mitigation with escalating response strategies
    - Intelligent flow direction analysis for accurate threat assessment
    - Comprehensive whitelist/blacklist management
    - Honeypot integration for advanced threat detection
    - Administrative interface for security operations
    
    Security Architecture:
    - Multi-tier defense with configurable risk thresholds
    - Automated blacklisting with exponential timeout escalation
    - Smart server/client traffic differentiation
    - Persistent state management for threat intelligence
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialize the intelligent network security controller.
        
        Sets up the complete security monitoring infrastructure including:
        - ML-based flow classification system
        - Risk-based mitigation management
        - Network topology tracking and learning
        - Security policy enforcement mechanisms
        """
        super(AnomalyDetectionController, self).__init__(*args, **kwargs)
        
        # Core Network Management Components
        self.datapaths = {}  # Active OpenFlow switch connections
        self.mac_to_port = {}  # MAC address to port mapping for learning
        self.mac_to_ip = {}   # MAC to IP address resolution cache
        
        # ML-based Security Analysis System
        self.flow_classifier = FlowClassifier()
        
        # Advanced Risk Management and Mitigation System
        self.mitigation_manager = RiskBasedMitigationManager(
            controller_ref=self,
            low_risk_threshold=0.08,      # Adjusted threshold for low-risk traffic (< 0.08 = ALLOW)
            medium_risk_threshold=0.15,   # Adjusted threshold triggering rate limiting (0.08-0.15 = RATE_LIMIT)
            high_risk_threshold=0.30,     # Adjusted threshold for blocking actions (> 0.30 = BLOCK)
            base_rate_limit_pps=1000,     # Base packet rate limit (packets/second)
            base_rate_limit_bps=1000000,  # Base bandwidth limit (bytes/second)
            base_blacklist_timeout=60,    # Initial blacklist timeout (seconds)
            max_blacklist_timeout=3600    # Maximum blacklist timeout (seconds)
        )
        
        # Real-time Monitoring Infrastructure
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Security Policy Configuration
        # Production whitelist - currently empty for testing purposes
        self.whitelist = set([
            # '10.0.0.1',  # Example: Normal user host
            # '10.0.0.2',  # Example: Web server host
        ])
        self.blacklist = set()  # Dynamic blacklist for malicious sources
        
        # Infrastructure Server Classification
        # Servers are not analyzed as potential attack sources (response traffic)
        self.server_ips = {
            '10.0.0.1',  # h1 - Normal user host (can also run services)
            '10.0.0.2',  # h2 - Web server host
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle new switch connections and perform initial switch configuration.
        
        This method is triggered when a new OpenFlow switch connects to the controller.
        It performs essential initialization including fragment handling configuration,
        table-miss flow installation, and switch registration for monitoring.
        
        Security Initialization:
        - Configures packet fragmentation handling for security analysis
        - Installs default table-miss flow for comprehensive monitoring
        - Registers switch for real-time traffic analysis
        
        Args:
            ev: EventOFPSwitchFeatures containing switch capability information
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"✅ Switch {datapath.id} connected")

        # Configure switch for optimal security monitoring
        # Enable normal fragment handling for complete packet analysis
        datapath.send_msg(parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 65535))

        # Install table-miss flow to ensure all unmatched packets are sent to controller
        # This is critical for comprehensive network monitoring and threat detection
        match = parser.OFPMatch()  # Match all packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)  # Lowest priority (0)

        # Register switch for active monitoring and management
        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Install a flow rule on the specified OpenFlow switch.
        
        This method creates and installs OpenFlow flow modifications for traffic
        control and security enforcement. It supports various priority levels
        for implementing hierarchical security policies and traffic management.
        
        Flow Rule Applications:
        - Security policy enforcement (blocking, rate limiting)
        - Traffic forwarding and learning switch behavior
        - Honeypot traffic redirection
        - Quality of Service (QoS) implementations
        
        Args:
            datapath: Target OpenFlow switch connection
            priority (int): Flow rule priority (higher values take precedence)
            match: OpenFlow match criteria for packet matching
            actions (list): Actions to apply to matching packets
            buffer_id (int, optional): Packet buffer identifier for optimization
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create instruction set for action application
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Build and send flow modification message
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            priority=priority, 
            match=match, 
            instructions=inst,
            buffer_id=(buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER)
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle incoming packets from OpenFlow switches for learning and forwarding.
        
        This method implements intelligent packet processing that combines learning
        switch functionality with network topology discovery for security analysis.
        It processes ARP packets for IP address resolution and establishes forwarding
        rules while maintaining the network state needed for accurate threat detection.
        
        Packet Processing Pipeline:
        1. Extract packet and switch information
        2. Filter out LLDP (topology discovery) traffic
        3. Learn MAC-to-IP mappings from ARP packets for security analysis
        4. Perform MAC address learning for switch forwarding
        5. Install forwarding flows or flood unknown destinations
        6. Send packet out through appropriate port
        
        Args:
            ev: EventOFPPacketIn containing the incoming packet and metadata
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse packet for protocol analysis
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Filter out LLDP topology discovery traffic
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        # Network Learning: Extract MAC-to-IP mappings from ARP traffic
        # This mapping is crucial for correlating Layer 2 and Layer 3 information
        # in security analysis and threat attribution
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self.mac_to_ip[arp_pkt.src_mac] = arp_pkt.src_ip
                self.logger.debug(f"ARP Cache: Learned {arp_pkt.src_mac} -> {arp_pkt.src_ip}")

        # Learning Switch Implementation with Security-aware Flow Installation
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Learn MAC address to port mapping for intelligent forwarding
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        # Determine output port: learned port or flood if unknown
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding flow for known destinations to improve performance
        # and enable flow-based security monitoring
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Forward packet through determined port
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """
        Continuous network monitoring thread for real-time security analysis.
        
        This background thread implements the core monitoring loop that drives
        the security analysis system. It periodically requests flow statistics
        from all connected switches to enable real-time threat detection and
        response. The monitoring frequency is optimized for rapid anomaly
        detection while maintaining system performance.
        
        Monitoring Cycle:
        1. Iterate through all connected OpenFlow switches
        2. Request current flow statistics from each switch
        3. Wait for configured interval before next monitoring cycle
        4. Repeat continuously for real-time security coverage
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)  # Optimized 2-second interval for responsive threat detection

    def _request_stats(self, datapath):
        """
        Request flow statistics from a specific OpenFlow switch.
        
        Sends an OpenFlow flow statistics request to gather current traffic
        information for security analysis. The statistics include packet counts,
        byte counts, flow duration, and match criteria essential for ML-based
        anomaly detection.
        
        Args:
            datapath: Target OpenFlow switch connection for statistics collection
        """
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Core security analysis engine for processing OpenFlow statistics.
        
        This method implements the primary security analysis pipeline that processes
        flow statistics from OpenFlow switches to detect and respond to network threats.
        It applies a multi-tier security framework with ML-based anomaly detection,
        risk assessment, and automated mitigation responses.
        
        Security Analysis Pipeline:
        1. Whitelist Check: Allow pre-approved trusted sources
        2. Blacklist Check: Block known malicious sources immediately
        3. Honeypot Tripwire: Detect and respond to honeypot interactions
        4. Flow Direction Analysis: Distinguish client vs server traffic
        5. ML-based Anomaly Detection: Identify suspicious behavior patterns
        6. Risk-based Mitigation: Apply appropriate security responses
        
        Args:
            ev: EventOFPFlowStatsReply containing flow statistics from switches
        """
        body = ev.msg.body
        flows_to_process = [flow for flow in body if flow.priority == 1]
        
        for stat in sorted(flows_to_process, 
                           key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            source_ip = self._extract_source_ip(stat)
            dest_ip = self._extract_dest_ip(stat)
            
            self.logger.debug(f"\n[FLOW ANALYSIS] Processing: src={source_ip}, dst={dest_ip}, "
                            f"packets={stat.packet_count}, duration={stat.duration_sec}s")

            # === SECURITY TIER 1: WHITELIST VALIDATION ===
            if source_ip and source_ip in self.whitelist:
                self.logger.debug(f"✅ WHITELIST: {source_ip} -> {dest_ip} (packets: {stat.packet_count}) - ALLOWED")
                continue

            # === SECURITY TIER 2: BLACKLIST ENFORCEMENT ===
            elif source_ip and source_ip in self.blacklist:
                self.logger.warning(f"🚫 BLACKLIST: {source_ip} - BLOCKED IMMEDIATELY")
                try:
                    datapath = ev.msg.datapath
                    self.remove_flow(datapath, stat.match)
                except Exception as e:
                    self.logger.error(f"Failed to remove blacklisted flow: {e}")
                continue

            # === SECURITY TIER 3: HONEYPOT TRIPWIRE SYSTEM ===
            elif dest_ip and dest_ip in self.mitigation_manager.honeypot_ips:
                if source_ip:
                    self.logger.info(f"🪤 HONEYPOT INTERACTION: {source_ip} -> {dest_ip} - Attacker observed, traffic allowed")
                    mitigation_action = self.mitigation_manager.risk_based_mitigation(
                        flow_stats=stat,
                        ml_confidence=1.0,
                        source_ip=source_ip,
                        dest_ip=dest_ip
                    )
                    if mitigation_action:
                        self.logger.info(f"🛡️ HONEYPOT LOGGED: {mitigation_action}")
                        # --- Ensure redirected traffic goes to honeypot port 22 ---
                        datapath = ev.msg.datapath
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto
                        match = parser.OFPMatch(ipv4_src=source_ip, ipv4_dst=dest_ip, eth_type=0x0800)
                        actions = [
                            parser.OFPActionSetField(ipv4_dst=dest_ip),
                            parser.OFPActionSetField(tcp_dst=22),
                            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
                        ]
                        self.add_flow(datapath, 10, match, actions)
                    continue
                else:
                    self.logger.error(f"🚨 HONEYPOT HIT: Unable to extract source IP from flow {stat.match}")
                    continue

            # === SECURITY TIER 4: INTELLIGENT FLOW ANALYSIS ===
            # Apply smart flow direction analysis to focus on potential attack vectors
            if not self._should_analyze_flow_for_attacks(source_ip, dest_ip):
                continue  # Skip server response traffic analysis
                
            # === SECURITY TIER 5: ML-BASED RISK ASSESSMENT ===
            else:
                self.logger.debug(f"[ML ANALYSIS] Analyzing flow: packets={stat.packet_count}")
                is_anomaly, confidence = self.flow_classifier.classify_flow(stat)
                self.logger.debug(f"[ML RESULT] Anomaly={is_anomaly}, Confidence={confidence:.4f}")
                
                # ALWAYS process flows through mitigation system, not just anomalies
                if source_ip:
                    self.logger.debug(f"🛡️ PROCESSING FLOW: {source_ip} (ML Confidence: {confidence:.3f})")
                    mitigation_action = self.mitigation_manager.risk_based_mitigation(
                        flow_stats=stat,
                        ml_confidence=confidence,
                        source_ip=source_ip,
                        dest_ip=dest_ip
                    )
                    
                    if mitigation_action:
                        self.logger.info(f"🛡️ MITIGATION APPLIED: {mitigation_action['action']} "
                                       f"for {source_ip} (Risk: {mitigation_action['risk_level']})")
                        
                        # Auto-blacklist for critical threats
                        if (mitigation_action['action'] == 'BLOCK' or 
                            mitigation_action.get('risk_level') == 'critical'):
                            self.blacklist.add(source_ip)
                            self.logger.info(f"🚫 AUTO-BLACKLIST: {source_ip} added due to critical risk")
                    else:
                        self.logger.warning(f"⚠️ MITIGATION FAILED: Unable to apply response for {source_ip}")
                
                # Handle Layer 2 anomalies (MAC-based threats) - only if anomaly detected
                elif is_anomaly:
                    source_mac = self._extract_source_mac(stat)
                    if source_mac and source_mac != '00:00:00:00:00:01':
                        self.logger.info(f"⚠️ L2 ANOMALY: MAC {source_mac} - logging security event")
                        self.mitigation_manager.log_l2_anomaly(
                            source_mac=source_mac,
                            confidence=confidence,
                            flow_stats=stat
                        )
                    elif not source_mac:
                        self.logger.warning("⚠️ UNIDENTIFIED ANOMALY: No source identifier available")
                        self.mitigation_manager.log_unidentified_anomaly(confidence, stat)
                
                # Emergency flow removal for very high confidence threats
                if confidence > 0.9 and source_ip:
                    try:
                        datapath = ev.msg.datapath
                        self.remove_flow(datapath, stat.match)
                        self.logger.info(f"🚫 EMERGENCY BLOCK: Removed high-confidence threat flow")
                    except Exception as e:
                        self.logger.error(f"Failed to remove threat flow: {e}")

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        """
        Handle OpenFlow switch connection state changes.
        
        Manages the dynamic network topology by tracking switch connections
        and disconnections. Maintains accurate switch registry for security
        monitoring and ensures proper cleanup when switches disconnect.
        
        Args:
            ev: EventOFPStateChange containing switch state information
        """
        datapath = ev.datapath
        if ev.state == ofproto_v1_3.OFPPR_DELETE:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.warning(f"❌ SWITCH DISCONNECTED: {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        """
        Handle OpenFlow protocol error messages from switches.
        
        Provides comprehensive error logging for debugging and monitoring
        OpenFlow communication issues. Critical for maintaining reliable
        controller-switch communication in production deployments.
        
        Args:
            ev: EventOFPErrorMsg containing error details from switch
        """
        self.logger.error(f"⚠️ OPENFLOW ERROR: {ev.msg}")

    def _should_analyze_flow_for_attacks(self, source_ip, dest_ip):
        """
        Intelligent flow direction analysis for accurate threat assessment.
        
        This method implements smart traffic analysis logic to distinguish between
        legitimate server response traffic and potential attack vectors. By analyzing
        the direction and context of network flows, it reduces false positives and
        focuses security analysis on genuine threats.
        
        Traffic Classification Logic:
        - Server Response Traffic: Flows from known servers (legitimate responses)
        - Client-to-Server Traffic: Potential attack vectors requiring analysis
        - Lateral Movement: Client-to-client flows indicating potential compromise
        - Unknown Destinations: Suspicious outbound traffic requiring analysis
        
        Args:
            source_ip (str): Source IP address of the flow
            dest_ip (str): Destination IP address of the flow
            
        Returns:
            bool: True if flow requires security analysis, False if it should be ignored
        """
        if not source_ip:
            return False  # Cannot analyze flows without source identification
            
        # Server Response Traffic Analysis
        # Legitimate server responses should not be analyzed as potential attacks
        if source_ip in self.server_ips:
            self.logger.debug(f"🔄 SERVER RESPONSE: {source_ip} -> {dest_ip or 'unknown'} - IGNORED")
            return False
            
        # Client-to-Server Attack Vector Analysis
        # Traffic targeting servers requires comprehensive security analysis
        if dest_ip and dest_ip in self.server_ips:
            self.logger.debug(f"🔍 CLIENT->SERVER: {source_ip} -> {dest_ip} - ANALYZING")
            return True
            
        # Lateral Movement and Unknown Destination Analysis
        # Client-to-client or unknown destination flows may indicate compromise
        self.logger.debug(f"🔍 LATERAL/UNKNOWN: {source_ip} -> {dest_ip or 'unknown'} - ANALYZING")
        return True

    def add_server_ip(self, ip):
        """Add an IP to the server list (won't be analyzed as attack source)"""
        self.server_ips.add(ip)
        self.logger.info(f"📡 Added {ip} to server list - will not be analyzed as attack source")
        
    def remove_server_ip(self, ip):
        """Remove an IP from the server list"""
        if ip in self.server_ips:
            self.server_ips.remove(ip)
            self.logger.info(f"🔄 Removed {ip} from server list - will now be analyzed normally")
        
    def get_server_ips(self):
        """Get current list of server IPs"""
        return set(self.server_ips)

    def _extract_source_ip(self, flow_stat):
        """
        Extract source IP address from OpenFlow statistics with intelligent fallback.
        
        This method implements a multi-tier approach to extract source IP addresses
        from OpenFlow flow statistics, essential for accurate threat attribution and
        security policy enforcement. It uses MAC-to-IP resolution as a fallback for
        Layer 2 flows that lack explicit IP matching.
        
        Extraction Strategy:
        1. Primary: Direct IPv4 source extraction from flow match
        2. Fallback: Alternative match representation handling
        3. Resolution: MAC-to-IP cache lookup for Layer 2 flows
        
        Args:
            flow_stat: OpenFlow flow statistics object
            
        Returns:
            str or None: Source IP address if found, None otherwise
        """
        match = flow_stat.match
        
        # Primary extraction: Direct IPv4 source field access
        if 'ipv4_src' in match:
            return match['ipv4_src']
        
        # Alternative match representation handling
        if hasattr(match, 'get'):
            ip = match.get('ipv4_src')
            if ip:
                return ip

        # Intelligent MAC-to-IP resolution for Layer 2 flows
        mac = self._extract_source_mac(flow_stat)
        if mac and mac in self.mac_to_ip:
            resolved_ip = self.mac_to_ip[mac]
            self.logger.debug(f"MAC Resolution: {mac} -> {resolved_ip}")
            return resolved_ip

        return None

    def _extract_source_mac(self, stat):
        """
        Extract source MAC address from OpenFlow flow statistics.
        
        Provides robust MAC address extraction for Layer 2 traffic analysis
        and network topology learning. Essential for correlating network
        activity when IP-level information is not available.
        
        Args:
            stat: OpenFlow flow statistics object
            
        Returns:
            str or None: Source MAC address if found, None otherwise
        """
        match = stat.match
        
        # Primary MAC extraction from Ethernet source field
        if 'eth_src' in match:
            return match['eth_src']
        
        # Alternative match representation handling
        if hasattr(match, 'get'):
            mac = match.get('eth_src')
            if mac:
                return mac
        
        return None

    def _extract_dest_ip(self, stat):
        """
        Extract destination IP address from OpenFlow flow statistics.
        
        Provides destination IP extraction for security policy enforcement,
        honeypot detection, and network access control. Critical for identifying
        attack targets and implementing protection mechanisms.
        
        Args:
            stat: OpenFlow flow statistics object
            
        Returns:
            str or None: Destination IP address if found, None otherwise
        """
        match = stat.match
        if 'ipv4_dst' in match:
            return match['ipv4_dst']
        if hasattr(match, 'get'):
            return match.get('ipv4_dst')
        return None

    def _resolve_mac_to_ip(self, mac_address):
        """Attempt to resolve MAC address to IP using ARP table or host tracking"""
        # Simple implementation - in production, you'd maintain an ARP table
        # For now, we'll return None to avoid IP-based mitigation for MAC-only flows
        return None

    def remove_flow(self, datapath, match):
        """
        Remove specific flow entries from OpenFlow switches for security enforcement.
        
        This method implements intelligent flow removal for security policy enforcement,
        including blocking malicious traffic, removing compromised flows, and enforcing
        access control policies. It handles complex OpenFlow match field parsing to
        ensure accurate flow identification and removal.
        
        Flow Removal Applications:
        - Blocking identified malicious traffic sources
        - Removing flows for blacklisted IP addresses
        - Enforcing honeypot protection policies
        - Emergency response for high-confidence threats
        
        Args:
            datapath: Target OpenFlow switch connection
            match: OpenFlow match object specifying flows to remove
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Intelligent match field extraction with multiple fallback strategies
        if hasattr(match, 'oxm_fields') and match.oxm_fields:
            match_dict = match.oxm_fields.copy()
        else:
            # Robust field parsing for various OpenFlow match representations
            match_dict = {}
            try:
                for field in match.fields:
                    if hasattr(field, 'header') and hasattr(field, 'value'):
                        if hasattr(field.header, 'type_'):
                            # OpenFlow Extensible Match (OXM) field type mapping
                            oxm_type_map = {
                                0x80000602: 'eth_src',     # Ethernet source address
                                0x80000704: 'eth_dst',     # Ethernet destination address
                                0x80000204: 'in_port',     # Input port number
                                0x80000c04: 'ipv4_src',    # IPv4 source address
                                0x80000e04: 'ipv4_dst'     # IPv4 destination address
                            }
                            
                            if field.header.type_ in oxm_type_map:
                                match_dict[oxm_type_map[field.header.type_]] = field.value
                                
            except Exception as e:
                self.logger.error(f"Error parsing match fields for flow removal: {e}")
                return
        
        # Execute flow removal with comprehensive match criteria
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,  # Delete matching flows
            out_port=ofproto.OFPP_ANY,     # Match any output port
            out_group=ofproto.OFPG_ANY,    # Match any group
            match=parser.OFPMatch(**match_dict)
        )
        datapath.send_msg(mod)
        self.logger.info(f"🚫 FLOW REMOVED: Security enforcement on switch {datapath.id}")

    # ==================== SECURITY ANALYTICS AND MANAGEMENT INTERFACE ====================
    
    def get_risk_analytics(self):
        """
        Retrieve comprehensive network security analytics and threat intelligence.
        
        Provides detailed security metrics, threat patterns, and risk assessments
        for network security operations and incident response activities.
        
        Returns:
            dict: Comprehensive analytics including threat statistics, risk trends,
                 and security posture assessments
        """
        return self.mitigation_manager.get_risk_analytics()
    
    def get_source_analysis(self, source_ip):
        """
        Perform detailed security analysis for a specific network source.
        
        Generates comprehensive threat assessment including historical behavior,
        risk scoring, active mitigations, and recommended security actions.
        
        Args:
            source_ip (str): IP address for detailed analysis
            
        Returns:
            dict: Detailed source analysis including threat history and risk profile
        """
        return self.mitigation_manager.get_source_detailed_analysis(source_ip)
    
    def manual_whitelist_source(self, source_ip, reason="Manual admin action"):
        """
        Manually whitelist a network source for administrative intervention.
        
        Provides emergency override capability for security administrators to
        immediately allow traffic from specific sources during incident response
        or false positive resolution scenarios.
        
        Args:
            source_ip (str): IP address to whitelist
            reason (str): Administrative justification for whitelisting
        """
        self.mitigation_manager.manual_whitelist(source_ip, reason)
        self.logger.info(f"🔧 ADMIN WHITELIST: {source_ip} - {reason}")
    
    def manual_blacklist_source(self, source_ip, duration=3600, reason="Manual admin action"):
        """
        Manually blacklist a network source for immediate threat response.
        
        Enables emergency blocking of malicious sources during active incidents
        or when immediate threat mitigation is required by security operators.
        
        Args:
            source_ip (str): IP address to blacklist
            duration (int): Blacklist duration in seconds
            reason (str): Administrative justification for blacklisting
        """
        self.mitigation_manager.manual_blacklist(source_ip, duration, reason)
        self.logger.warning(f"🔧 ADMIN BLACKLIST: {source_ip} for {duration}s - {reason}")
    
    def remove_all_mitigations(self, source_ip):
        """
        Remove all active security mitigations for a specific source.
        
        Provides comprehensive mitigation clearance for resolving false positives
        or completing incident response activities. Clears all automated and
        manual security controls for the specified source.
        
        Args:
            source_ip (str): IP address to clear all mitigations
            
        Returns:
            dict: Summary of removed mitigations and affected security policies
        """
        removed = self.mitigation_manager.manual_remove_mitigation(source_ip)
        self.logger.info(f"🔧 MITIGATION CLEARED: {source_ip} - {removed}")
        return removed
    
    # ==================== ADMINISTRATIVE SECURITY MANAGEMENT INTERFACE ====================
    
    def admin_add_to_whitelist(self, ip_address, reason="Admin addition"):
        """
        Administrative interface for whitelist management.
        
        Provides secure administrative access to modify network security policies
        with proper logging and validation. Essential for security operations
        and incident response workflows.
        
        Args:
            ip_address (str): IP address to add to whitelist
            reason (str): Administrative justification
            
        Returns:
            tuple: (success: bool, message: str) indicating operation result
        """
        success, message = self.mitigation_manager.admin_add_to_whitelist(ip_address, reason)
        self.logger.info(f"🔧 ADMIN WHITELIST ADD: {message}")
        return success, message
    
    def admin_add_to_blacklist(self, ip_address, duration=3600, reason="Admin addition"):
        """Administrative blacklist management with threat containment."""
        success, message = self.mitigation_manager.admin_add_to_blacklist(ip_address, duration, reason)
        self.logger.warning(f"🔧 ADMIN BLACKLIST ADD: {message}")
        return success, message
    
    def admin_remove_from_whitelist(self, ip_address):
        """Administrative whitelist removal for security policy updates."""
        success, message = self.mitigation_manager.admin_remove_from_whitelist(ip_address)
        self.logger.info(f"🔧 ADMIN WHITELIST REMOVE: {message}")
        return success, message
    
    def admin_remove_from_blacklist(self, ip_address):
        """Administrative blacklist removal for incident resolution."""
        success, message = self.mitigation_manager.admin_remove_from_blacklist(ip_address)
        self.logger.info(f"🔧 ADMIN BLACKLIST REMOVE: {message}")
        return success, message
    
    def admin_add_honeypot(self, ip_address):
        """Administrative honeypot deployment for advanced threat detection."""
        success, message = self.mitigation_manager.admin_add_honeypot(ip_address)
        self.logger.warning(f"🔧 ADMIN HONEYPOT ADD: {message}")
        return success, message
    
    def admin_remove_honeypot(self, ip_address):
        """Administrative honeypot removal for infrastructure changes."""
        success, message = self.mitigation_manager.admin_remove_honeypot(ip_address)
        self.logger.info(f"🔧 ADMIN HONEYPOT REMOVE: {message}")
        return success, message
    
    def admin_clear_all_mitigations(self, ip_address):
        """Comprehensive administrative mitigation clearance for incident resolution."""
        success, message = self.mitigation_manager.admin_clear_all_mitigations(ip_address)
        self.logger.info(f"🔧 ADMIN FULL CLEARANCE: {message}")
        return success, message
    
    def admin_get_ip_status(self, ip_address):
        """
        Retrieve comprehensive security status for administrative analysis.
        
        Returns:
            dict: Complete security profile including all active mitigations,
                 threat history, and current security classifications
        """
        return self.mitigation_manager.admin_get_ip_status(ip_address)
    
    # ==================== SERVER INFRASTRUCTURE MANAGEMENT ====================
    
    def admin_add_server(self, ip_address):
        """Administrative server designation for traffic analysis optimization."""
        self.add_server_ip(ip_address)
        return f"Added {ip_address} to server infrastructure list"
        
    def admin_remove_server(self, ip_address):
        """Administrative server removal for infrastructure updates."""
        self.remove_server_ip(ip_address)
        return f"Removed {ip_address} from server infrastructure list"
        
    def admin_list_servers(self):
        """Retrieve current server infrastructure inventory."""
        return list(self.get_server_ips())
    
    def get_current_ip_lists(self):
        """
        Retrieve comprehensive security policy status.
        
        Returns:
            dict: Complete security policy state including whitelists,
                 blacklists, honeypots, and active mitigations
        """
        return self.mitigation_manager.get_current_lists()
