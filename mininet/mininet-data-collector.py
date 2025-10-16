import time
import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3
import pandas as pd
import numpy as np
from collections import defaultdict

class FlowStatisticsCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowStatisticsCollector, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('FlowStatisticsCollector')
        self.logger.setLevel(logging.INFO)
        
        # Flow tracking structures
        self.flows = defaultdict(lambda: {
            'fwd_packets': [],
            'bwd_packets': [],
            'fwd_bytes': [],
            'bwd_bytes': [],
            'fwd_timestamps': [],
            'bwd_timestamps': [],
            'fwd_flags': [],
            'bwd_flags': [],
            'start_time': time.time(),
            'last_update': time.time()
        })
        
        # Set stats request interval (in seconds)
        self.stats_request_interval = 5
        self.datapaths = {}
        
        # Start periodic stats collection
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info("FlowStatisticsCollector initialized")
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if datapath.id not in self.datapaths:
            self.logger.info(f'Registered datapath: {datapath.id}')
            self.datapaths[datapath.id] = datapath
    
    def _monitor(self):
        """Periodically request flow stats from switches"""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.stats_request_interval)
            
            # Export statistics every minute
            if int(time.time()) % 60 == 0:
                self.export_flow_stats()
    
    def _request_stats(self, datapath):
        """Request flow statistics from datapath"""
        self.logger.debug(f'Sending stats request to datapath {datapath.id}')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        # Also request port stats for additional metrics
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        body = ev.msg.body
        
        for stat in body:
            if 'ipv4_src' in stat.match and 'ipv4_dst' in stat.match:
                self._process_flow_stats(stat)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Process packet-in events for detailed flow tracking"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if not ip_pkt:
            return  # Not an IP packet
            
        # Get transport layer details
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt:
            protocol = 6  # TCP
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            flags = self._get_tcp_flags(tcp_pkt)
        elif udp_pkt:
            protocol = 17  # UDP
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
            flags = 0
        else:
            protocol = ip_pkt.proto
            src_port = 0
            dst_port = 0
            flags = 0
            
        # Create flow keys for both directions
        forward_key = (ip_pkt.src, ip_pkt.dst, src_port, dst_port, protocol)
        backward_key = (ip_pkt.dst, ip_pkt.src, dst_port, src_port, protocol)
        
        curr_time = time.time()
        pkt_len = len(msg.data)
        
        # Update flow statistics
        if forward_key in self.flows:
            flow = self.flows[forward_key]
            flow['fwd_packets'].append(1)
            flow['fwd_bytes'].append(pkt_len)
            flow['fwd_timestamps'].append(curr_time)
            flow['fwd_flags'].append(flags if protocol == 6 else 0)
            flow['last_update'] = curr_time
        elif backward_key in self.flows:
            flow = self.flows[backward_key]
            flow['bwd_packets'].append(1)
            flow['bwd_bytes'].append(pkt_len)
            flow['bwd_timestamps'].append(curr_time)
            flow['bwd_flags'].append(flags if protocol == 6 else 0)
            flow['last_update'] = curr_time
        else:
            # New flow, set up initial data
            flow = self.flows[forward_key]
            flow['fwd_packets'] = [1]
            flow['fwd_bytes'] = [pkt_len]
            flow['fwd_timestamps'] = [curr_time]
            flow['fwd_flags'] = [flags if protocol == 6 else 0]
            flow['bwd_packets'] = []
            flow['bwd_bytes'] = []
            flow['bwd_timestamps'] = []
            flow['bwd_flags'] = []
            flow['start_time'] = curr_time
            flow['last_update'] = curr_time
            flow['src_ip'] = ip_pkt.src
            flow['dst_ip'] = ip_pkt.dst
            flow['src_port'] = src_port
            flow['dst_port'] = dst_port
            flow['protocol'] = protocol
    
    def _get_tcp_flags(self, tcp_pkt):
        """Extract TCP flags as a composite value"""
        flags = 0
        if tcp_pkt.has_flags(tcp.TCP_FIN):
            flags |= 1
        if tcp_pkt.has_flags(tcp.TCP_SYN):
            flags |= 2
        if tcp_pkt.has_flags(tcp.TCP_RST):
            flags |= 4
        if tcp_pkt.has_flags(tcp.TCP_PSH):
            flags |= 8
        if tcp_pkt.has_flags(tcp.TCP_ACK):
            flags |= 16
        if tcp_pkt.has_flags(tcp.TCP_URG):
            flags |= 32
        return flags
    
    def _process_flow_stats(self, stat):
        """Process flow statistics from OpenFlow stats reply"""
        # Extract flow identifiers
        match = stat.match
        if 'ipv4_src' not in match or 'ipv4_dst' not in match:
            return  # Skip incomplete flows
            
        src_ip = match['ipv4_src']
        dst_ip = match['ipv4_dst']
        protocol = match.get('ip_proto', 0)
        src_port = match.get('tcp_src', match.get('udp_src', 0))
        dst_port = match.get('tcp_dst', match.get('udp_dst', 0))
        
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        # Update flow data with stats from switch
        if flow_key not in self.flows:
            # Initialize new flow if not already tracked
            curr_time = time.time()
            self.flows[flow_key] = {
                'fwd_packets': [],
                'bwd_packets': [],
                'fwd_bytes': [],
                'bwd_bytes': [],
                'fwd_timestamps': [],
                'bwd_timestamps': [],
                'fwd_flags': [],
                'bwd_flags': [],
                'start_time': curr_time,
                'last_update': curr_time,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol
            }
        
        # Update with stats from flow entry
        flow = self.flows[flow_key]
        curr_time = time.time()
        
        # Only update if there's new data
        if stat.packet_count > sum(flow['fwd_packets']) if flow['fwd_packets'] else 0:
            # Calculate delta since last update
            prev_packets = sum(flow['fwd_packets']) if flow['fwd_packets'] else 0
            delta_packets = stat.packet_count - prev_packets
            
            prev_bytes = sum(flow['fwd_bytes']) if flow['fwd_bytes'] else 0
            delta_bytes = stat.byte_count - prev_bytes
            
            if delta_packets > 0:
                flow['fwd_packets'].append(delta_packets)
                flow['fwd_bytes'].append(delta_bytes)
                flow['fwd_timestamps'].append(curr_time)
                flow['last_update'] = curr_time
    
    def export_flow_stats(self, filename="flow_statistics.csv"):
        """Export flow statistics to CSV format similar to CICIDS2017"""
        current_time = time.time()
        flow_features = []
        
        # Process each flow and extract features
        for flow_key, flow_data in list(self.flows.items()):
            # Skip flows with no activity in the last minute
            if current_time - flow_data['last_update'] > 60:
                del self.flows[flow_key]
                continue
                
            # Skip flows with insufficient data
            if not flow_data['fwd_packets'] or (current_time - flow_data['start_time'] < 1):
                continue
                
            # Calculate basic flow statistics
            flow_duration = current_time - flow_data['start_time']
            total_fwd_packets = sum(flow_data['fwd_packets'])
            total_bwd_packets = sum(flow_data['bwd_packets']) if flow_data['bwd_packets'] else 0
            total_fwd_bytes = sum(flow_data['fwd_bytes'])
            total_bwd_bytes = sum(flow_data['bwd_bytes']) if flow_data['bwd_bytes'] else 0
            
            # Calculate packet length statistics
            fwd_packet_lengths = flow_data['fwd_bytes']
            bwd_packet_lengths = flow_data['bwd_bytes'] if flow_data['bwd_bytes'] else [0]
            
            # Calculate inter-arrival times
            fwd_iats = []
            if len(flow_data['fwd_timestamps']) > 1:
                fwd_iats = np.diff(flow_data['fwd_timestamps'])
                
            bwd_iats = []
            if len(flow_data['bwd_timestamps']) > 1:
                bwd_iats = np.diff(flow_data['bwd_timestamps'])
            
            # Extract TCP flags
            fwd_flags = flow_data['fwd_flags'] if flow_data['fwd_flags'] else [0]
            bwd_flags = flow_data['bwd_flags'] if flow_data['bwd_flags'] else [0]
            
            # Count flags
            syn_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 2)
            fin_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 1)
            rst_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 4)
            psh_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 8)
            ack_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 16)
            urg_count = sum(1 for flag in fwd_flags + bwd_flags if flag & 32)
            
            # Build feature dictionary similar to CICIDS2017
            features = {
                # Flow identifiers
                "src_ip": flow_data['src_ip'],
                "dst_ip": flow_data['dst_ip'],
                "src_port": flow_data['src_port'],
                "dst_port": flow_data['dst_port'],
                "protocol": flow_data['protocol'],
                
                # Basic metrics
                "Flow Duration": flow_duration,
                "Total Fwd Packets": total_fwd_packets,
                "Total Backward Packets": total_bwd_packets,
                "Total Length of Fwd Packets": total_fwd_bytes,
                "Total Length of Bwd Packets": total_bwd_bytes,
                
                # Packet length statistics
                "Fwd Packet Length Max": max(fwd_packet_lengths) if fwd_packet_lengths else 0,
                "Fwd Packet Length Min": min(fwd_packet_lengths) if fwd_packet_lengths else 0,
                "Fwd Packet Length Mean": np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0,
                "Fwd Packet Length Std": np.std(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0,
                "Bwd Packet Length Max": max(bwd_packet_lengths) if bwd_packet_lengths else 0,
                "Bwd Packet Length Min": min(bwd_packet_lengths) if bwd_packet_lengths else 0,
                "Bwd Packet Length Mean": np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
                "Bwd Packet Length Std": np.std(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0,
                
                # Flow rate metrics
                "Flow Bytes/s": (total_fwd_bytes + total_bwd_bytes) / flow_duration if flow_duration > 0 else 0,
                "Flow Packets/s": (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0,
                "Fwd Packets/s": total_fwd_packets / flow_duration if flow_duration > 0 else 0,
                "Bwd Packets/s": total_bwd_packets / flow_duration if flow_duration > 0 else 0,
                
                # Inter-arrival time metrics
                "Flow IAT Mean": np.mean(fwd_iats + bwd_iats) if fwd_iats or bwd_iats else 0,
                "Flow IAT Std": np.std(fwd_iats + bwd_iats) if len(fwd_iats + bwd_iats) > 1 else 0,
                "Flow IAT Max": max(fwd_iats + bwd_iats) if fwd_iats or bwd_iats else 0,
                "Flow IAT Min": min(fwd_iats + bwd_iats) if fwd_iats or bwd_iats else 0,
                "Fwd IAT Mean": np.mean(fwd_iats) if fwd_iats else 0,
                "Fwd IAT Std": np.std(fwd_iats) if len(fwd_iats) > 1 else 0,
                "Fwd IAT Max": max(fwd_iats) if fwd_iats else 0,
                "Fwd IAT Min": min(fwd_iats) if fwd_iats else 0,
                "Bwd IAT Mean": np.mean(bwd_iats) if bwd_iats else 0,
                "Bwd IAT Std": np.std(bwd_iats) if len(bwd_iats) > 1 else 0,
                "Bwd IAT Max": max(bwd_iats) if bwd_iats else 0,
                "Bwd IAT Min": min(bwd_iats) if bwd_iats else 0,
                
                # Flag metrics
                "FIN Flag Count": fin_count,
                "SYN Flag Count": syn_count,
                "RST Flag Count": rst_count,
                "PSH Flag Count": psh_count,
                "ACK Flag Count": ack_count,
                "URG Flag Count": urg_count,
                
                # Additional metrics
                "Average Packet Size": (total_fwd_bytes + total_bwd_bytes) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0,
                "Avg Fwd Segment Size": total_fwd_bytes / total_fwd_packets if total_fwd_packets > 0 else 0,
                "Avg Bwd Segment Size": total_bwd_bytes / total_bwd_packets if total_bwd_packets > 0 else 0,
                "Subflow Fwd Packets": total_fwd_packets,
                "Subflow Fwd Bytes": total_fwd_bytes,
                "Subflow Bwd Packets": total_bwd_packets,
                "Subflow Bwd Bytes": total_bwd_bytes,
                
                # For training, you can label the flows here
                "Label": "BENIGN"  # Default label, modify as needed
            }
            
            flow_features.append(features)
        
        if flow_features:
            df = pd.DataFrame(flow_features)
            df.to_csv(filename, index=False)
            self.logger.info(f"Exported {len(flow_features)} flow records to {filename}")
        else:
            self.logger.info("No flow records to export")

    def add_simulated_attack_flows(self, attack_type, count=20):
        """Add simulated attack flows for training purposes"""
        current_time = time.time()
        base_ip = "10.0.0."
        
        for i in range(count):
            src_ip = f"{base_ip}{random.randint(1, 10)}"
            dst_ip = f"{base_ip}{random.randint(1, 10)}"
            while src_ip == dst_ip:  # Ensure src and dst are different
                dst_ip = f"{base_ip}{random.randint(1, 10)}"
                
            src_port = random.randint(1024, 65535)
            
            # Create different attack patterns
            if attack_type == "DDoS":
                # DDoS attack has multiple sources targeting same destination
                dst_ip = f"{base_ip}1"  # Target
                dst_port = 80  # Web server
                protocol = 6  # TCP
                
                # Create high packet rate, many SYN flags
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = {
                    'fwd_packets': [random.randint(100, 1000) for _ in range(10)],
                    'bwd_packets': [],
                    'fwd_bytes': [random.randint(40, 100) for _ in range(10)],  # Small packets
                    'bwd_bytes': [],
                    'fwd_timestamps': [current_time - i for i in range(10, 0, -1)],  # Recent timestamps
                    'bwd_timestamps': [],
                    'fwd_flags': [2] * 10,  # All SYN flags
                    'bwd_flags': [],
                    'start_time': current_time - 10,
                    'last_update': current_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'label': "DDoS"
                }
                
            elif attack_type == "PortScan":
                # Port scan has one source probing many ports
                dst_ip = f"{base_ip}1"  # Target
                dst_port = 1000 + i  # Different ports
                protocol = 6  # TCP
                
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = {
                    'fwd_packets': [1, 1, 1],  # Few packets
                    'bwd_packets': [],
                    'fwd_bytes': [40, 40, 40],  # Small packets
                    'bwd_bytes': [],
                    'fwd_timestamps': [current_time - 3, current_time - 2, current_time - 1],
                    'bwd_timestamps': [],
                    'fwd_flags': [2, 2, 2],  # SYN probes
                    'bwd_flags': [],
                    'start_time': current_time - 3,
                    'last_update': current_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'label': "PortScan"
                }
                
            elif attack_type == "BruteForce":
                # Brute force has one source sending many auth requests
                dst_ip = f"{base_ip}1"  # Target
                dst_port = 22  # SSH
                protocol = 6  # TCP
                
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = {
                    'fwd_packets': [random.randint(5, 15) for _ in range(20)],
                    'bwd_packets': [random.randint(5, 15) for _ in range(20)],
                    'fwd_bytes': [random.randint(200, 500) for _ in range(20)],
                    'bwd_bytes': [random.randint(200, 500) for _ in range(20)],
                    'fwd_timestamps': [current_time - i/2 for i in range(20, 0, -1)],
                    'bwd_timestamps': [current_time - i/2 + 0.1 for i in range(20, 0, -1)],
                    'fwd_flags': [random.randint(8, 24) for _ in range(20)],  # PSH, ACK flags
                    'bwd_flags': [random.randint(8, 24) for _ in range(20)],
                    'start_time': current_time - 10,
                    'last_update': current_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'label': "BruteForce"
                }
            
            else:  # Normal traffic
                dst_port = random.choice([80, 443, 22, 53])
                protocol = random.choice([6, 17])  # TCP or UDP
                
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = {
                    'fwd_packets': [random.randint(1, 10) for _ in range(5)],
                    'bwd_packets': [random.randint(1, 10) for _ in range(5)],
                    'fwd_bytes': [random.randint(100, 1500) for _ in range(5)],
                    'bwd_bytes': [random.randint(100, 1500) for _ in range(5)],
                    'fwd_timestamps': [current_time - i for i in range(5, 0, -1)],
                    'bwd_timestamps': [current_time - i + 0.2 for i in range(5, 0, -1)],
                    'fwd_flags': [random.randint(0, 31) for _ in range(5)],
                    'bwd_flags': [random.randint(0, 31) for _ in range(5)],
                    'start_time': current_time - 5,
                    'last_update': current_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'label': "BENIGN"
                }
            
            self.flows[flow_key] = flow
        
        self.logger.info(f"Added {count} simulated {attack_type} flows")
    
    def generate_training_dataset(self, filename="training_dataset.csv", benign_count=100, 
                                ddos_count=50, portscan_count=30, bruteforce_count=20):
        """Generate a complete training dataset with labeled flows"""
        # First clear existing flows
        self.flows.clear()
        
        # Add simulated flows
        self.add_simulated_attack_flows("Normal", benign_count)
        self.add_simulated_attack_flows("DDoS", ddos_count)
        self.add_simulated_attack_flows("PortScan", portscan_count)
        self.add_simulated_attack_flows("BruteForce", bruteforce_count)
        
        # Export to CSV
        self.export_flow_stats(filename)
        self.logger.info(f"Generated training dataset with {len(self.flows)} flows")
        
        # Print distribution
        labels = [flow.get('label', 'BENIGN') for flow in self.flows.values()]
        label_counts = {label: labels.count(label) for label in set(labels)}
        self.logger.info(f"Label distribution: {label_counts}")
        
        return filename

# Import missing module
from ryu.lib import hub