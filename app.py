import time
import socket
import numpy as np
from collections import defaultdict
from scapy.all import sniff, TCP, UDP, IP
import joblib
import logging
import json
from datetime import datetime

# ====== ALERT LOGGING SYSTEM ======
class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'source_port': packet_info.get('source_port'),
            'destination_port': packet_info.get('destination_port'),
            'confidence': threat.get('confidence', 0.0),
            'attack_type': threat.get('attack_type'),
            'details': threat
        }
        self.logger.warning(json.dumps(alert))
        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )

# ====== FLOW BUFFER & FEATURE EXTRACTION ======
class FlowBuffer:
    def __init__(self, flow_key):
        self.flow_key = flow_key
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_times = []
        self.bwd_times = []
        self.packet_times = []
        self.flow_start_time = None
        self.flow_end_time = None
        self.last_packet_time = None
        self.idle_times = []
        self.flags = []
        self.ack_count = 0
        self.psh_count = 0
        self.fwd_header_length = []
        self.bwd_header_length = []
        self.init_win_bytes_forward = None
        self.init_win_bytes_backward = None
        self.min_seg_size_forward = []
        self.act_data_pkt_fwd = 0
        self.dst_ports = set()

    def add_packet(self, packet, direction, now):
        pkt_len = len(packet)
        self.packet_lengths.append(pkt_len)
        self.packet_times.append(now)
        if self.flow_start_time is None:
            self.flow_start_time = now
        self.flow_end_time = now
        if self.last_packet_time is not None:
            self.idle_times.append(now - self.last_packet_time)
        self.last_packet_time = now
        if direction == "fwd":
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_times.append(now)
            if TCP in packet:
                self.fwd_header_length.append(packet[TCP].dataofs * 4)
                if self.init_win_bytes_forward is None:
                    self.init_win_bytes_forward = packet[TCP].window
            if UDP in packet:
                self.fwd_header_length.append(8)
        elif direction == "bwd":
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_times.append(now)
            if TCP in packet:
                self.bwd_header_length.append(packet[TCP].dataofs * 4)
                if self.init_win_bytes_backward is None:
                    self.init_win_bytes_backward = packet[TCP].window
            if UDP in packet:
                self.bwd_header_length.append(8)
        if direction == "fwd":
            if TCP in packet:
                self.min_seg_size_forward.append(packet[TCP].dataofs * 4)
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x10:
                self.ack_count += 1
            if flags & 0x08:
                self.psh_count += 1
        if TCP in packet or UDP in packet:
            self.dst_ports.add(packet.dport)
        if direction == "fwd" and pkt_len > 0:
            self.act_data_pkt_fwd += 1

    def compute_features(self):
        features = {}
        pl = self.packet_lengths
        fpl = self.fwd_packet_lengths
        bpl = self.bwd_packet_lengths
        pt = self.packet_times
        ft = self.fwd_times
        bt = self.bwd_times
        duration = (self.flow_end_time - self.flow_start_time) * 1000 if self.flow_end_time and self.flow_start_time else 0
        features['Packet Length Std'] = float(np.std(pl)) if pl else 0
        features['Packet Length Variance'] = float(np.var(pl)) if pl else 0
        features['Packet Length Mean'] = float(np.mean(pl)) if pl else 0
        features['Average Packet Size'] = float(np.mean(pl)) if pl else 0
        features['Max Packet Length'] = float(np.max(pl)) if pl else 0
        features['Fwd Packet Length Max'] = float(np.max(fpl)) if fpl else 0
        features['Fwd Packet Length Mean'] = float(np.mean(fpl)) if fpl else 0
        features['Fwd Packet Length Std'] = float(np.std(fpl)) if fpl else 0
        features['Bwd Packet Length Max'] = float(np.max(bpl)) if bpl else 0
        features['Bwd Packet Length Mean'] = float(np.mean(bpl)) if bpl else 0
        features['Bwd Packet Length Std'] = float(np.std(bpl)) if bpl else 0
        features['Bwd Packet Length Min'] = float(np.min(bpl)) if bpl else 0
        features['Flow Duration'] = duration
        features['Total Fwd Packets'] = len(fpl)
        features['Total Length of Fwd Packets'] = float(np.sum(fpl)) if fpl else 0
        iats = np.diff(pt) if len(pt) > 1 else [0]
        features['Flow IAT Max'] = float(np.max(iats)) if len(iats) else 0
        features['Flow IAT Std'] = float(np.std(iats)) if len(iats) else 0
        features['Idle Max'] = float(np.max(self.idle_times)) if self.idle_times else 0
        features['Idle Mean'] = float(np.mean(self.idle_times)) if self.idle_times else 0
        fwd_iats = np.diff(ft) if len(ft) > 1 else [0]
        features['Fwd IAT Max'] = float(np.max(fwd_iats)) if len(fwd_iats) else 0
        features['Fwd IAT Std'] = float(np.std(fwd_iats)) if len(fwd_iats) else 0
        features['Fwd IAT Mean'] = float(np.mean(fwd_iats)) if len(fwd_iats) else 0
        features['Fwd IAT Total'] = float(np.sum(fwd_iats)) if len(fwd_iats) else 0
        features['Bwd Packets/s'] = len(bpl) / ((duration / 1000) + 1e-6)
        features['Flow Bytes/s'] = float(np.sum(pl)) / ((duration / 1000) + 1e-6)
        features['Flow Packets/s'] = len(pl) / ((duration / 1000) + 1e-6)
        features['Fwd Header Length'] = float(np.sum(self.fwd_header_length)) if self.fwd_header_length else 0
        features['Bwd Header Length'] = float(np.sum(self.bwd_header_length)) if self.bwd_header_length else 0
        features['Init_Win_bytes_forward'] = self.init_win_bytes_forward or 0
        features['Init_Win_bytes_backward'] = self.init_win_bytes_backward or 0
        features['min_seg_size_forward'] = min(self.min_seg_size_forward) if self.min_seg_size_forward else 0
        features['ACK Flag Count'] = self.ack_count
        features['PSH Flag Count'] = self.psh_count
        features['act_data_pkt_fwd'] = self.act_data_pkt_fwd
        features['Destination Port'] = next(iter(self.dst_ports)) if self.dst_ports else 0
        return features

# ====== FLOW TABLE AND PACKET PROCESSING ======
flows = defaultdict(lambda: None)
FLOW_TIMEOUT = 30  # seconds, adjust as needed

def get_flow_key(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        if TCP in pkt or UDP in pkt:
            sport = pkt.sport
            dport = pkt.dport
        else:
            sport = 0
            dport = 0
        return (src, dst, sport, dport, proto)
    return None

def get_direction(pkt, flow_key):
    if IP in pkt:
        if (pkt[IP].src, pkt[IP].dst) == (flow_key[0], flow_key[1]):
            return "fwd"
        else:
            return "bwd"
    return "fwd"

def process_packet(pkt):
    now = pkt.time if hasattr(pkt, 'time') else time.time()
    flow_key = get_flow_key(pkt)
    if flow_key is None:
        return
    if flows[flow_key] is None:
        flows[flow_key] = FlowBuffer(flow_key)
    direction = get_direction(pkt, flow_key)
    flows[flow_key].add_packet(pkt, direction, now)
    # -- Flow expiry logic (time-based)
    if now - flows[flow_key].flow_start_time > FLOW_TIMEOUT:
        features = flows[flow_key].compute_features()
        packet_info = {
            'source_ip': flow_key[0],
            'destination_ip': flow_key[1],
            'source_port': flow_key[2],
            'destination_port': flow_key[3]
        }
        threats = detect_threats(features)
        for threat in threats:
            alert_system.generate_alert(threat, packet_info)
        del flows[flow_key]

# ====== DETECTION ENGINE ======
expected_features = [
    'Packet Length Std', 'Packet Length Variance', 'Average Packet Size',
    'Bwd Packet Length Mean', 'Total Length of Fwd Packets',
    'Bwd Packet Length Max', 'Fwd Packet Length Max',
    'Bwd Packet Length Std', 'Max Packet Length', 'Fwd Packet Length Mean',
    'Packet Length Mean', 'Init_Win_bytes_backward', 'Flow IAT Max',
    'PSH Flag Count', 'Destination Port', 'Bwd Header Length',
    'act_data_pkt_fwd', 'Total Fwd Packets', 'Fwd IAT Max',
    'Fwd Header Length', 'Fwd IAT Std', 'Init_Win_bytes_forward',
    'Fwd IAT Mean', 'Flow IAT Std', 'min_seg_size_forward',
    'Fwd Packet Length Std', 'Bwd Packets/s', 'Flow Duration', 'Idle Max',
    'Bwd Packet Length Min', 'ACK Flag Count', 'Flow Bytes/s',
    'Fwd IAT Total', 'Flow Packets/s', 'Idle Mean'
]

type_names = {
    0: 'Bots',
    1: 'Brute Force',
    2: 'DDoS',
    3: 'DoS',
    4: 'Normal Traffic',
    5: 'Port Scanning',
    6: 'Web Attacks'
}

rf_model = joblib.load("model_rf.joblib")
alert_system = AlertSystem()

def detect_threats(features):
    threats = []
    feature_vector = np.array([[features.get(name, 0) for name in expected_features]])
    pred = rf_model.predict(feature_vector)[0]
    if pred != 4:  # Not Normal Traffic
        threats.append({
            'type': 'ml_rf',
            'confidence': 1.0,
            'prediction': int(pred),
            'attack_type': type_names[int(pred)]
        })
    return threats

# ====== MAIN ======
if __name__ == "__main__":
    iface = "enp0s3"  # Change as needed
    print(f"Starting flow-based IDS on interface {iface}...")
    sniff(iface=iface, prn=process_packet, store=0)
