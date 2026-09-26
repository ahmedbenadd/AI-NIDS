import os
import time
import json
import secrets
import joblib
import pandas as pd
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.arch import get_if_addr, get_if_hwaddr
from threading import Thread
from collections import deque
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Never hardcode this. Falls back to a random per-run key so no secret is
# ever committed to version control.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Network interface configuration
SNIFF_INTERFACE = os.getenv('SNIFF_INTERFACE', 'ens33')

try:
    LOCAL_IP = get_if_addr(SNIFF_INTERFACE)
    LOCAL_MAC = get_if_hwaddr(SNIFF_INTERFACE)
except:
    LOCAL_IP = "127.0.0.1"
    LOCAL_MAC = "00:00:00:00:00:00"
    print(f"Warning: Could not resolve local IP/MAC for interface {SNIFF_INTERFACE}")

# Load saved ML artifacts from the XGBoost folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
print("Loading ML Artifacts (XGBoost)...")
try:
    model = joblib.load(os.path.join(BASE_DIR, 'models/XGBoost/xgb_model.pkl'))
    scaler = joblib.load(os.path.join(BASE_DIR, 'models/XGBoost/scaler.pkl'))
    encoder_features = joblib.load(os.path.join(BASE_DIR, 'models/XGBoost/encoder.pkl'))
    label_encoder = joblib.load(os.path.join(BASE_DIR, 'models/XGBoost/label_encoder.pkl'))
    print("Models loaded successfully!")
except Exception as e:
    print(f"Error loading models. Did you train XGBoost? {e}")

recent_connections = {}
dst_host_history = {}

def extract_features(packet):
    """Extract organic, mathematically accurate features based on NSL-KDD definitions using sliding windows."""
    try:
        # Initialize default feature values
        features = {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'SF',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 0, 'srv_count': 0, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 0,
            'dst_host_srv_count': 0, 'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

        if IP not in packet:
            return None

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port = 0
        
        # Set Bytes and IP level features
        # NSL-KDD src_bytes is data payload ONLY, not headers!
        payload_len = len(packet[Raw].load) if Raw in packet else 0
        features['src_bytes'] = payload_len
        features['dst_bytes'] = 0 # dst_bytes is from server, which we'd need bidirectional tracking for
        if ip_src == ip_dst:
            features['land'] = 1
        if packet[IP].flags & 0x01 or packet[IP].frag != 0:
            features['wrong_fragment'] = 1

        # Protocol and Service and Flag
        if TCP in packet:
            features['protocol_type'] = 'tcp'
            # Look at both ports to correctly identify the service (useful for incoming server responses)
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            port = dport
            
            srv_port = dport if dport <= 1024 else sport
            if srv_port in [80, 443]: features['service'] = 'http'
            elif srv_port == 21: features['service'] = 'ftp'
            elif srv_port in [22, 23]: features['service'] = 'telnet'
            elif srv_port == 25: features['service'] = 'smtp'
            else: features['service'] = 'private'
            
            flags = packet[TCP].flags
            if flags & 0x02 and flags & 0x10: features['flag'] = 'S1' # SYN+ACK
            elif flags & 0x02: features['flag'] = 'S0'                # SYN
            elif flags & 0x01: features['flag'] = 'SF'                # FIN
            elif flags & 0x04: features['flag'] = 'REJ'               # RST
            if flags & 0x20: features['urgent'] = 1
                
        elif UDP in packet:
            features['protocol_type'] = 'udp'
            dport = packet[UDP].dport
            sport = packet[UDP].sport
            port = dport
            
            srv_port = dport if dport <= 1024 else sport
            if srv_port == 53: features['service'] = 'domain_u'
            elif srv_port == 123: features['service'] = 'ntp_u'
            else: features['service'] = 'private'
            
        elif ICMP in packet:
            features['protocol_type'] = 'icmp'
            features['service'] = 'eco_i'

        # -------------------------------------------------------------
        # CONNECTION TRACKING (Grouping packets into logical connections)
        # -------------------------------------------------------------
        sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        conn_id = f"{ip_src}:{sport}-{ip_dst}:{port}-{features['protocol_type']}"
        
        global recent_connections
        global dst_host_history
        
        current_time = time.time()
        
        if conn_id not in recent_connections or current_time - recent_connections[conn_id]['time'] > 5.0:
            # This is a NEW connection
            record = {
                'time': current_time,
                'src': ip_src,
                'dst': ip_dst,
                'service': features['service'],
                'flag': features['flag'],
                'port': port
            }
            recent_connections[conn_id] = record
            
            # Add to 100-connection host history
            if ip_dst not in dst_host_history:
                dst_host_history[ip_dst] = deque(maxlen=100)
            dst_host_history[ip_dst].append(record)
        else:
            # Update existing connection
            recent_connections[conn_id]['time'] = current_time
            # If the connection progresses to a normal state (SF), update it so it doesn't inflate serror_rate!
            if features['flag'] == 'SF':
                recent_connections[conn_id]['flag'] = 'SF'
                
        # Clean up old connections from memory (> 5 seconds old)
        keys_to_delete = [k for k, v in recent_connections.items() if current_time - v['time'] > 5.0]
        for k in keys_to_delete:
            del recent_connections[k]
        
        # -------------------------------------------------------------
        # ORGANIC MATHEMATICAL FEATURE CALCULATIONS
        # -------------------------------------------------------------
        
        # Calculate 2-second window features using active connections
        recent_conns_list = [c for c in recent_connections.values() if current_time - c['time'] <= 2.0]
        
        same_host_conns = [c for c in recent_conns_list if c['dst'] == ip_dst]
        same_srv_conns = [c for c in recent_conns_list if c['service'] == features['service']]
        
        features['count'] = min(len(same_host_conns), 255)
        features['srv_count'] = min(len(same_srv_conns), 255)
        
        if len(same_host_conns) > 0:
            features['serror_rate'] = sum(1 for c in same_host_conns if c['flag'] in ['S0', 'S1']) / len(same_host_conns)
            features['rerror_rate'] = sum(1 for c in same_host_conns if c['flag'] == 'REJ') / len(same_host_conns)
            features['same_srv_rate'] = sum(1 for c in same_host_conns if c['service'] == features['service']) / len(same_host_conns)
            features['diff_srv_rate'] = 1.0 - features['same_srv_rate']
            
        if len(same_srv_conns) > 0:
            features['srv_serror_rate'] = sum(1 for c in same_srv_conns if c['flag'] in ['S0', 'S1']) / len(same_srv_conns)
            features['srv_rerror_rate'] = sum(1 for c in same_srv_conns if c['flag'] == 'REJ') / len(same_srv_conns)
            features['srv_diff_host_rate'] = sum(1 for c in same_srv_conns if c['dst'] != ip_dst) / len(same_srv_conns)
            
        # 100-connection host window features
        host_conns = dst_host_history[ip_dst]
        features['dst_host_count'] = min(len(host_conns), 255)
        
        if len(host_conns) > 0:
            host_srv_conns = [c for c in host_conns if c['service'] == features['service']]
            features['dst_host_srv_count'] = min(len(host_srv_conns), 255)
            
            features['dst_host_same_srv_rate'] = len(host_srv_conns) / len(host_conns)
            features['dst_host_diff_srv_rate'] = 1.0 - features['dst_host_same_srv_rate']
            features['dst_host_same_src_port_rate'] = sum(1 for c in host_conns if c['port'] == port) / len(host_conns)
            features['dst_host_serror_rate'] = sum(1 for c in host_conns if c['flag'] in ['S0', 'S1']) / len(host_conns)
            features['dst_host_rerror_rate'] = sum(1 for c in host_conns if c['flag'] == 'REJ') / len(host_conns)
            
            if len(host_srv_conns) > 0:
                features['dst_host_srv_diff_host_rate'] = sum(1 for c in host_srv_conns if c['src'] != ip_src) / len(host_srv_conns)
                features['dst_host_srv_serror_rate'] = sum(1 for c in host_srv_conns if c['flag'] in ['S0', 'S1']) / len(host_srv_conns)
                features['dst_host_srv_rerror_rate'] = sum(1 for c in host_srv_conns if c['flag'] == 'REJ') / len(host_srv_conns)

        return features
    except Exception as e:
        print(f"Extraction error: {e}")
        return None

def preprocess_packet(features_dict):
    """Transform extracted dictionary into a scaled, encoded DataFrame matching training"""
    df = pd.DataFrame([features_dict])
    
    cat_cols = ['protocol_type', 'service', 'flag']
    num_cols = [col for col in df.columns if col not in cat_cols]
    
    encoded_cats = pd.DataFrame(encoder_features.transform(df[cat_cols]))
    encoded_cats.columns = encoder_features.get_feature_names_out(cat_cols)
    
    df = df.drop(cat_cols, axis=1).reset_index(drop=True)
    df_combined = pd.concat([df, encoded_cats], axis=1)
    
    df_combined[num_cols] = scaler.transform(df_combined[num_cols])
    
    # CRITICAL: Force DataFrame columns to match the exact order the model expects!
    model_cols = model.get_booster().feature_names
    for col in model_cols:
        if col not in df_combined.columns:
            df_combined[col] = 0
    df_combined = df_combined[model_cols]
    
    return df_combined

def is_local_ip(ip_addr):
    """Check if an IP is a local/private network address."""
    return (ip_addr.startswith('192.168.') or 
            ip_addr.startswith('10.') or 
            ip_addr.startswith('127.') or 
            (ip_addr.startswith('172.') and 16 <= int(ip_addr.split('.')[1]) <= 31))

def packet_callback(packet):
    try:
        if IP not in packet:
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # 0. Limit entirely to local network traffic (ignore internet/public IPs)
        if not is_local_ip(src_ip):
            return
            
        # Ignore Broadcast and Multicast traffic
        if dst_ip.endswith('.255') or dst_ip.startswith('224.') or dst_ip.startswith('239.') or dst_ip == '255.255.255.255':
            return
            
        # 1. Ignore outgoing traffic (we only want to detect incoming attacks)
        if Ether in packet and packet[Ether].src == LOCAL_MAC:
            return
            
        # 2. Whitelist internal dashboard traffic (port 5000)
        if TCP in packet and (packet[TCP].dport == 5000 or packet[TCP].sport == 5000):
            return
        features = extract_features(packet)
        if not features:
            return
            
        preprocessed_df = preprocess_packet(features)
        prediction_num = model.predict(preprocessed_df)[0]
        
        # In label encoder, BENIGN is usually 1, ATTACK is 0 based on alphabetical (ATTACK, BENIGN)
        # Let's decode it safely
        try:
            prediction_str = label_encoder.inverse_transform([prediction_num])[0]
        except:
            prediction_str = "BENIGN" if prediction_num == 1 else "ATTACK"
            
        if prediction_str == "ATTACK":
            print(f"[!] ATTACK DETECTED: {src_ip} -> {dst_ip} | Proto: {features['protocol_type']} | Service: {features['service']} | Bytes: {features['src_bytes']} | Count: {features['count']} | serror: {features['serror_rate']}")

        packet_data = {
            'timestamp': time.strftime('%H:%M:%S'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': features['protocol_type'].upper(),
            'service': features['service'].upper(),
            'prediction': prediction_str,
            'bytes': features['src_bytes']
        }
        
        # Emit strictly to connected websocket clients
        socketio.emit('new_packet', packet_data)
    except Exception as e:
        # Prevent sniffer thread from crashing on error
        print(f"Packet callback error: {e}")

def start_sniffer():
    print(f"Starting Scapy sniffer on interface: {SNIFF_INTERFACE}")
    sniff(prn=packet_callback, store=False, iface=SNIFF_INTERFACE)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Start sniffer in background
    sniffer_thread = Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Run server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
