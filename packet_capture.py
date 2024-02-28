import json  
import netfilterqueue  
from datetime import datetime  
from scapy.all import *  
from scapy.layers.inet import IP, TCP, UDP  
from scapy.layers.dns import DNS, DNSQR  
  
# Function to load blocked IPs from blocked_ips.json  
def load_blocked_ips():  
    try:  
        with open('config/blocked_ips.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_ips', []))  
    except FileNotFoundError:  
        return set()  
  
# Function to load blocked URLs from blocked_domains.json  
def load_blocked_urls():  
    try:  
        with open('config/blocked_domains.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_domains', []))  
    except FileNotFoundError:  
        return set()  
  
# Function to load blocked ports from blocked_ports.json  
def load_blocked_ports():  
    try:  
        with open('config/blocked_ports.json', 'r') as f:  
            data = json.load(f)  
            blocked_ports = set()  
            for entry in data:  
                port_number = int(entry.get('port_number', 0))  # Convert port_number to integer  
                blocked_ports.add(port_number)  
            return blocked_ports  
    except FileNotFoundError:  
        return set()  
  
# Function to load blocked services from blocked_services.json  
def load_blocked_services():  
    try:  
        with open('config/blocked_services.json', 'r') as f:  
            data = json.load(f)  
            return set(data.get('blocked_services', []))  
    except FileNotFoundError:  
        return set()  
  
# Define blocked IPs, URLs, ports, and services  
blocked_ips = load_blocked_ips()  
blocked_urls = load_blocked_urls()  
blocked_ports = load_blocked_ports()  
blocked_services = load_blocked_services()  
  
# Function to check if a packet matches any blocked criteria  
def is_blocked(scapy_packet):  
    if IP in scapy_packet:  
        src_ip = scapy_packet[IP].src  
        dst_ip = scapy_packet[IP].dst  
        if src_ip in blocked_ips or dst_ip in blocked_ips:  
            return True, f"Blocked IP: {src_ip if src_ip in blocked_ips else dst_ip}"  
    if DNS in scapy_packet and scapy_packet[DNS].qr == 0:  # Only check queries, not responses  
        domain = scapy_packet[DNSQR].qname.decode("utf-8")  
        if any(blocked_domain in domain for blocked_domain in blocked_urls):  
            return True, f"Blocked URL: {domain}"  
    if TCP in scapy_packet:  
        src_port = scapy_packet[TCP].sport  
        dst_port = scapy_packet[TCP].dport  
        if src_port in blocked_ports or dst_port in blocked_ports:  
            return True, f"Blocked Port: {src_port if src_port in blocked_ports else dst_port}"  
    if UDP in scapy_packet:  
        # Handle UDP payloads as binary data  
        payload = bytes(scapy_packet[UDP].payload)  
        # Convert blocked services to bytes-like objects  
        blocked_services_bytes = [service.encode() for service in blocked_services]  
        if any(service_bytes.lower() in payload.lower() for service_bytes in blocked_services_bytes):  
            return True, f"Blocked Service in Payload"  
    return False, ""  

  
# Function to handle blocked packets and write logs  
def handle_packet(packet):  
    scapy_packet = IP(packet.get_payload())  
    blocked, log_message = is_blocked(scapy_packet)  
    if blocked:  
        # Write log to file  
        with open('config/blocking_logs.json', 'a') as log_file:  
            log_entry = {"timestamp": str(datetime.now()), "message": log_message}  
            json.dump(log_entry, log_file)  
            print("Blocked packet:", scapy_packet.summary()) 
            log_file.write('\n')  
            # Drop the packet  
            packet.drop()  
    else:  
        # Allow the packet to pass through  
        # print("Allowed packet:", scapy_packet.summary())  
        packet.accept()  
  
queue = netfilterqueue.NetfilterQueue()  
queue.bind(0, handle_packet)  # Bind to queue number 0  
try:  
    print("[*] Waiting for packets...")  
    queue.run()  
except KeyboardInterrupt:  
    print("[*] Stopping...")  

