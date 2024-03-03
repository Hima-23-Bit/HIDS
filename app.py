from flask import Flask, render_template, jsonify, request, redirect, url_for
import socket
import json
import time
import os
from scapy.all import ARP, Ether, srp
from typing import List 
import socket  
import ipaddress 
from collections import Counter  
import netifaces  


start_time = time.time()

BLOCKED_DOMAINS_FILE = 'config/blocked_domains.json'
BLOCKED_PORTS_FILE = 'config/blocked_ports.json'

app = Flask(__name__)



@app.route('/alerts')  
def alerts():  
    with open('config/blocking_logs.json', 'r') as f:  
        logs = [json.loads(line) for line in f]  
  
    ddos_alerts = [log for log in logs if 'DDoS' in log['message']]  
  
    return render_template('alerts.html', ddos_alerts=ddos_alerts)  


@app.route('/statistics')  
def statistics():  
    with open('config/blocking_logs.json', 'r') as f:  
        logs = [json.loads(line) for line in f]  
  
    ips_blocked = len(set(log['src'] for log in logs if 'Blocked IP' in log['message']))  
    ports_blocked = len(set(log['dst'] for log in logs if 'Blocked Port' in log['message']))  
    domains_blocked = len(set(log['dst'] for log in logs if 'Blocked Domain' in log['message']))  
    ddos_detected = sum(1 for log in logs if 'DDoS' in log['message'])  
    ddos_by_src = Counter(log['src'] for log in logs if 'DDoS' in log['message'])  
  
    most_blocked_ips = Counter(log['src'] for log in logs if 'Blocked IP' in log['message']).most_common(10)  
    most_blocked_ports = Counter(log['dst'] for log in logs if 'Blocked Port' in log['message']).most_common(10)  
    most_blocked_domains = Counter(log['dst'] for log in logs if 'Blocked Domain' in log['message']).most_common(10)  
  
    return render_template(  
        'statistics.html',   
        ips_blocked=ips_blocked,   
        ports_blocked=ports_blocked,  
        domains_blocked=domains_blocked,   
        ddos_detected=ddos_detected,   
        ddos_by_src=ddos_by_src.items(),  
        most_blocked_ips=most_blocked_ips,  
        most_blocked_ports=most_blocked_ports,  
        most_blocked_domains=most_blocked_domains  
    )  

def load_blocked_ports():  
    try:  
        with open(BLOCKED_PORTS_FILE, 'r') as f:  
            return json.load(f)  
    except json.JSONDecodeError:  
        return []  

  
def save_blocked_ports(blocked_ports):  
    with open(BLOCKED_PORTS_FILE, 'w') as f:  
        json.dump(blocked_ports, f)  
  
@app.route('/block-port', methods=['POST'])  
def block_port():  
    blocked_ports = load_blocked_ports()  
    port = request.form.get('port')  
  
    if port not in blocked_ports:  
        blocked_ports.append(port)  
        save_blocked_ports(blocked_ports)  
        return jsonify({'success': True})  
  
    return jsonify({'success': False, 'error': 'Port is already blocked.'})  
  
@app.route('/unblock-port', methods=['POST'])  
def unblock_port():  
    blocked_ports = load_blocked_ports()  
    port = request.form.get('port')  
  
    if port in blocked_ports:  
        blocked_ports.remove(port)  
        save_blocked_ports(blocked_ports)  
        return jsonify({'success': True})  
  
    return jsonify({'success': False, 'error': 'Port is not blocked.'})  
  
@app.route('/block-ports')  
def block_ports():  
    blocked_ports = load_blocked_ports()  
    return render_template('block-ports.html', blocked_ports=blocked_ports)  

BLOCKED_SERVICES_FILE = 'config/blocked_services.json'

BLOCKED_IPS_FILE = 'config/blocked_ips.json'

# Function to read the list of blocked IP addresses from blocked_ips.json
def read_blocked_ips():
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return json.load(f).get('blocked_ips', [])
    except FileNotFoundError:
        return []

# Function to write the list of blocked IP addresses to blocked_ips.json
def write_blocked_ips(blocked_ips):
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump({'blocked_ips': blocked_ips}, f, indent=4)

@app.route('/block-ip', methods=['POST'])
def block_ip():
    try:
        ip_address = request.form['ip']
        blocked_ips = read_blocked_ips()
        if ip_address not in blocked_ips:
            blocked_ips.append(ip_address)
            write_blocked_ips(blocked_ips)
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'error': 'IP address already blocked.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/unblock-ip', methods=['POST'])
def unblock_ip():
    try:
        ip_address = request.form['ip']
        blocked_ips = read_blocked_ips()
        if ip_address in blocked_ips:
            blocked_ips.remove(ip_address)
            write_blocked_ips(blocked_ips)
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'error': 'IP address not found in the blocked list.'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/blocked-ips')
def get_blocked_ips():
    try:
        blocked_ips = read_blocked_ips()
        return jsonify({'success': True, 'blocked_ips': blocked_ips}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    

@app.route('/block-ip-page')
def block_ip_page():
    blocked_ips = read_blocked_ips()
    return render_template('block-ip.html', blocked_ips=blocked_ips)

def load_blocked_domains():
    try:
        with open(BLOCKED_DOMAINS_FILE, 'r') as f:
            data = json.load(f)
            blocked_domains = data.get('blocked_domains', [])
            return set(blocked_domains)
    except FileNotFoundError:
        return set()

def save_blocked_domains(blocked_domains):
    with open(BLOCKED_DOMAINS_FILE, 'w') as f:
        json.dump({'blocked_domains': list(blocked_domains)}, f, indent=4)

@app.route('/delete-domain', methods=['POST'])
def delete_domain():
    try:
        domain_to_delete = request.form['domain']
        blocked_domains = load_blocked_domains()

        if domain_to_delete in blocked_domains:
            blocked_domains.remove(domain_to_delete)
            save_blocked_domains(blocked_domains)
            return jsonify({'success': True, 'message': f'Successfully deleted domain: {domain_to_delete}'}), 200
        else:
            return jsonify({'success': False, 'error': f'Domain "{domain_to_delete}" not found in blocked domains'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/configuration')
def configuration():
    try:
        with open('config/blocked_services.json', 'r') as f:
            data = json.load(f)
            blocked_services = data.get('blocked_services', [])
    except FileNotFoundError:
        blocked_services = []

    return render_template('configuration.html', blocked_services=blocked_services)



@app.route('/block-domain')
def block_domain():
    domains = get_domains()
    return render_template('block-domain.html', domains=domains)

def read_blocked_domains():
    try:
        with open(BLOCKED_DOMAINS_FILE, 'r') as f:
            return set(json.load(f).get('blocked_domains', []))
    except FileNotFoundError:
        return set()

def write_blocked_domains(blocked_domains):
    with open(BLOCKED_DOMAINS_FILE, 'w') as f:
        json.dump({'blocked_domains': list(blocked_domains)}, f, indent=4)

@app.route('/add-domain', methods=['POST'])
def add_domain():
    try:
        domain = request.form['domain']
        blocked_domains = read_blocked_domains()
        blocked_domains.add(domain)
        write_blocked_domains(blocked_domains)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/domains')
def get_domains():
    try:
        blocked_domains = read_blocked_domains()
        return blocked_domains
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/uptime')
def get_uptime():
    uptime_seconds = int(time.time() - start_time)
    uptime = format_time(uptime_seconds)
    return jsonify(uptime=uptime)

def format_time(seconds):
    # Convert seconds to days, hours, minutes, and seconds
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

def get_local_ip():
    try:
        # Create a socket to get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's public DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print("Error fetching local IP:", e)
        return None

  
def get_internet_connected_interface():  
    gateways = netifaces.gateways()  
    default_gateway = gateways['default'][netifaces.AF_INET][1]  
    return default_gateway  
  
def get_local_ip():  
    connected_interface = get_internet_connected_interface()  
    local_ip = netifaces.ifaddresses(connected_interface)[netifaces.AF_INET][0]['addr']  
    return local_ip  
  
def get_connected_devices():  
    all_connected_devices = []  
  
    # Get the local IP address  
    local_ip = get_local_ip()  
  
    # Calculate the /24 subnet that the local IP is a part of  
    ip_interface = ipaddress.ip_interface(f"{local_ip}/24")  
    ip_network = ip_interface.network  
    ip_range = str(ip_network)  
  
    try:  
        arp = ARP(pdst=ip_range)  
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  
        packet = ether/arp  
  
        result = srp(packet, timeout=3, verbose=False)[0]  
  
        connected_devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]  
  
        all_connected_devices.extend(connected_devices)  
    except Exception as e:  
        print(f"An error occurred while scanning the IP range {ip_range}: {e}")  
  
    return all_connected_devices  
  
@app.route('/')  
def dashboard():  
    local_ip = get_local_ip()  
    connected_devices = get_connected_devices()  
    return render_template('home.html', local_ip=local_ip, connected_devices=connected_devices) 

if __name__ == '__main__':
    app.run(debug=True)
