from flask import Flask, render_template, jsonify, request
import socket
import json
import time
import os
from scapy.all import ARP, Ether, srp

start_time = time.time()

BLOCKED_DOMAINS_FILE = 'config/blocked_domains.json'

app = Flask(__name__)


BLOCKED_PORTS_FILE = 'config/blocked_ports.json'
BLOCKED_SERVICES_FILE = 'config/blocked_services.json'

def load_blocked_services():
    try:
        with open('blocked_services.json', 'r') as f:
            data = json.load(f)
            blocked_services = dataa.get('blocked_services', [])
            return [service.lower() for service in blocked_services]  # Convert to lowercase for case-insensitive comparison
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return []

# Save the list of blocked services to blocked_services.json
def save_blocked_services(blocked_services):
    with open('blocked_services.json', 'w') as f:
        json.dump({'blocked_services': blocked_services}, f, indent=4)

@app.route('/delete-service', methods=['POST'])
def delete_service():
    try:
        # Get the service to delete from the form data
        service_to_delete = request.form['deleteService'].lower()  # Convert to lowercase for case-insensitive comparison
        print(service_to_delete)

        # Load the current list of blocked services
        blocked_services = load_blocked_services()
        print(blocked_services)

        # Check if the service exists in the list (case-insensitive comparison)
        if service_to_delete in blocked_services:
            # Remove the selected service from the list
            blocked_services.remove(service_to_delete)

            # Save the updated list of blocked services
            save_blocked_services(blocked_services)

            return jsonify({'success': True, 'message': f'Successfully deleted service: {service_to_delete.capitalize()}'}), 200
        else:
            return jsonify({'success': False, 'error': f'Service "{service_to_delete}" not found in blocked services'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/set-ddos-threshold', methods=['POST'])
def set_ddos_threshold():
    try:
        threshold = int(request.form['threshold'])
        with open('config/ddos_threshold.json', 'w') as f:
             json.dump({'threshold': threshold}, f, indent=4)
        return jsonify({'success': True}), 200
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


def read_blocked_services():
    try:
        with open(BLOCKED_SERVICES_FILE, 'r') as f:
            return set(json.load(f).get('blocked_services', []))
    except FileNotFoundError:
        return set()

def write_blocked_services(blocked_services):
    with open(BLOCKED_SERVICES_FILE, 'w') as f:
        json.dump({'blocked_services': list(blocked_services)}, f, indent=4)

@app.route('/block-service', methods=['POST'])
def block_service():
    try:
        service_name = request.form['serviceName']
        blocked_services = read_blocked_services()
        blocked_services.add(service_name)
        write_blocked_services(blocked_services)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/blocked-services')
def get_blocked_services():
    try:
        blocked_services = read_blocked_services()
        return {'success': True, 'blocked_services': list(blocked_services)}, 200
    except Exception as e:
        return {'success': False, 'message': str(e)}, 500


def read_blocked_ports():
    if os.path.exists(BLOCKED_PORTS_FILE):
        with open(BLOCKED_PORTS_FILE, 'r') as f:
            return json.load(f)
    else:
        return []

def write_blocked_ports(blocked_ports):
    with open(BLOCKED_PORTS_FILE, 'w') as f:
        json.dump(blocked_ports, f, indent=4)

@app.route('/block-port', methods=['POST'])
def block_port():
    try:
        port_number = request.form['portNumber']
        traffic_type = request.form['trafficType']
        
        # Perform actions to block the port based on port_number and traffic_type
        
        blocked_ports = read_blocked_ports()
        blocked_ports.append({'port_number': port_number, 'traffic_type': traffic_type})
        write_blocked_ports(blocked_ports)
        
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/block-ports')
def block_ports():
    return render_template('block-ports.html')

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

def get_connected_devices(ip_ranges):
    all_connected_devices = []
    for ip_range in ip_ranges:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=False)[0]

        connected_devices = []
        for sent, received in result:
            connected_devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        all_connected_devices.extend(connected_devices)

    return all_connected_devices

@app.route('/')
def dashboard():
    uptime = get_uptime()
    local_ip = get_local_ip()
    ip_ranges = ["192.168.1.0/24", "192.168.254.0/24"]
    connected_devices = get_connected_devices(ip_ranges)
    return render_template('home.html', local_ip=local_ip, connected_devices=connected_devices, uptime=uptime)

if __name__ == '__main__':
    app.run(debug=True)
