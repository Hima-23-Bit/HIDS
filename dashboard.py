import socket
import subprocess

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

def get_connected_devices():
    try:
        # Use subprocess to execute system command to get connected devices
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        arp_output = result.stdout.split('\n')
        
        devices = []
        for line in arp_output:
            if 'dynamic' in line.lower():
                device_info = line.split()
                if len(device_info) >= 2:
                    devices.append(device_info[0])
        return devices
    except Exception as e:
        print("Error fetching connected devices:", e)
        return []

# Fetch local IP address
local_ip = get_local_ip()
if local_ip:
    print("Local IP Address:", local_ip)

# Fetch locally connected devices
connected_devices = get_connected_devices()
if connected_devices:
    print("Connected Devices:")
    for i, device in enumerate(connected_devices, 1):
        print(f"{i}. {device}")
else:
    print("No devices connected.")
