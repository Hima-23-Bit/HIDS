```markdown
# HIDS (Host-based Intrusion Detection System)

## Prerequisites  
Ensure that you have the following installed on your local machine:  
- Python 3.x  
- pip  
- virtualenv  
- Root access on your machine  

## Setting Up  
Follow these steps to get a local copy of the code:  
1. Clone the repository:  
```bash  
git clone https://github.com/midhunsankar23/HIDS.git  
```  
2. Navigate to the project directory:  
```bash  
cd HIDS  
```  
3. Create a virtual environment:  
```bash  
python3 -m venv venv  
```  
4. Activate the virtual environment:  
```bash  
source venv/bin/activate  
```  
5. Install the required dependencies:  
```bash  
pip install -r requirements.txt  
```  

## Running the Application  
Follow these steps to run the application:  
1. Open two terminals with root access:  
```bash  
sudo su  
```  
2. In both terminals, navigate to the project directory and activate the virtual environment:  
```bash  
source venv/bin/activate  
```  
3. In the first terminal, run the main application:  
```bash  
python3 app.py  
```  
4. In the second terminal, set up the `iptables` rules to redirect packets to a Netfilter queue (NFQUEUE):  
```bash  
iptables -I INPUT -j NFQUEUE --queue-num 0  
iptables -I OUTPUT -j NFQUEUE --queue-num 0  
```  
5. Still in the second terminal, run the packet capture script:  
```bash  
python3 packet_capture.py  
```  
6. After running the application, clear the `iptables` rules to restore normal network activity:  
```bash  
iptables --flush  
```
```
