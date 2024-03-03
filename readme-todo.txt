Configuration and Tuning: configure detection rules, thresholds, and other parameters

     <a href="#">Home</a>
            <a href="#">Report</a>
            <a href="#">Alerts</a>
            <a href="#">Traffic Visualization</a>
            <a href="#">Configuration</a>
            <a href="#">Blocked Connections</a>
            <a href="#">Blacklist</a>
            <a href="#">Blacklist URLs</a>
            <a href="#">Blacklist IPs</a>
            <a href="#">Tuning</a>
            <a href="#">Block Ports</a>

If you're running this on your local machine, you need to queue the incoming and outgoing packets to NFQUEUE. You can do this by setting up the following iptables rules:

iptables -I OUTPUT -j NFQUEUE --queue-num 0  
iptables -I INPUT -j NFQUEUE --queue-num 0  
 
These commands tell iptables to queue both incoming and outgoing packets to NFQUEUE number 0, which is the queue that your Python script is listening on.

Remember, these commands require administrative permissions and should be run in the terminal.

When you're done or if you want to stop queuing packets, don't forget to flush the iptables rules:

iptables --flush  
 
This command will clear all iptables rules and stop queuing packets to NFQUEUE. This is important to remember because forgetting to do this can result in all your network traffic being queued indefinitely, which might cause network connectivity issues.

iptables --flush  
(venv) root@15s-dr0xxx:/home/midhun/Desktop/Hima# iptables -I INPUT -j NFQUEUE --queue-num 0  && iptables -I OUTPUT -j NFQUEUE --queue-num 0