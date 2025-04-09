# D-SHIELD
IoT Gateway Setup - README
IoT Gateway Setup - README
This document outlines the configuration and tools used to build a Privacy-Focused IoT
Security Gateway. It provides internet access, static IP management, and real-time traffic
analysis with packet inspection and alerting.
--------------------------------------------------
1. Tools Used
1.1 `hostapd`
- **Purpose**: Create a Wi-Fi access point.
- **Config File**: `/etc/hostapd/hostapd.conf`
- **Sample Config:**
```
interface=wlan0
ssid=IoT_Gateway
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=SecurePass123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```
1.2 `dnsmasq`
- **Purpose**: Acts as a lightweight DHCP and DNS server.
- **Config File**: `/etc/dnsmasq.conf`
- **Sample Config:**
```
interface=wlan0
dhcp-range=192.168.2.10,192.168.2.100,255.255.255.0,24h
dhcp-option=3,192.168.2.1
dhcp-host=AA:BB:CC:DD:EE:FF,192.168.2.20
```
1.3 `iptables`
- **Purpose**: Network Address Translation (NAT) and firewall rules.
- **Used Commands:**
```
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o ens33 -j ACCEPT
sudo iptables -A FORWARD -i ens33 -o wlan0 -m state --state RELATED,ESTABLISHED -j
ACCEPT
```
1.4 `nmap`
- **Purpose**: Network scanning and device discovery.
- **Typical Command:**
```
nmap -sn 192.168.2.0/24 -oN /home/project/D-SHIELD/logs/nmap.log
```
1.5 `tshark`
- **Purpose**: Real-time packet capture.
- **Command Example:**
```
tshark -i wlan0 -w /home/project/D-SHIELD/logs/tshark_output.pcap
```
1.6 `snort`
- **Purpose**: Intrusion detection and alerting system.
- **Command:**
```
sudo snort -q -A console -i wlan0 -c /etc/snort/snort.conf | tee -a /home/project/DSHIELD/logs/snort.log
```
- **Custom Rules Location:** `/etc/snort/rules/local.rules`
Example Snort Rule (only allow Nmap scans from 192.168.2.1):
```
alert tcp !192.168.2.1 any -> 192.168.2.0/24 any (msg:"Unauthorized Nmap scan detected";
sid:1000008; rev:1;)
```
--------------------------------------------------
2. Logs
- **Nmap Log**: `/home/project/D-SHIELD/logs/nmap.log`
- **Snort Log**: `/home/project/D-SHIELD/logs/snort.log`
- **Tshark Capture**: `/home/project/D-SHIELD/logs/tshark_output.pcap`
--------------------------------------------------
3. Security and Monitoring
- Snort rules block suspicious traffic and unauthorized port scans.
- Scheduled Nmap scans detect unknown devices.
- Tshark captures real-time traffic for forensic analysis.
- Snort logs are stored in human-readable format:
```
tail -f /home/project/D-SHIELD/logs/snort.log
```
