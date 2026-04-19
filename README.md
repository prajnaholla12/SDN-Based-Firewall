# SDN-Based Firewall using Mininet + Ryu

## Problem Statement
Implement an SDN controller-based firewall that filters traffic between 
hosts based on IP address, MAC address, and TCP port rules.

## Setup
1. Install Mininet: `sudo apt-get install mininet`
2. Install Ryu: `pip install ryu`
3. Clone this repo: `git clone <your-repo>`

## Running
1. Terminal 1: `ryu-manager firewall_controller.py`
2. Terminal 2: `sudo python3 topology.py`

## Test Scenarios
- H1↔H2↔H3: allowed (ping works)
- H4→any: blocked (IP block rule)
- any→port 22: blocked (port rule)
# 🔥 SDN Firewall using Ryu Controller


- MAC Address (Layer 2)
- IP Address / ICMP (Layer 3)
- TCP Port (Layer 4)

---

##  Key Concept

In SDN:
- **Controller (Ryu)** → Makes decisions  
- **Switch (OpenFlow)** → Forwards packets  

This enables centralized and programmable network control.

---

## Network Topology

- 1 Switch → `s1`
- 4 Hosts:
  - `h1` → 10.0.0.1  
  - `h2` → 10.0.0.2  
  - `h3` → 10.0.0.3  
  - `h4` → 10.0.0.4  

All hosts are connected to a single switch.

```
h1 ----\
h2 ----- s1 ---- Controller (Ryu)
h3 ----/
h4 ----/
```

---

## 🔒 Firewall Rules

### ICMP Blocking (IP-based)
Blocks ping (ICMP) traffic to:
```
10.0.0.4 (h4)
```

Example:
- h1 → h4  
- h2 → h4  
- h3 → h4 

---

###  MAC Address Blocking
Blocks all traffic involving:
```
00:00:00:00:00:02 (h2)
```

 Example:
- h1 → h2 
- h3 → h2 
- h2 → any 

---

### 3️⃣ TCP Port Blocking
Blocks TCP traffic on:
```
Port 22 (SSH)
```

---

## How It Works

1. Packet arrives at switch  
2. Switch sends packet to controller (`packet_in`)  
3. Controller checks:
   - MAC address  
   - IP / ICMP  
   - TCP port  
4. If rule matches → packet is dropped  
5. Else → packet is forwarded  

---

##  Logging

Blocked packets are logged in the controller:

```
[BLOCKED ICMP] 10.0.0.1 -> 10.0.0.4
[BLOCKED MAC] 00:00:00:00:00:01 -> 00:00:00:00:00:02
[BLOCKED TCP] 10.0.0.1 -> 10.0.0.3 PORT 22
```


---

##  Setup & Execution

### 1. Clean previous runs
```bash
sudo mn -c
```

### 2. Start Ryu Controller
```bash
source ~/ryu-env/bin/activate
python -m ryu.cmd.manager firewall_controller.py
```

### 3. Run Topology
```bash
sudo python3 topology.py
```

---

## 🧪 Testing

### ICMP Blocking
```bash
h1 ping h4
h2 ping h4
```

### MAC Blocking
```bash
h1 ping h2
h3 ping h2
```

### TCP Port Blocking
```bash
h1 telnet 10.0.0.3 22
h1 telnet 10.0.0.4 22
```

### Allowed Traffic
```bash
h1 ping h3
```

---
## Expected Output
- Flow table shows drop rules for H4
- firewall_log.txt shows [BLOCKED] entries with timestamps
- iperf shows normal throughput between allowed hosts

## Tools Used
- Mininet, Ryu (OpenFlow 1.3), Wireshark, iperf, ovs-ofctl
