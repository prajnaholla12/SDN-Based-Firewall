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
- any→port 80: blocked (port rule)

## Expected Output
- Flow table shows drop rules for H4
- firewall_log.txt shows [BLOCKED] entries with timestamps
- iperf shows normal throughput between allowed hosts

## Tools Used
- Mininet, Ryu (OpenFlow 1.3), Wireshark, iperf, ovs-ofctl
