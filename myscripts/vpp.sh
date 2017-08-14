#!/bin/bash

# Configure VPP
if pidof vpp; then
       sudo kill `pidof vpp`
       sleep 5
fi
sudo vpp "api-trace { on } dpdk { dev 0000:00:09.0 }"
sleep 5
if [[ $(hostname) == "netplugin-node1" ]]; then
       sudo vppctl set int ip address GigabitEthernet0/9/0 192.168.3.10/24
else
       sudo vppctl set int ip address GigabitEthernet0/9/0 192.168.3.11/24
fi
sudo vppctl set interface state GigabitEthernet0/9/0 up