#!/bin/bash

# Directory to store pcap files
PCAP_DIR="/tmp/pcap_files"
mkdir -p $PCAP_DIR

# Duration of capture in seconds
DURATION=60

# Start tcpdump on each host
for host in $(seq 1 4); do
    h="h$host"
    echo "Starting packet capture on $h..."
    sudo mnexec -a $(pgrep -f "mininet: $h") tcpdump -i $h-eth0 -w $PCAP_DIR/$h.pcap &
done

# Sleep for the duration of the capture
sleep $DURATION

# Stop all tcpdump processes
echo "Stopping packet capture..."
sudo pkill tcpdump
