Simple building block script for inspecting packets flying across an interface/pcap file. Concatenates fragmented packets. Prints a 1 line packet summary if the packet has a TCP layer and a load. Meant to be built out to find specific information from packets.


Auto-detect the interface to sniff
```sudo python net-sniffer.py```

Choose eth0 as the interface
```sudo python net-sniffer.py -i eth0```

Read from pcap
```sudo python net-sniffer.py -p pcapfile```
