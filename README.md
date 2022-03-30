# MATLAB tools for libpcap
Provides some functions to work with \*.pcap-files.

## Content
### Functions
- `read_pcap_file` reads a pcap-file into the set of structures for further analysis.
- `parse_ethernet_frame` splits the captured Ethernet frame into a structure describing its header and the bytes array representing the frame's payload.
- `parse_ipv4_packet` does the same for the IPv4 packets extracted from the frames.
- `parse_udp_packet` does the same for the UPD packets extracted from the IPv4 packets.
### Examples
- `pcap_file_reading_example` reads the file `example_pcap_file.pcap` with the captured pseudo-random UDP packets and parses them.

## Dependencies
MATLAB 2021b or newer.
