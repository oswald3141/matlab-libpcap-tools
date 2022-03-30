clearvars
clc

% Read the pcap file with pseudo-random UDP/IP packets in it packed into
% the Ethernet frames. Extract the payload.

%   The code is distributed under The MIT License
%   Copyright (c) 2022 Andrey Smolyakov
%       (andreismolyakow 'at' gmail 'punto' com)
%   See LICENSE for the complete license text

filename = "./example_pcap_file.pcap";

[global_header, packet_header, packet_data, file_format] = ...
                                        read_pcap_file(filename);

N_pkts = length(packet_header);

for i = N_pkts:-1:1
    % You can perform packet filtering based on the headers here
    [eth_hdr_num(i), eth_hdr_str(i), ip_packet(i).bytes] = ...
        parse_ethernet_frame(packet_data(i).bytes);

    [ip_hdr_num(i), ip_hdr_str(i), udp_packet(i).bytes] = ...
        parse_ipv4_packet(ip_packet(i).bytes);

    [udp_hdr_num(i), udp_hdr_str(i), payload(i).bytes] = ...
        parse_udp_packet(udp_packet(i).bytes);
end
