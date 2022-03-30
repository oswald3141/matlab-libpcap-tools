function [udp_hdr_num, udp_hdr_str, payload] = parse_udp_packet(packet)
%PARSE_UDP_PACKET Parse a UDP packet read from a pcap file
%   Splits the packet into the header (udp_hdr_num) and payload (payload).
%   Also returns the header with all the fields converted into the strings
%   of more comprehensible format (udp_hdr_str).
%
%   udp_hdr_num is more convinient to use in the code, while udp_hdr_str is
%   more comprehensible for a human's eye.
%
%   See also parse_ethernet_frame, parse_ipv4_packet, read_pcap_file

%   The code is distributed under The MIT License
%   Copyright (c) 2022 Andrey Smolyakov
%       (andreismolyakow 'at' gmail 'punto' com)
%   See LICENSE for the complete license text

arguments
    packet {mustBeVector, mustBeA(packet,"uint8")}
end

if (length(packet) < 8 || length(packet) > 65536)
    throwAsCaller(MException("parse_udp_packet:incorrectPacketSize", ...
        "The UDP packet has incorrect size."));
end

header  = packet(1:8);
payload = packet(9:end);

udp_hdr_num = struct( ...
    "port_src", typecast(header(2:-1:1), "uint16"), ...
    "port_dst", typecast(header(4:-1:3), "uint16"), ...
    "length",   typecast(header(6:-1:5), "uint16"), ...
    "checksum", typecast(header(8:-1:7), "uint16")  ...
);

if (udp_hdr_num.length ~= length(packet))
    throw(MException("parse_udp_packet:incorrectLengthField", ...
        "The UDP packet has incorrect length field value."));
end

udp_hdr_str = udp_hdr_num;
udp_hdr_str.checksum = dec2hex(udp_hdr_num.checksum, 4);

end
