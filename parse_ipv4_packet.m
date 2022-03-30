function [ip_hdr_num, ip_hdr_str, payload] = parse_ipv4_packet(packet)
%PARSE_IPV4_PACKET Parse an IPv4 packet read from a pcap file
%   Splits the packet into the header (ip_hdr_num) and payload (payload).
%   Also returns the header with all the fields converted into the strings
%   of more comprehensible format (ip_hdr_str).
%
%   ip_hdr_num is more convinient to use in the code, while ip_hdr_str is
%   more comprehensible for a human's eye.
%
%   See also parse_ethernet_frame, read_pcap_file, parse_udp_packet

%   The code is distributed under The MIT License
%   Copyright (c) 2022 Andrey Smolyakov
%       (andreismolyakow 'at' gmail 'punto' com)
%   See LICENSE for the complete license text

arguments
    packet {mustBeVector, mustBeA(packet,"uint8")}
end

if (length(packet) < 20 || length(packet) > 65536)
    throwAsCaller(MException("parse_ipv4_packet:incorrectPacketSize", ...
        "The IP packet has incorrect size."));
end

% Parsing the packet into the integer fields
ip_hdr_num = struct( ...
    "version",      bitshift(bitand(packet(1),0b11110000),-4), ...
    "IHL",          bitand(packet(1),0b00001111),              ...
    "DSCP",         bitshift(bitand(packet(2),0b11111100),-2), ...
    "ECN",          bitand(packet(2),0b00000011),              ...
    "total_length", typecast(packet(4:-1:3), "uint16"),        ...
    "ID",           typecast(packet(6:-1:5), "uint16"),        ...
    "flags",        bitshift(bitand(packet(7),0b11100000),-5), ...
    "fragm_offset", typecast([packet(8) bitand( ...
                            packet(7),0b00011111)], "uint16"), ...
    "TTL",          packet(9),                                 ...
    "protocol",     packet(10),                                ...
    "hdr_checksum", typecast(packet(12:-1:11), "uint16"),      ...
    "src_addr",     packet(13:16),                             ...
    "src_addr_u32", typecast(packet(16:-1:13), "uint32"),      ...
    "dst_addr",     packet(17:20),                             ...
    "dst_addr_u32", typecast(packet(20:-1:17), "uint32"),      ...
    "options",      []                                         ...
);

% Additional packet correctness checks
if (ip_hdr_num.version ~= 4)
    throw(MException("parse_ipv4_packet:unsopportedIpVersion", ...
        "The packet's IP version is not sopported."));
end

if (ip_hdr_num.IHL < 5 || ip_hdr_num.IHL*4 > length(packet))
    throw(MException("parse_ipv4_packet:incorrectIhlField", ...
        "The IP packet has incorrect IHL field value."));
end

% Extract the options field. It's safe now due to the previous check
ip_hdr_num.options = packet(21:double(ip_hdr_num.IHL*4));

% Convert the fields into a more comprehesnible format
ip_hdr_str              = ip_hdr_num;
ip_hdr_str.ECN          = dec2bin(ip_hdr_num.ECN,  2);
ip_hdr_str.flags        = dec2bin(ip_hdr_num.flags,3);
ip_hdr_str.protocol     = dec2hex(ip_hdr_num.protocol,2);
ip_hdr_str.hdr_checksum = dec2hex(ip_hdr_num.hdr_checksum,4);
ip_hdr_str.src_addr     = join(string(ip_hdr_num.src_addr),".");
ip_hdr_str.dst_addr     = join(string(ip_hdr_num.dst_addr),".");

% Extracting the payload
payload = packet(double(ip_hdr_num.IHL*4+1):end);

end
