function [eth_hdr_num, eth_hdr_str, payload] = parse_ethernet_frame(frame)
%PARSE_ETHERNET_FRAME Parse an Etehrnet frame read from a pcap file
%   Splits the frame into the header (eth_hdr_num) and payload (payload).
%   Also returns the header with all the fields converted into the HEX
%   strings (eth_hdr_str).
%
%   Implies, that the frames were captured with libpcap, so they do not
%   have Preamble, Start frame delimiter, FCS and interpacket gap.
%
%   The Ethernet frames with IEEE 802.1Q and IEEE 802.1ad tags are not
%   supported.
%
%   eth_hdr_num is more convinient to use in the code, while eth_hdr_str is
%   more comprehensible for a human's eye.
%
%   See also read_pcap_file, parse_ipv4_packet, parse_udp_packet

%   The code is distributed under The MIT License
%   Copyright (c) 2022 Andrey Smolyakov
%       (andreismolyakow 'at' gmail 'punto' com)
%   See LICENSE for the complete license text

arguments
    frame {mustBeVector, mustBeA(frame,"uint8")}
end

if (length(frame) < 60 || length(frame) > 1518)
    throwAsCaller(MException("parse_ethernet_frame:incorrectFrameSize", ...
        "The Ethernet frame has incorrect size."));
end

% Wireshark drops Preamble, Start frame delimiter, FCS and interpacket gap
% IEEE 802.1Q and IEEE 802.1ad frames are not supported
HEADER_LENGTH = 14;

header  = frame(1:HEADER_LENGTH);
payload = frame(HEADER_LENGTH+1:end);

MAC_dst    = header( 1: 6);
MAC_src    = header( 7:12);
Ethertype  = typecast(header(14:-1:13)', "uint16");

if (Ethertype <= 1500)     % IEEE 802.3
    payld_size = Ethertype;
    Ethertype  = [];
    if (payld_size ~= length(payload)) % Check payload size if possible
        throw(MException("parse_ethernet_frame:invalidPayloadSize", ...
            "Frame's contains invalid payload size in its header. " + ...
            "The frame is probably corrupted"));
    end
elseif (Ethertype >= 1536) % Ethernet II
    payld_size = [];
else
    throw(MException("parse_ethernet_frame:invalidEthertype", ...
        "Frame's Ethertype field denotes neither actual Ethertype, " + ...
        "nor the payload size. The frame is probably corrupted"));
end

eth_hdr_num = struct( ...
    "MAC_dst",      MAC_dst,   ...
    "MAC_src",      MAC_src,   ...
    "Ethertype",    Ethertype, ...
    "Payload_size", payld_size ...
);

eth_hdr_str = struct( ...
    "MAC_dst",      join(string(dec2hex(MAC_dst,   2)), ":"), ...
    "MAC_src",      join(string(dec2hex(MAC_src,   2)), ":"), ...
    "Ethertype",                dec2hex(Ethertype, 4)       , ...
    "Payload_size", payld_size ...
);

end
