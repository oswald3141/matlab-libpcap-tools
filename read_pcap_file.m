function [global_header, packet_header, packet_data, file_format] = ...
                                                       read_pcap_file(file)
%READ_PCAP_FILE Read a file of the libpcap format
%   Reads the file and returns the global file header (global_header),
%   array with the captured packets headers (packet_header) and array with
%   these packets' data (packet_data), represented as a simple array of
%   bytes.
%
%   Works only with the old libpcap file format (*.pcap). Doesn't work with
%   the new PCAP Next Generation Capture File Format (*.pcapng).
%   Supports standard libpcap file format and the nanosecond format.
%
%   To save the captured packets into pcap-file in Wireshark press "Save
%   this capture file" button on the menu bar, change the file format from
%   pcapng to pcap in a dropdown list in the dialog window, and click Save.
% 
%   For the further details about libpcap file format, please, refer to
%   https://wiki.wireshark.org/Development/LibpcapFileFormat
%
%   See also parse_ethernet_frame, parse_ipv4_packet, parse_udp_packet

%   The code is distributed under The MIT License
%   Copyright (c) 2022 Andrey Smolyakov
%       (andreismolyakow 'at' gmail 'punto' com)
%   See LICENSE for the complete license text

arguments
    file {mustBeFile}
end

if ~isequal(regexpi(file, ".*\.pcap$"),1)
    throwAsCaller(MException("read_pcap_file:notPcapFile", ...
        "The file is not of a valid libpcap format."));
end

fileID = fopen(file,'r');

magic_number  = fread(fileID,1,'*uint32');
machinefmt    = 'l';

% Detect file format and the bytes ordering
switch (magic_number)
    case {0xa1b2c3d4, 0xd4c3b2a1}
        file_format = 'standard';
        rev_bytes_ord = (magic_number == 0xd4c3b2a1);
    case {0xa1b23c4d, 0x4dc3b2a1}
        file_format = 'nanosecond';
        rev_bytes_ord = (magic_number == 0x4dc3b2a1);
    case {0xa1b2cd34, 0x34cdb2a1}
        file_format = 'modified'; %#ok<NASGU> 
        rev_bytes_ord = (magic_number == 0x34cdb2a1); %#ok<NASGU> 
        throw(MException('read_pcap_file:unsupportedFormat', ...
            '"Modified" pcap format is not supported.'))
    case {0x1c0001ac, 0xac01001c}
        file_format = 'IXIA_hard'; %#ok<NASGU> 
        rev_bytes_ord = (magic_number == 0xac01001c); %#ok<NASGU> 
        throw(MException('read_pcap_file:unsupportedFormat', ...
            'IXIA hardware generated pcap format is not supported.'))
    case {0x01c0001ab, 0xab01001c}
        file_format = 'IXIA_soft'; %#ok<NASGU> 
        rev_bytes_ord = (magic_number == 0xab01001c); %#ok<NASGU> 
        throw(MException('read_pcap_file:unsupportedFormat', ...
            'IXIA software generated pcap format is not supported.'))
    otherwise
        file_format = 'unknown'; %#ok<NASGU> 
        throw(MException('read_pcap_file:unknownFormat', ...
            'The pcap file format is not recognized.'))
end

if rev_bytes_ord
    magic_number = swapbytes(magic_number);
    machinefmt   = 'b';
end

% pcap_hdr_t type
global_header = struct( ...
    'magic_number', magic_number,             ... magic number
    'version_major', ...
        fread(fileID,1,'*uint16',machinefmt), ... major version number
    'version_minor', ...
        fread(fileID,1,'*uint16',machinefmt), ... minor version number
    'thiszone',...
        fread(fileID,1,'*int32' ,machinefmt), ... GMT to local correction
    'sigfigs', ...
        fread(fileID,1,'*uint32',machinefmt), ... accuracy of timestamps
    'snaplen', ...
        fread(fileID,1,'*uint32',machinefmt), ... max packet length octets
    'network', ...
        fread(fileID,1,'*uint32',machinefmt)  ... data link type
);

% pcaprec_hdr_t type
packet_header = struct( ...
    'ts_sec',   [], ... timestamp seconds
    'ts_usec',  [], ... timestamp microseconds
    'incl_len', [], ... number of octets of packet saved in file
    'orig_len', []  ... actual length of packet
);

% Not a libpcap type, just arrays for the data
packet_data = struct('bytes',[]);

i = 1;
while (true)
    ts_sec = fread(fileID,1,'*uint32',machinefmt);
    
    % Break, if the EOF has been reached
    if ( isempty(ts_sec) )
        break;
    end

    % Fill pcaprec_hdr_t structure
    packet_header(i).ts_sec   = ts_sec;
    packet_header(i).ts_usec  = fread(fileID,1,'*uint32',machinefmt);
    packet_header(i).incl_len = fread(fileID,1,'*uint32',machinefmt);
    packet_header(i).orig_len = fread(fileID,1,'*uint32',machinefmt);

    % Read the packet data
    packet_data(i).bytes = ...
        fread(fileID,packet_header(i).incl_len,'*uint8',machinefmt);

    i = i + 1;
end

fclose(fileID);

end
