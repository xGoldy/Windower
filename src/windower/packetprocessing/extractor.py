"""
Extracts interesting data and metadata from packets.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-21
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import scapy.packet
import scapy.layers.inet
import scapy.layers.inet6
import scapy.layers.l2

from common.time import sec2nsec
from dataclasses import dataclass
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.sctp import SCTP


# Define L4 protocols numbers manually, since they cannot be assigned from L3 header due to IPv6 extension headers
# We also do not care for SCTP due to its negligible usage in modern networks
PROTO_L4_ICMP = 1           # L4 ICMP identifier. Used for ICMPv6 for simplification
PROTO_L4_TCP  = 6           # L4 TCP identifier
PROTO_L4_UDP  = 17          # L4 UDP identifier
PROTO_L4_SCTP = 132         # L4 SCTP identifier


@dataclass
class PacketFeatures:
    """Class representing extracted features from the packet."""
    time:        int  = 0       # Packet arrival time
    src_ip:      str  = None    # Source IP address
    dst_ip:      str  = None    # Destination IP address
    proto_l4:    int  = 0       # Identifier of the L4 protocol (TCP/UDP/ICMP/ICMPv6)
    src_port:    int  = 0       # Source port (if present)
    dst_port:    int  = 0       # Destination port (if present)
    len_headers: int  = 0       # Length of the L3 + L4 headers
    len_payload: int  = 0       # Length of the upper layer data (L7, headers included)
    fragmented:  bool = False   # Indicator whether the packet is fragmented


def extract_features(pkt: scapy.packet.Packet):
    """Extracts important features (time, IP lengths, port, etc.) from the packet.
    Only IPv4 or IPv6 L3 headers are expected.

    Parameters:
        pkt             Packet to extract data from

    Returns:
        None upon error or unexpected L3 header, PacketFeatures object otherwise."""

    features = PacketFeatures()
    features.time = sec2nsec(pkt.time)

    try:
        # Determine source IP and packet length according to the type of L3 header
        if IP in pkt:
            features.src_ip      = pkt[IP].src
            features.dst_ip      = pkt[IP].dst
            features.len_headers = pkt[IP].ihl * 4
            features.len_payload = len(pkt[IP]) - features.len_headers
            features.fragmented  = pkt[IP].frag > 0 or pkt[IP].flags == 'MF'
        elif IPv6 in pkt:
            features.src_ip      = pkt[IPv6].src
            features.dst_ip      = pkt[IPv6].dst
            features.len_headers = 40
            features.len_payload = pkt[IPv6].plen

            # Check for extension header for fragmentation
            if IPv6ExtHdrFragment in pkt:
                features.fragmented = True
        else:
            # Return None when unsupported L3 header (other than IP) is received
            return None

        # Acquire port number and adjust header sizes (IPv6 may have extension headers)
        if TCP in pkt:
            # TCP header length as dataoffs field * 4 (defines number of 32-words)
            features.proto_l4     = PROTO_L4_TCP
            features.src_port     = pkt[TCP].sport
            features.dst_port     = pkt[TCP].dport
            features.len_headers += features.len_payload - len(pkt[TCP]) + pkt[TCP].dataofs * 4
            features.len_payload  = len(pkt[TCP]) - pkt[TCP].dataofs * 4
        elif UDP in pkt:
            # UDP header as 8B long
            # QUIC encapsulated in UDP is considered payload, can be changed in future versions
            features.proto_l4     = PROTO_L4_UDP
            features.src_port     = pkt[UDP].sport
            features.dst_port     = pkt[UDP].dport
            features.len_headers += features.len_payload - len(pkt[UDP]) + 8
            features.len_payload  = pkt[UDP].len - 8
        elif SCTP in pkt:
            # SCTP common header of 12 bytes + data chunks as payload
            features.proto_l4     = PROTO_L4_SCTP
            features.src_port     = pkt[SCTP].sport
            features.dst_port     = pkt[SCTP].dport
            features.len_headers += features.len_payload - len(pkt[SCTP]) + 12
            features.len_payload  = len(pkt[SCTP]) - 12
        elif ICMP in pkt:
            # Expect flat 8 bytes for ICMP echo request/reply as usual
            # Other ICMP types will be considered as 8B for header + payload
            features.proto_l4     = PROTO_L4_ICMP
            features.len_headers += features.len_payload - len(pkt[ICMP]) + 8
            features.len_payload  = len(pkt[ICMP]) - 8
        elif ICMPv6EchoRequest in pkt:
            # Special case of ICMPv6 echo request to extract ping floods
            # Header length of 8 bytes
            features.proto_l4     = PROTO_L4_ICMP
            features.len_headers += features.len_payload - len(pkt[ICMPv6EchoRequest]) + 8
            features.len_payload  = len(pkt[ICMPv6EchoRequest]) - 8
        elif ICMPv6EchoReply in pkt:
            # Special case of ICMPv6 echo reply to extract ping floods
            # Header length of 8 bytes
            features.proto_l4     = PROTO_L4_ICMP
            features.len_headers += features.len_payload - len(pkt[ICMPv6EchoReply]) + 8
            features.len_payload  = len(pkt[ICMPv6EchoReply]) - 8
    except:
        # If this fires, the packet is probably improperly cut (such as with missing L4 header)
        return None

    return features


def extract_features_caida(pkt: scapy.packet.Packet, arrival_tstamp: float = None):
    """Extracts important features (time, IP lengths, port, etc.) from the packet for CAIDA-dataset like packets.
    These packets are characterized by missing L2 headers and L4 payloads. Therefore, different principles of features
    extraction are used.  Since nanosecond precision timestamps are present in separate files, they can be supplied
    separately as arrival_tstamp function parameter, which will be used as a packet arrival timestamp instead of the
    value written directly in PCAP file.  If this parameter is None, the original timestamp is used
    Only IPv4 or IPv6 L3 headers are expected.
    Note: Although both extractor functions share a lot of common code, they are provided separately to avoid
    unnecessary IF-ing, which would decrease performance even further.

    Parameters:
        pkt             Packet to extract data from
        arrival_tstamp  Packet arrival timestamp in seconds or None if originally extracted timestamps should be used

    Returns:
        None if unexpected L3 header is received, PacketFeatures object otherwise."""

    features      = PacketFeatures()            # Packet features
    timedata      = 0                           # Time data obtained from a desired source
    true_pkt_len  = 0                           # Number of bytes for L3-L7 captured data

    # Load timestamps from a desired time source and convert to nanoseconds
    if arrival_tstamp is not None:
        timedata = arrival_tstamp
    else:
        timedata = pkt.time

    features.time = sec2nsec(timedata)

    try:
        # Determine source IP and packet length according to the type of L3 header
        if IP in pkt:
            # There was a case when a packet reported 0 as its length, causing the program to crash
            if pkt[IP].len == 0:
                return None

            features.src_ip      = pkt[IP].src
            features.dst_ip      = pkt[IP].dst
            features.len_headers = pkt[IP].ihl * 4
            features.len_payload = pkt[IP].len - features.len_headers

            true_pkt_len = len(pkt[IP])
        elif IPv6 in pkt:
            features.src_ip      = pkt[IPv6].src
            features.dst_ip      = pkt[IPv6].dst
            features.len_headers = 40
            features.len_payload = pkt[IPv6].plen

            true_pkt_len = len(pkt[IPv6])
        else:
            # Return None when unsupported L3 header (other than IP) is received
            return None

        # Acquire port number and adjust header sizes (IPv6 may have extension headers)
        if TCP in pkt:
            # TCP header length as dataoffs field * 4 (defines number of 32-words)
            features.proto_l4     = PROTO_L4_TCP
            features.src_port     = pkt[TCP].sport
            features.dst_port     = pkt[TCP].dport

            features.len_payload -= (true_pkt_len - len(pkt[TCP]) - features.len_headers) + pkt[TCP].dataofs * 4
            features.len_headers  = true_pkt_len - len(pkt[TCP]) + pkt[TCP].dataofs * 4
        elif UDP in pkt:
            # UDP header as 8B long
            # QUIC encapsulated in UDP is considered payload, can be changed in future versions
            features.proto_l4     = PROTO_L4_UDP
            features.src_port     = pkt[UDP].sport
            features.dst_port     = pkt[UDP].dport

            features.len_payload -= (true_pkt_len - len(pkt[UDP]) - features.len_headers) + 8
            features.len_headers  = true_pkt_len - len(pkt[UDP]) + 8
        elif SCTP in pkt:
            # SCTP common header of 12 bytes + data chunks as payload
            features.src_port     = pkt[SCTP].sport
            features.dst_port     = pkt[SCTP].dport

            features.len_payload -= (true_pkt_len - len(pkt[SCTP]) - features.len_headers) + 12
            features.len_headers  = true_pkt_len - len(pkt[SCTP]) + 12
        elif ICMP in pkt:
            # Expect flat 8 bytes for ICMP echo request/reply as usual
            # Other ICMP types will be considered as 8B for header + payload
            features.proto_l4     = PROTO_L4_ICMP

            features.len_payload -= (true_pkt_len - len(pkt[ICMP]) - features.len_headers) + 8
            features.len_headers  = true_pkt_len - len(pkt[ICMP]) + 8
        elif ICMPv6EchoRequest in pkt:
            # Special case of ICMPv6 echo request to extract ping floods
            # Header length of 8 bytes
            features.proto_l4     = PROTO_L4_ICMP

            features.len_payload -= (true_pkt_len - len(pkt[ICMPv6EchoRequest]) - features.len_headers) + 8
            features.len_headers  = true_pkt_len - len(pkt[ICMPv6EchoRequest]) + 8
        elif ICMPv6EchoReply in pkt:
            # Special case of ICMPv6 echo reply to extract ping floods
            # Header length of 8 bytes
            features.proto_l4     = PROTO_L4_ICMP

            features.len_payload -= (true_pkt_len - len(pkt[ICMPv6EchoReply]) - features.len_headers) + 8
            features.len_headers  = true_pkt_len - len(pkt[ICMPv6EchoReply]) + 8
    except:
        # If this fires, the packet is probably improperly cut (such as with missing L4 header)
        return None

    return features
