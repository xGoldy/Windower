"""
Creates a separate file with 0/1 ground truth labelling based on provided IP file.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-07-03
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Usage:
python labeldataset.py <in_PCAP> <in_attack_ips> <out_labels>
"""

import scapy
import scapy.utils
import sys

from typing import Optional
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def extract_src_ip(pkt) -> Optional[str]:
    src_ip = None

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src

    return src_ip


def main(args : list) -> None:
    in_pcap_filename      = args[1]
    in_attck_ips_filename = args[2]
    out_labels_filename   = args[3]

    labels          = []        # Final labels to be written into the file
    attack_ips      = set()     # List of attacking IPs
    in_pcap_reader  = None      # Input PCAP file reader

    # Open PCAP file reader
    in_pcap_reader = scapy.utils.PcapReader(in_pcap_filename)

    # Open Attacking IPs file and load them to a set
    with open(in_attck_ips_filename, 'r') as attacking_ips_file:
        attack_ips = set(attacking_ips_file.read().split())

    # Read packet-by-packet from the file and create a labeled list
    for pkt in in_pcap_reader:
        # Determine packet source IP
        src_ip = extract_src_ip(pkt)

        # Create label based on the source IP presence in the list of attackers
        labels.append('1') if src_ip in attack_ips else labels.append('0')

    # Open output file and write packet ground truths into it
    with open(out_labels_filename, 'w') as labels_file:
        labels_file.write('\n'.join(labels) + '\n')

    in_pcap_reader.close()


if __name__ == '__main__':
    main(sys.argv)
