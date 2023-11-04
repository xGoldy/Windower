"""
Creates a train-test dataset splits from PCAP files respecting data snoping
(does not include the same IP address data within both sets).

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-06-01
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Use the variables in "Program Settings" source code section to customize the
program and create a dataset based on given PCAP and its statistics as args.
The script requires a statistics file created by tshark regarding the given
PCAP to exist. If it does not, use the following command:
tshark -r <file.pcap> -q -z ip_srcdst,tree > <file.ipstats>

Usage:
python traintest_splitter.py <pcap_path.pcap> <stats_file.ipstats> <ignore_ips_filepath.txt>

pcap_path.pcap
    - PCAP file to extract packets from
stats_file.ipstats
    - statistics file about IPs communication using tshark
ignore_ips_filepath.txt
    - list of whitespace-delimited string-represented IPs to ignore
    - do not use this argument (leave empty) if no IPs should be ignored
"""

import os
import random
import scapy
import scapy.utils
import sys

from tqdm import tqdm
from typing import Optional
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


###############################################################################
############################   Program Settings   #############################
###############################################################################

# How many IPs to include in train and test sets
TRAIN_IPS_CNT  = 0
TEST_IPS_CNT   = 20

# Minimum and maximum number of packets eligible for selection into train/test data
SELECTION_PKTS_MIN = 75000
SELECTION_PKTS_MAX = 150000

# If true, only IP addresses for train and test splits are returned
RETURN_IPS_ONLY  = False
DUMP_IPS_DIVISON = True

# Technique for IP addresses selection
# Available options: random, mostactive, leastactive
# Note that when the number of available IPs is lesser than
IP_SELECTION_TECHNIQUE = 'random'


###############################################################################
#############################   Program itself   ##############################
###############################################################################
def extract_src_ip(pkt) -> Optional[str]:
    src_ip = None

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src

    return src_ip


def parse_ipstats(ipstats_lst : list) -> dict:
    resultdict = {}

    # Skip the first 7 lines
    ipstats_lst = ipstats_lst[5:]

    for ipstats_line in ipstats_lst:
        ipstats_words = ipstats_line.split()

        # Solve specific cases of the tshark's output
        if ipstats_words[0] == 'Source':
            # All IPv4 addresses have been processed let's go for IPv6
            continue
        elif ipstats_words[0] == 'Destination':
            # Break the loop upon reading all source IP addresses
            break

        ip = ipstats_words[0]
        pkts = int(ipstats_words[1])

        resultdict[ip] = pkts

    return resultdict


def split_traintest_ips(ipstats_dict : dict, ips_ignore : set) -> tuple:
    # Apply filters to obtain dict of usable IPs
    ipstats_dict = {ip : pkts for ip, pkts in ipstats_dict.items() if pkts >=
        SELECTION_PKTS_MIN and pkts <= SELECTION_PKTS_MAX}
    ips = list(ipstats_dict.keys())

    # Initialize IP sets
    train_ips = set()
    test_ips  = set()

    # Modify the list of IP addresses based on selection technique
    if IP_SELECTION_TECHNIQUE == 'leastactive':
        ips = reversed(ips)
    elif IP_SELECTION_TECHNIQUE == 'random':
        random.shuffle(ips)

    # Branch if some of the set is desired to be empty
    if TRAIN_IPS_CNT == 0 or TEST_IPS_CNT == 0:
        dest_set = train_ips if TRAIN_IPS_CNT != 0 else test_ips
        dest_cnt = TRAIN_IPS_CNT if TRAIN_IPS_CNT != 0 else TEST_IPS_CNT

        for ip in ips:
            if ip in ips_ignore:
                continue

            dest_set.add(ip)

            if len(dest_set) == dest_cnt:
                break

    # Branch for other cases when both sets should have at least 1 IP
    if len(train_ips) == 0 and len(test_ips) == 0:
        # Compute rounded ratio of test/train subets and add counters
        train_test_rratio = round(TRAIN_IPS_CNT / TEST_IPS_CNT)

        for ip in ips:
            # Ignore IP address if it is present in the set of ignored IPs
            if ip in ips_ignore:
                continue

            # If one (or both) counts are reached, fill in the remaining one and exit
            if len(train_ips) == TRAIN_IPS_CNT or len(test_ips) == TEST_IPS_CNT:
                while len(train_ips) != TRAIN_IPS_CNT:
                    train_ips.add(ip)

                while len(test_ips) != TEST_IPS_CNT:
                    test_ips.add(ip)

                break

            # Counts are not reached yet, decide which set to fill
            if (len(train_ips) + len(test_ips)) % (train_test_rratio + 1) != train_test_rratio:
                train_ips.add(ip)
            else:
                test_ips.add(ip)

        # In some cases, such as providing ignored IPs, a situation when the maximum
        # rounded ratio is highly exceeded, may occur, this IF fixes it
        if len(train_ips) / len(test_ips) >= 2 * train_test_rratio:
            firstip = list(train_ips)[0]
            train_ips.remove(firstip)
            test_ips.add(firstip)

    return train_ips, test_ips


def main(args : list) -> None:
    pcap_filepath  = args[1]    # Path to processed PCAP file
    stats_filepath = args[2]    # Path to tshark IP communication stats
    ips_ignored_filepath = args[3] if len(args) == 4 else None
    ips_stats      = {}         # Parsed IP communication statistics
    ips_ignored    = set()      # Set of ignored IP addresses

    # Open a file with IPs communication statistics
    with open(stats_filepath, 'r') as statsfile:
        ips_stats = parse_ipstats(statsfile.readlines())

    # Open a file with ignored IP addresses, if any
    if ips_ignored_filepath is not None:
        with open(ips_ignored_filepath, 'r') as ipsfile:
            ips_ignored = set(ipsfile.read().split())

    # Split the parsed IP stats into train & test subsets
    ips_train, ips_test = split_traintest_ips(ips_stats, ips_ignored)

    # Save train-test IP divisions to the file
    if ips_train:
        with open(os.path.splitext(pcap_filepath)[0] + '_train_ips.txt', 'w') as train_ips_file:
            train_ips_file.write(' '.join(list(ips_train)) + '\n')

    if ips_test:
        with open(os.path.splitext(pcap_filepath)[0] + '_test_ips.txt', 'w') as test_ips_file:
            test_ips_file.write(' '.join(list(ips_test)) + '\n')

    if RETURN_IPS_ONLY:
        return

    # Open file handles for PCAP reading/writing
    pcap_reader  = scapy.utils.PcapReader(pcap_filepath)

    if ips_train:
        pcap_writer_train = scapy.utils.PcapWriter(os.path.splitext(
            pcap_filepath)[0] + '_train.pcap', nano=True)

    if ips_test:
        pcap_writer_test = scapy.utils.PcapWriter(os.path.splitext(
            pcap_filepath)[0] + '_test.pcap', nano=True)

    # Iterate through the PCAP file and apply the previous IP division for packet selection
    for pkt in tqdm(pcap_reader):
        # Determine packet source IP
        src_ip = extract_src_ip(pkt)

        # Place the packet based on the source IP address to the desired packet set
        if src_ip in ips_train:
            pcap_writer_train.write(pkt)
        elif src_ip in ips_test:
            pcap_writer_test.write(pkt)
        else:
            continue

    pcap_reader.close()

    if ips_train:
        pcap_writer_train.close()

    if ips_test:
        pcap_writer_test.close()


if __name__ == '__main__':
    main(sys.argv)
