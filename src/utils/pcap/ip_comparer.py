"""
Compares IP addresses of two files and returns any that are the same.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-06-19
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Usage:
python ip_comparer.py <file1_ips.txt> <file2_ips.txt>

Where:
<fileN_ips.txt> is an IP dump generated by the following command:
    tshark -r <filename.pcap> -T fields -e ip.src | sort | uniq
"""

import sys


def main(args : list):
    ips_file1 = set()
    ips_file2 = set()

    # Load IPs from specified files
    with open(args[1], 'r') as file1:
        ips_file1 = set(file1.read().split())

    with open(args[2], 'r') as file2:
        ips_file2 = set(file2.read().split())

    # Compute set intersection and print if any common IPs in both sets are found
    ips_intersect = ips_file1.intersection(ips_file2)

    if ips_intersect:
        print(ips_intersect)


if __name__ == '__main__':
    main(sys.argv)
