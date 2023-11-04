"""
Data types for numpy logs and pandas conversion functions.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-27
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import numpy as np

from common import defines

# Numpy datatype for internal window statistics
# Currently taking 112B with alignment (structure padding)
NP_DTYPE_WINDOW_STATS = np.dtype([
    # Window summary
    ('window_id', 'u4'),                    # Window identifier
    ('pkts_total', 'u8'),                   # Total number of packets
    ('bytes_total', 'u8'),                  # Total number of bytes
    # Time
    ('tstamp_start', 'u8'),                 # First packet timestamp in the given window
    ('tstamp_end', 'u8'),                   # Last packet timestamp in the given window
    ('pkt_arrivals_avg', 'f8'),             # Average time between packet arrivals
    ('pkt_arrivals_std', 'f8'),             # Std of time between packet arrivals
    # Packet sizes
    ('pkt_size_min', 'u4'),                 # Minimum packet size
    ('pkt_size_max', 'u4'),                 # Maximum packet size
    ('pkt_size_avg', 'f4'),                 # Average of packet sizes
    ('pkt_size_std', 'f4'),                 # Std of packet sizes
    # L4 Protocols
    ('tcp_pkt_count', 'u8'),                # Number of logged TCP packets (segments)
    ('udp_pkt_count', 'u8'),                # Number of logged UDP packets
    ('icmp_pkt_count', 'u8'),               # Number of logged ICMP packets
    # Ports
    ('port_src_unique', 'u4'),              # Number of unique source ports
    ('port_src_entropy', 'f4'),             # Source port entropy
    # Connections
    ('conn_pkts_avg', 'f4'),                # Average number of packets for socket2socket transfers
    # Properties
    ('pkts_frag_count', 'u8'),              # Number of fragmented packets
    ('hdrs_payload_ratio_avg', 'f4'),       # Average of header to whole packet size ratio
], align=True)

NP_DTYPE_WINDOW_AUXDATA = np.dtype([
    ('last_pkt_arrival', 'u8'),             # Timestamp of the last packet arrival
    ('pkt_arrivals_std_aux', 'f4'),         # Aux value for running arrivals std computation
    ('pkt_size_std_aux', 'f4'),             # Aux value for running packet size std computation
], align=True)

# Numpy datatype for windows summary statistics
# Unless explicitly mentioned otherwise, all fields are the average of values from multiple processed windows
NP_DTYPE_WINDOW_SUMMARY_STATS = np.dtype([
    # Window identifier
    (defines.DATA_SRC_IP_COLNAME, 'U46'),   # Source IP address as 46-character length string for IPv6 maximum
    # Window summaries
    ('window_count', 'u4'),                 # Number of summarized windows
    ('window_span', 'u4'),                  # Difference between the last and the first processed window
    ('pkts_total', 'u8'),                   # Total number of packets
    ('bytes_total', 'u8'),                  # Total number of bytes
    ('pkt_rate', 'f4'),                     # Rate of packets per second estimate
    ('byte_rate', 'f4'),                    # Rate of bytes per second estimate
    # Time
    ('pkt_arrivals_avg', 'f8'),             # Average time between packet arrivals
    ('pkt_arrivals_std', 'f8'),             # Std of time between packet arrivals
    # Packet sizes
    ('pkt_size_min', 'u4'),                 # Minimum of all windows packet sizes
    ('pkt_size_max', 'u4'),                 # Maximum of all windows packet sizes
    ('pkt_size_avg', 'f4'),                 # Average of packet sizes
    ('pkt_size_std', 'f4'),                 # Std of packet sizes
    # L4 Protocols
    ('proto_tcp_share', 'f4'),              # TCP traffic share
    ('proto_udp_share', 'f4'),              # UDP traffic share
    ('proto_icmp_share', 'f4'),             # ICMP traffic share
    # Ports
    ('port_src_unique', 'f4'),              # Number of unique source ports
    ('port_src_entropy', 'f4'),             # Source port entropy
    # Connections
    ('conn_pkts_avg', 'f4'),                # Average number of packets for socket2socket transfers
    # Properties
    ('pkts_frag_share', 'f4'),              # Share of the fragmented packets
    ('hdrs_payload_ratio_avg', 'f4'),       # Average of header to whole packet size ratio
], align=True)

# Numpy datatype for inter-window statistics
NP_DTYPE_INTERWINDOW_STATS = np.dtype([
    ('pkts_total_std', 'f4'),               # Std of total number of packets
    ('bytes_total_std', 'f4'),              # Std of total number of bytes
    ('pkt_size_avg_std', 'f4'),             # Std of packet size averages
    ('pkt_size_std_std', 'f4'),             # Std of packet size stds
    ('pkt_arrivals_avg_std', 'f4'),         # Std of packet average time between packet arrivals
    ('port_src_unique_std', 'f4'),          # Std of number of unique source port number
    ('port_src_entropy_std', 'f4'),         # Std of source port entropies
    ('conn_pkts_avg_std', 'f4'),            # Std of number of packets per connection averages
    ('pkts_frag_share_std', 'f4'),          # Std of the fragmented packets share
    ('hdrs_payload_ratio_avg_std', 'f4'),   # Std of header to whole packet ratios
    ('dominant_proto_ratio_std', 'f4'),     # Std of ratio of the dominant L4 protocol
    ('intrawindow_activity_ratio', 'f4'),   # Host activity estimate within the summarized windows
    ('interwindow_activity_ratio', 'f4'),   # Host activity estimate during the whole summarized period
], align=True)

# Approximate size of the numpy array of NP_DTYPE_WINDOW_STATS dtype with a single row
# Initialized upon module load in __init__.py
NP_WINDOW_STATS_ARRAY_SIZE = None
