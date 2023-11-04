"""
Packets extraction from PCAP file, given corresponding flow data.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-12
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

python flows2packets.py <inputPCAP> <outputPCAP> <referenceFlows> <datasetType>

datasetType = {ndsec, unswnb15}

What's it good for:
The program extracts packets from a PCAP file based on a corresponding flow file, selecting only
packets contained within flows. Many datasets label their PCAP data with flows, but when we want
to extract packets from those PCAPs, a problem begins - how do we want to extract them? Consider
an example when flows labeled as "DoS" are interesting for us. However, the corresponding PCAP is
intermixed with benign traffic and other types of attacks. According to our brief research, no
tools to extract packets from flows in a simple manner exist. And by a pure strike of luck, this
tool exactly does that. It extracts all packets CORRESPONDING TO ANY FLOW within the
<referenceFlows> file. Therefore, to extract a particular class type, the pandas library has to
be used first. Firstly, filter out the flows of interest, e.g., data[data["label"] == DoS], and
then use this tool to extract relevant packets from the selected flows.

Tweaking for other datasets:
The tool is currently customized for the NDSec-1 dataset. However, it can be adapted to any
dataset with brief changes to code. Variables just under the imports commented as "Flows dataset
column names" need to be changed to represent column names of the flow CSV file. Furthermore,
variables with the comment "Dataset properties" should be adapted. And that should be it!
However, the dataset is required to contain all the columns specified by the variables previously
set up. However, the flow end-time column may sometimes not be present. In this case, modify the
function "prepare_dataset" to compute such a row by adding a flow start timestamp (already
converted to epoch) with the flow duration. Voila!
"""


import math
import pandas as pd
import scapy.packet
import scapy.utils
import sys

from dataclasses import dataclass
from scapy.layers.sctp import SCTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6
from tqdm import tqdm

import flows2packets_config as f2pc


@dataclass
class PacketInfo:
    """A simple structure-like class for passing extracted data from packets."""

    timestamp : int = 0
    src_ip    : str = ""
    dst_ip    : str = ""
    src_port  : int = 0
    dst_port  : int = 0
    proto     : int = 0


def extract_packet_info(pkt: scapy.packet.Packet):
    """Parses packet information and returns a PacketInfo structure with filled information or None
    if the packet is of non-interest."""

    pkt_info = PacketInfo()

    # Packet timestamp is extracted directly
    pkt_info.timestamp = pkt.time

    # Determine L3 layer
    if pkt.haslayer(IP):
        pkt_info.src_ip = pkt[IP].src
        pkt_info.dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        pkt_info.src_ip = pkt[IPv6].src
        pkt_info.dst_ip = pkt[IPv6].dst

    # Determine L4 layer
    if pkt.haslayer(TCP):
        pkt_info.proto = 6
        pkt_info.src_port = pkt[TCP].sport
        pkt_info.dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        pkt_info.proto = 17
        pkt_info.src_port = pkt[UDP].sport
        pkt_info.dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        pkt_info.proto = 1
    elif pkt.haslayer(_ICMPv6):
        pkt_info.proto = 58
    elif pkt.haslayer(SCTP):
        pkt_info.proto = 132
        pkt_info.src_port = pkt[SCTP].sport
        pkt_info.dst_port = pkt[SCTP].dport
    else:
        # Other protocols than TCP/UDP/ICMPv4 (v6) and SCTP are not considered for flows anyway
        return None

    return pkt_info


def search_for_flow_inclusion(pkt_info: PacketInfo, flows: pd.DataFrame, dataset_cfg: dict):
    """Searches whether the packet defined by pkt_info is included within the flows dataframe."""

    dset_colnames = dataset_cfg[f2pc.CONFIG_KEY_COLUMNS]
    dset_props = dataset_cfg[f2pc.CONFIG_KEY_PROPERTIES]

    filt_flows = flows[
        (flows[dset_colnames['FLOWS_COL_PROTO']] == pkt_info.proto) &
        (flows[dset_colnames['FLOWS_COL_IP_SRC']] == pkt_info.src_ip) &
        (flows[dset_colnames['FLOWS_COL_PORT_SRC']] == pkt_info.src_port) &
        (flows[dset_colnames['FLOWS_COL_IP_DST']] == pkt_info.dst_ip) &
        (flows[dset_colnames['FLOWS_COL_PORT_DST']] == pkt_info.dst_port)
    ]

    # Out of all selected flows, perform a look based on a timestamp
    # Ceil and floors are included to make sure the packet will get matched to the flow, if the
    # dataset uses rounding/truncating timestamps on a certain number of decimal places
    matched_flow = filt_flows[
        (filt_flows[dset_colnames['FLOWS_COL_TSTAMP_START']] * dset_props['TIMESTAMP_MODIF_CONST'] <=
            math.ceil(pkt_info.timestamp * dset_props['TIMESTAMP_MODIF_CONST']))
        &
        (filt_flows[dset_colnames['FLOWS_COL_TSTAMP_END']] * dset_props['TIMESTAMP_MODIF_CONST'] >=
            math.floor(pkt_info.timestamp * dset_props['TIMESTAMP_MODIF_CONST']))
    ]

    return not matched_flow.empty


def is_in_flows(pkt_info: PacketInfo, flows: pd.DataFrame, dataset_cfg: dict):
    """Searches whether the packet is included in the flows dataframe, in uni-flow mode by default, but also
    reverses the fields if the dataset uses bi-flows."""

    # Search the flows dataframe and get any row that mathces the given 5-column
    retval = False

    if search_for_flow_inclusion(pkt_info, flows, dataset_cfg):
        retval = True
    elif dataset_cfg[f2pc.CONFIG_KEY_PROPERTIES]['DATASET_BIFLOW']:
        # If the dataset is composed of biflows, search once againt with swapped IPs and ports
        reversed_pkt_info = PacketInfo(
            timestamp = pkt_info.timestamp,
            src_ip    = pkt_info.dst_ip,
            src_port  = pkt_info.dst_port,
            dst_ip    = pkt_info.src_ip,
            dst_port  = pkt_info.src_port,
            proto     = pkt_info.proto)

        retval = search_for_flow_inclusion(reversed_pkt_info, flows, dataset_cfg)

    return retval


def main(args: list):
    # Check if the script is run correctly
    if len(args) != 5:
        raise Exception("Invalid number of arguments provided.")

    # Retrieve dataset config and initialize column name variables
    dataset_config, dataset_prepare_func = f2pc.retrieve_dataset_specifics(args[4])
    start_tstamp_colname = dataset_config[f2pc.CONFIG_KEY_COLUMNS]['FLOWS_COL_TSTAMP_START']
    end_tstamp_colname   = dataset_config[f2pc.CONFIG_KEY_COLUMNS]['FLOWS_COL_TSTAMP_END']

    # Open file handles
    in_pcap_reader  = scapy.utils.PcapReader(args[1])
    out_pcap_writer = scapy.utils.PcapWriter(args[2], nano=True)
    flows           = pd.read_csv(args[3])

    # Prepare dataset by converting timestamps into epochs
    flows = dataset_prepare_func(flows)

    # Perform operations to optimize the program - sort by ending timestamp & compute max duration
    flows = flows.sort_values(by=end_tstamp_colname, ascending=True, ignore_index=True)
    flows_dur_max = (flows[end_tstamp_colname] - flows[start_tstamp_colname]).max().item()
    flows_of_interest = flows

    # Intialize tqdm progress bar
    pbar = tqdm(unit='pkt', unit_scale=True)

    # Read the packets in batches
    pkt_batch = in_pcap_reader.read_all(f2pc.PACKETS_BATCH_SIZE)

    while pkt_batch:
        flows_trimmed  = False      # Whether the flows have been trimmed for the current batch
        last_pkt_info  = None       # Packet info structure of the last valid packet

        # Get the last valid packet within a batch
        for pkt in reversed(pkt_batch):
            last_pkt_info = extract_packet_info(pkt)

            if last_pkt_info is not None:
                break

        # Iterate through all packets within a batch
        for pkt in pkt_batch:
            pkt_info = extract_packet_info(pkt)

            # Trim flows for optimization when the first and last valid packets are known
            if pkt_info is not None and not flows_trimmed:
                # Establish a starting index to cut irrelevant flows from the start
                dset_start_row = flows[end_tstamp_colname].searchsorted(
                    math.floor(pkt_info.timestamp), side='left')

                flows = flows.iloc[dset_start_row:]

                # Use maximum flow duration to reduce the amount of matched flows in LE operation
                # Logic: Add maximum flow duration, as the flow must have already started or this
                # is the first packet of it. Thus, adding max flow duration produces an upper bound
                dset_end_row = flows[end_tstamp_colname].searchsorted(
                    math.ceil(last_pkt_info.timestamp + flows_dur_max), side='right')
                flows_up_bound = flows[:dset_end_row]

                # The upper approximation with start and end rows would be theoretically enough.
                # However, since computing the flow inclusion is computationally expensive, we
                # further minimize the state space by selecting only flows that started sooner
                # as the timestamp of the last packet within a batch
                flows_of_interest = flows_up_bound[flows_up_bound[start_tstamp_colname].le(
                    math.ceil(last_pkt_info.timestamp))]

                flows_trimmed = True

            # Determine and write packets within the trimmed flows
            if pkt_info is not None and is_in_flows(pkt_info, flows_of_interest, dataset_config):
                out_pcap_writer.write(pkt)

        pbar.update(f2pc.PACKETS_BATCH_SIZE)

        # Read a next batch
        pkt_batch = in_pcap_reader.read_all(f2pc.PACKETS_BATCH_SIZE)

    # Close the opened file handles and the progress bar
    pbar.close()
    in_pcap_reader.close()
    out_pcap_writer.close()


if __name__ == '__main__':
    main(sys.argv)
