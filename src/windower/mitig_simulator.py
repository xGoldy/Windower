#!/usr/bin/env python3

"""
Evaluates a DDoS attack mitigation model, both per-packet and per-classification
of DDoS attack mitigation.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-01
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Usage:
model_evaluate.py -a <attackers_filepath> -m <model_filepath> -p <pcap_filepath>
    [-P <predictions_filepath>] [-f <extracted_features_filepath>] [-v]
where:
    -a Path to a text file containing attackers' IP addresses separated with whitespace
    -f Path to the file with statistical features extracted from the provided PCAP or None
    -m Path to a pickle-dumped model to use for the simulation
    -p Path to a PCAP file to evaluate model on
    -P Path to the file with precise model predictions, no file is created if not present
    -v Verbose output
"""

import numpy as np
import sys
import tqdm

import common.input, common.feature_preproc
from common.config_loader import install_config, load_prog_config, ConfigParamsError
from packetprocessing import logger
from mitig_simulator.argparser import ArgParser
from mitig_simulator.model_wrapper import KitNetWrapper
from mitig_simulator.packet_handler import PacketHandler

SCRIPT_NAME='mitig_simulator'


def main(args : list) -> None:
    args        = None      # Parsed arguments values
    attackers   = list()    # List of attackers for model evaluation
    pcap_reader = None      # Scapy PcapReader instance for PCAP file reading
    model       = None      # Pickle model to use for attack detection

    # Initialize logger configuration
    config = install_config(SCRIPT_NAME, None, logger)

    try:
        # Parse arguments and load the program configuration
        args   = ArgParser().parse_args(sys.argv[1:])
        config = load_prog_config(args.config, config)

        # Load the attackers' IPs
        with open(args.attackers, 'r') as file_attackers:
            attackers = file_attackers.read().split()

        # Load the model
        model = KitNetWrapper(args.model)

        # Open the evalation PCAP
        pcap_reader = common.input.determine_pcap_reader(args.pcap)
    except (FileNotFoundError, ConfigParamsError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    # Create instances of packet-processing objects
    pkt_logger = logger.Logger(**config[logger.MODULE_NAME])
    pkt_handler = PacketHandler(model=model, logger=pkt_logger,
        preproc_func=common.feature_preproc.preprocess,
        window_interval=config[logger.MODULE_NAME]['window_length'],
        model_treshold=config[SCRIPT_NAME]['threshold'],
        verbose=args.verbose)

    # Process the packets and write 0/1 (benign/malicious) for each of them into the file
    if args.decisions_pkts is not None:
        with open(args.decisions_pkts, 'w') as packets_file:
            for pkt in tqdm.tqdm(pcap_reader, unit='pkt'):
                pkt_info = pkt_handler.process(pkt)

                # Write valid packet decisions to a file
                if pkt_info is not None:
                    packets_file.write(f'{pkt_info[0]},{pkt_info[1]},')
                    packets_file.write(('1' if pkt_info[0] in attackers else '0') + '\n')
    else:
        for pkt in tqdm.tqdm(pcap_reader, unit='pkt'):
            pkt_info = pkt_handler.process(pkt)

    # Write predictions scores to the file if desired
    if args.predictions is not None:
        predictions = pkt_handler.get_predictions()

        with open(args.predictions, 'w') as preds_file:
            for pred in predictions:
                preds_file.write(f'{pred[0]},{pred[1]},')
                preds_file.write(('1' if pred[0] in attackers else '0') + '\n')

    # Dump statistics from the packet handler and add ground truth in the eval mode
    stats = pkt_handler.get_statistics()

    # Determine true labels
    stats['true_label'] = ['Attack' if ip in attackers else 'Benign' for ip, _ in stats.iterrows()]

    ###################################################
    ##########   Print statistical outputs   ##########
    ###################################################
    print(stats.to_string(index=True))

    # Precompute data for real attackers and legitimate users
    real_attackers     = stats[stats['true_label'] == 'Attack']
    real_legitimate    = stats[stats['true_label'] == 'Benign']
    classif_attackers  = stats[stats['detections_pos'] > 0]
    classif_legit      = stats[(stats['detections_pos'] == 0) & (stats['detections_neg'] > 0)]
    classif_total      = stats['detections_pos'].sum() + stats['detections_neg'].sum()

    # Compute how many were samples of true labels were actually processed by ML model
    # True labels may not be processed if their pps is not high enough or they do not communicate
    # for the required number of time windows
    classif_proc_attck_all  = real_attackers[(real_attackers['detections_neg'] > 0) | \
        (real_attackers['detections_pos'] > 0)]
    classif_proc_attck_true = real_attackers[(real_attackers['detections_neg'] == 0) & \
        (real_attackers['detections_pos'] > 0)]

    classif_proc_legit_all  = real_legitimate[(real_legitimate['detections_neg'] > 0) | \
        (real_legitimate['detections_pos'] > 0)]
    classif_proc_legit_true = real_legitimate[(real_legitimate['detections_neg'] > 0) & \
        (real_legitimate['detections_pos'] == 0)]

    # Compute prediction statistics
    tp = classif_proc_attck_true['detections_pos'].sum()
    tn = classif_proc_legit_true['detections_neg'].sum()
    fp = classif_attackers[classif_attackers['true_label'] == 'Benign']['detections_pos'].sum()
    fn = classif_legit[classif_legit['true_label'] == 'Attack']['detections_neg'].sum()
    conf_matrix = np.array([[tp, fp], [fn, tn]])

    accuracy  = (tp + tn) / classif_total if classif_total != 0 else '-'
    precision = tp / (tp + fp) if (tp + fp) != 0 else '-'
    recall    = tp / (tp + fn) if (tp + fp) != 0 else '-'
    fscore    = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) != 0 else '-'

    # Compute packet processing statistics that automated machine learning evaluation cannot provide
    real_attackers_pkts     = real_attackers['pkts_allowed'].sum() + real_attackers['pkts_denied'].sum()
    real_attackers_denied   = real_attackers['pkts_denied'].sum()
    real_legitimate_pkts    = real_legitimate['pkts_allowed'].sum() + real_legitimate['pkts_denied'].sum()
    real_legitimate_allowed = real_legitimate['pkts_allowed'].sum()

    hosts_detection_both = len(stats[(stats['detections_neg'] > 0) & (stats['detections_pos'] > 0)])
    ratio_attackers_detected = len(set(real_attackers.index).intersection(set(classif_attackers.index))) / \
        len(real_attackers) if len(real_attackers) != 0 else 1.0

    # Print the findings
    print("------   Classification statistics   -----")
    print("\nTotal number of classifications: {}".format(classif_total))
    print("Attackers detection  : {} / {}".format(len(classif_proc_attck_true), len(classif_proc_attck_all)))
    print("Legitimate detection : {} / {}".format(len(classif_proc_legit_true), len(classif_proc_legit_all)))
    print("Attackers all        : {} / {}".format(len(classif_proc_attck_true), len(real_attackers)))
    print("Legitimate all       : {} / {}".format(len(classif_proc_legit_true), len(real_legitimate)))
    print("\nConfusion matrix:\n{}\n".format(conf_matrix))

    print("Accuracy  : {}".format(accuracy))
    print("Precision : {}".format(precision))
    print("Recall    : {}".format(recall))
    print("F-Score   : {}\n".format(fscore))

    print("-----   Per-packet mitigation statistics   -----")
    print("Real attackers packet denied ratio    : {:<.3f} ({} / {})".format(
        real_attackers_denied / real_attackers_pkts if real_attackers_pkts != 0 else 1.0, real_attackers_denied,
        real_attackers_pkts))
    print("Real legitimate packets allowed ratio : {:<.3f} ({} / {})".format(
        real_legitimate_allowed / real_legitimate_pkts, real_legitimate_allowed, real_legitimate_pkts))


if __name__ == '__main__':
    main(sys.argv)
