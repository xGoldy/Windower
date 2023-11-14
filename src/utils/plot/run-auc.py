#!/bin/python3

"""
Plots changing AUC value curve with regard to changing number of employed windows.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-07-03
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import argparse
import logging

import matplotlib.pyplot as plt
import pandas as pd
import sklearn.metrics
import numpy

import utils

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument('--dirs', metavar='DIRS', nargs='+', type=str,
    help='packet/window rmses input file dirs')
parser.add_argument('--packet-rmses', metavar='RMSES', type=str,
    help='packet rmses input file paths template (use placeholder {dir})')
parser.add_argument('--packet-labels', metavar='LABELS', type=str,
    help='packet labels input file paths template (use placeholder {dir})')
parser.add_argument('--packet-skip', metavar='NUM', type=int, default=0,
    help='number of packet AUC to skip')
parser.add_argument('--window-rmses', metavar='RMSES', type=str,
    help='window rmses input file paths template (use placeholder {dir})')
parser.add_argument('--window-labels', metavar='LABELS', type=str,
    help='window labels input file paths template (use placeholder {dir})')
parser.add_argument('--window-skip', metavar='NUM', type=int, default=0,
    help='number of window AUC to skip')
parser.add_argument('-n', '--names', metavar='NAMES', nargs='+', type=str,
    default=['Window-based classification', 'Packet-based classification'],
    help='names to plot')
parser.add_argument('-c', '--colors', metavar='COLORS', nargs='+', type=str,
    default=['darkorange', 'darkred'],
    help='colors to plot')
parser.add_argument('-o', '--output', metavar='OUTFILE', type=str,
    default='output.png',
    help='path to write PNG output file')
parser.add_argument('-l', '--log-level', type=str,
    default='info',
    help='logging level (error, info, debug, ...)')

args = parser.parse_args()

# Set logging level
logging.basicConfig(level=args.log_level.upper())

def load_auc_data(labels, rmses, dirs, skip=0):

    aucs_data = []
    for i, dir_name in enumerate(dirs):

        if i < skip:
            logger.warning(f"loading dir {dir_name} data skipped")
            aucs_data.append(None)
            continue

        logger.warning(f"loading dir {dir_name} data")

        # Load labels data
        labels_file = labels.format(dir=dir_name)
        logger.info(f"loading labels {labels_file}")
        utils.check_file(labels_file, ext="txt")
        labels_data = pd.read_csv(labels_file, names=['y_true'])
        logger.info(f"loaded labels {labels_file}, {len(labels_data)} records")

        # Load RMSE data
        rmses_file = rmses.format(dir=dir_name)
        logger.info(f"loading rmses {rmses_file}")
        utils.check_file(rmses_file, ext="rmse")
        rmses_data = pd.read_csv(rmses_file, names=['losses'])
        logger.info(f"loaded rmses {rmses_file}, {len(rmses_data)} records")

        assert(len(labels_data) == len(rmses_data))

        auc = sklearn.metrics.roc_auc_score(labels_data, rmses_data)
        aucs_data.append(auc)

    return aucs_data

plot_data = []

if args.window_labels:
    logger.warning("loading window data")
    aucs_data = load_auc_data(args.window_labels, args.window_rmses, args.dirs, args.window_skip)
    plot_data.append(aucs_data)

if args.packet_labels:
    logger.warning("loading packets data")
    aucs_data = load_auc_data(args.packet_labels, args.packet_rmses, args.dirs, args.packet_skip)
    plot_data.append(aucs_data)

dirarr = numpy.array(args.dirs, dtype=numpy.int8)

plt.figure(figsize=(5,5))
plt.xticks(dirarr)
plt.xlabel("Window count (w)")
plt.ylabel("Area Under the ROC Curve (AUC)")

for (aucs, name, color) in zip(plot_data, args.names, args.colors):
    aucarr = numpy.array(aucs, dtype=numpy.float32)
    plt.plot(dirarr, aucarr, marker='o', color=color, label=name)

plt.legend()
plt.savefig(args.output, bbox_inches='tight')
