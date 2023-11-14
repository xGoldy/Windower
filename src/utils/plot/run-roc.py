#!/bin/python3

"""
Plots a ROC curve of one or more classficiation results.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-07-09
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import argparse
import logging

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import sklearn.metrics

import utils

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument('rmses', metavar='RMSES', nargs='+', type=str,
    help='rmse input files to plot')
parser.add_argument('-n', '--names', metavar='NAMES', nargs='+', type=str,
    default=['Autoencoder'],
    help='names to plot')
parser.add_argument('-c', '--colors', metavar='COLORS', nargs='+', type=str,
    default=['darkorange'],
    help='colors to plot')
parser.add_argument('-L', '--labels', metavar='LABELS', type=str,
    help='labels input file')
parser.add_argument('-o', '--output', metavar='OUTFILE', type=str,
    default='output.png',
    help='path to write PNG output file')
parser.add_argument('-l', '--log-level', type=str,
    default='info',
    help='logging level (error, info, debug, ...)')

args = parser.parse_args()

# Set logging level
logging.basicConfig(level=args.log_level.upper())

# ROC plotting function
def print_roc(output, labels, rmses) -> None:
    for data in rmses:
        fprs, tprs, threshs = sklearn.metrics.roc_curve(labels, data['rmses'])
        auc = sklearn.metrics.auc(fprs, tprs)
        plt.plot(fprs, tprs, data['color'], label=f"{data['name']} (AUC=%0.2f)" % auc)

    plt.plot([0, 1], [0, 1], "darkgray", linestyle='dashed', label="Chance level (AUC=0.5)")
    plt.axis("square")
    plt.xlabel("False Positive Rate (FPR)")
    plt.ylabel("True Positive Rate (TPR)")
    plt.legend()
    plt.savefig(output, bbox_inches='tight')

# Load label data
logger.info(f"loading {args.labels}")
utils.check_file(args.labels, ext="txt")
label_data = pd.read_csv(args.labels, names=['y_true'])
logger.info(f"loaded {args.labels}, {len(label_data)} records")

plot_data = []
for (file, name, color) in zip(args.rmses, args.names, args.colors):

    # Load RMSE data
    logger.info(f"name {name}, color {color}")
    logger.info(f"loading {file}")
    utils.check_file(file, ext="rmse")
    rmses_data = pd.read_csv(file, names=['losses'])
    logger.info(f"loaded {file}, {len(rmses_data)} records")

    assert(len(label_data) == len(rmses_data))

    plot_data.append({
        'file': file,
        'rmses': rmses_data,
        'name': name,
        'color': color,
    })

print_roc(args.output, label_data, plot_data)
