#!/usr/bin/env python3.8

import argparse
import logging
import pickle
import sys

import tqdm

import utils
from KitNET.KitNET import KitNET
from FeatureReader import FeatureReaderCSV, FeatureReaderH5, FeatureReaderMulti

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument('inputs', metavar='INFILE', type=str, nargs='+',
    help='csv/h5 file to process (generated by extraction)')
parser.add_argument('--csv', action='store_true', default=False,
    help='use csv format instead of h5')
parser.add_argument('-o', '--output', metavar='OUTFILE', type=str, default='-',
    help='path to write KitNET pickle output file')
parser.add_argument('-l', '--log-level', type=str, default='info',
    help='logging level (error, info, debug, ...)')
parser.add_argument('--maxae', type=int, default=10,
    help='maximum size for any autoencoder in the ensemble layer')
parser.add_argument('--fmgrace', type=int, default=5000,
    help='the number of instances taken to learn the feature mapping (the ensemble\'s architecture)')
parser.add_argument('--adgrace', type=int, default=50000,
    help='the number of instances used to train the anomaly detector (ensemble itself)')
parser.add_argument('--learning-rate', type=float, default=0.1,
    help='the stochastic gradient descent learning rate for all autoencoders')
parser.add_argument('--hidden-ratio', type=float, default=0.75,
    help='the ratio of hidden to visible neurons, e.g. 0.75 will cause roughly a 25%% compression in the hidden layer')

args = parser.parse_args()

# Set logging level
logging.basicConfig(level=args.log_level.upper())

# Create CSV/H5 reader
readers = []
for input in args.inputs:
    if args.csv:
        reader = FeatureReaderCSV(input)
    else:
        reader = FeatureReaderH5(input)
    readers.append(reader)
reader = FeatureReaderMulti(readers, args.fmgrace + args.adgrace + 1)
features_count = reader.get_num_features()

# Create detector (KitNET)
detector = KitNET(features_count, args.maxae, args.fmgrace, args.adgrace, args.learning_rate, args.hidden_ratio)
logger.info("running learning")

for vector in tqdm.tqdm(reader):
    detector.process(vector)

logger.info("learning finished")

with utils.open_output(args.output, "wb") as outfile:
    pickle.dump(detector, outfile)

logger.info("model written")
