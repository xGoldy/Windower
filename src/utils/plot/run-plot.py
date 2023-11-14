#!/bin/python3

"""
Plots Per-packet RMSE values plot and distinguihes between benign and malicious
packets by color.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-07-09
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import argparse
import logging
import numpy
from scipy.stats import norm
from matplotlib import pyplot

import utils

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument('rmses', metavar='RMSES', type=str,
    help='rmse input file to plot')
parser.add_argument('-L', '--labels', metavar='LABELS', type=str,
    help='labels input file')
parser.add_argument('-t', '--tstamps', metavar='TSTAMPS', type=str,
    help='tstamps input file')
parser.add_argument('-o', '--output', metavar='OUTFILE', type=str, default='output.png',
    help='path to write PNG output file')
parser.add_argument('-l', '--log-level', type=str, default='info',
    help='logging level (error, info, debug, ...)')
parser.add_argument('-s', '--skip', type=int, default=0,
    help='the number of instances to be skipped from the beginning')
parser.add_argument('-e', '--end', type=int, default=None,
    help='the number of instances to be plotted from the beginning (without ones skipped)')
parser.add_argument('-T', '--linthresh', metavar='x', type=float,
    help='the range (-x, x), within which the plot is linear (it avoids having the plot go to infinity around zero)')
parser.add_argument('-S', '--scale', metavar='SCALE', nargs='+', type=float, default=[2, 3],
    help='scale of points')
parser.add_argument('-A', '--alpha', metavar='ALPHA', nargs='+', type=float, default=[0.5, 0.75],
    help='scale of points')

args = parser.parse_args()

# Set logging level
logging.basicConfig(level=args.log_level.upper())

pyplot.figure(figsize=(10,3.5), dpi=400)

logger.info(f"loading {args.rmses}")
utils.check_file(args.rmses, ext="rmse")
rmses = numpy.genfromtxt(args.rmses, delimiter="\n")
logger.info(f"loaded {args.rmses}, {len(rmses)} records")
testSamples = rmses[args.skip:args.end]

if args.labels:
    logger.info(f"loading {args.labels}")
    utils.check_file(args.labels, ext="txt")
    labels = numpy.genfromtxt(args.labels, delimiter="\n")
    logger.info(f"loaded {args.labels}, {len(labels)} records")
    testLabels = labels[args.skip:args.end]
else:
    testLabels = numpy.zeros(len(testSamples))

if args.tstamps:
    logger.info(f"loading {args.tstamps}")
    utils.check_file(args.tstamps, ext="tstamp")
    tstamps = numpy.genfromtxt(args.tstamps, delimiter="\n", )
    # tstamps = numpy.array(tstamps * 1e3, dtype='datetime64[ms]')
    tstamps = tstamps - tstamps[args.skip]
    logger.info(f"loaded {args.tstamps}, {len(tstamps)} records")
    testStamps = tstamps[args.skip:args.end]
    pyplot.xlabel("time [seconds]")
else:
    testStamps = numpy.array(range(0, len(testSamples)))
    pyplot.xlabel("N [packets]")

testStampsBenign = testStamps[testLabels == 0]
testSamplesBenign = testSamples[testLabels == 0]
pyplot.scatter(
    testStampsBenign,
    testSamplesBenign,
    s=args.scale[0],
    c='darkgreen',
    label='_',
    rasterized=True,
    alpha=args.alpha[0],
    edgecolors='none',
)

testStampsAttack = testStamps[testLabels == 1]
testSamplesAttack = testSamples[testLabels == 1]
pyplot.scatter(
    testStampsAttack,
    testSamplesAttack,
    s=args.scale[1],
    c='darkred',
    label='_',
    rasterized=True,
    alpha=args.alpha[1],
    edgecolors='none',
)

pyplot.scatter(
    [], [],
    s=0.05,
    c='darkgreen',
    label='Benign packets',
)

pyplot.scatter(
    [], [],
    s=0.05,
    c='darkred',
    label='Attack packets',
)

# fakermse = numpy.where(labels == 0, 20, 0)
# fakermse = numpy.where(labels == 1, 40, fakermse)
# testSamples = numpy.where(testSamples == 0, fakermse, testSamples)

# zeroLabels = numpy.full(len(labels), 0.5)
# testLabels = numpy.where(testSamples == 0, testLabels, testLabels)

if args.linthresh:
    minSample = args.linthresh
else:
    nonzeroSamples = testSamples > 0
    minSample = numpy.amin(testSamples, where=nonzeroSamples, initial=1.0)

pyplot.yscale("symlog", linthresh=minSample, linscale=1.0)
pyplot.ylabel("RMSE (log scaled)")
pyplot.legend(markerscale=25)

pyplot.savefig(args.output, bbox_inches='tight')
