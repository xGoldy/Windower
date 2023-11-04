#!/bin/python3

"""
Creation of the dataset from raw PCAP files according the configuration.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-13
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import decimal
import pandas as pd
import os
import sys

from common import input, defines
from common.config_loader import load_prog_config, install_config, ConfigParamsError
from common.exceptions import ArgumentCombinationException
from packetprocessing import logger
from dataset_creator.argparser import ArgParser, ArgumentCombinationException
from dataset_creator.packet_handler import PacketHandler

SCRIPT_NAME = "dataset_creator"


if __name__ == "__main__":
    args              = None        # Parsed argument values
    config_user       = None        # Configuration structure for the program
    dataset_negative  = None        # Pandas dataframe for negative (benign) traffic data
    dataset_positive  = None        # Pandas dataframe for positive (attack) traffic data
    pkt_logger        = None        # Logger instance for packet processing and statistics computation
    pkt_handler       = None        # Packet handler instance for packet statistics saving
    tstamp_srcfile    = None        # File for external timestamps source

    # Initialize script expected configuration with used modules
    config_setup = install_config(SCRIPT_NAME, None, logger)

    try:
        # Parse arguments and load the program configuration
        args        = ArgParser().parse_args(sys.argv[1:])
        config_user = load_prog_config(args.config, config_setup)

        # Open a file for external timestamps
        if args.timestamps is not None:
            tstamp_srcfile = open(args.timestamps, 'r')
    except (ArgumentCombinationException, FileNotFoundError, ConfigParamsError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    # Initialize logger instance
    pkt_logger = logger.Logger(**config_user[logger.MODULE_NAME])
    pkt_handler = PacketHandler(pkt_logger, config_user[logger.MODULE_NAME]['window_length'], tstamp_srcfile,
        args.caida)

    try:
        # Create dataset for negative and positive traffic data if desired
        if args.negative is not None:
            input.read_file(args.negative, pkt_handler.process)

            # Obtain data from packet handler and add target variable to it
            dataset_negative = pkt_handler.get_labels()
            dataset_negative[defines.DATASET_TARGET_COLNAME] = defines.DATASET_TARGET_VALUE_BENIGN

            # Clear packet handler and logger object after using
            pkt_handler.clear()

        if args.positive is not None:
            input.read_file(args.positive, pkt_handler.process)

            # Obtain data from packet handler and add target variable to it
            dataset_positive = pkt_handler.get_labels()
            dataset_positive[defines.DATASET_TARGET_COLNAME] = defines.DATASET_TARGET_VALUE_ATTACK
    except (RuntimeError, FileNotFoundError) as file_exc:
        print("Error: {}.".format(file_exc), file=sys.stderr)
        sys.exit(1)
    except decimal.InvalidOperation as dec_exc:
        print("Error: Timestamp from {} cannot be converted to a number.".format(args.timestamps), file=sys.stderr)
        sys.exit(1)
    finally:
        # Close the file if its opened
        if tstamp_srcfile is not None:
            tstamp_srcfile.close()

    # Merge both classes into a single file if desired
    if args.merge and dataset_positive is not None and dataset_negative is not None:
        dataset_merged = pd.concat([dataset_negative, dataset_positive], ignore_index=True)

        dataset_merged.to_csv(args.output, index=False)
    else:
        # No merging will take place - save created pandas dataframes as they are
        outfile_negative_name = args.output
        outfile_positive_name = args.output

        if dataset_negative is not None and dataset_positive is not None:
            # Both negative and positive will be saved - create separate filenames for them
            (file, ext) = os.path.splitext(args.output)

            outfile_negative_name = file + "N" + ext
            outfile_positive_name = file + "P" + ext

        # Save datasets to file if they exist
        if dataset_negative is not None:
            dataset_negative.to_csv(outfile_negative_name, index=False)

        if dataset_positive is not None:
            dataset_positive.to_csv(outfile_positive_name, index=False)
