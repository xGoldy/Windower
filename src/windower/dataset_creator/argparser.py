"""
Argument parser for dataset_creator script.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-06
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import argparse

from common.exceptions import ArgumentCombinationException


# Program description messages
PROG_DESCRIPTION = "Create CSV datasets from PCAP files."
PROG_EPILOG = "Configuration keys: dataset_creator, logger"\
    "\n\nAuthor: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)\nVersion: 1.1. (08-2023)"
PROG_NAME = "dataset_creator.py"
PROG_USAGE = "dataset_creator.py [-h] | (-p PCAP_FILE [-n PCAP_FILE] | -n PCAP_FILE [-p PCAP_FILE]) "\
    "[-t TSTAMPS_FILE] [-m] -c CONFIG_FILE OUT_FILE"

# Argument help messages
ARG_HELP_CAIDA    = "CAIDA-like packets on input with trimmed L4 payloads and L2 headers"
ARG_HELP_CONFIG   = "Path to the dataset creator configuration file"
ARG_HELP_MERGE    = "Merge 2 processed PCAPs into a single CSV. If only 1 PCAP is specified, -m is ignored"
ARG_HELP_NEGATIVE = "PCAP file to label as negative (benign traffic)"
ARG_HELP_POSITIVE = "PCAP file to label as positive (attack traffic)"
ARG_HELP_OUTPUT   = "Output filename. If both positive and negative are created at once, particular suffix is added"
ARG_HELP_TSTAMPS  = "Path to the file with external timestamps"

# Exception messages
EXC_NO_ACTION      = "At least one of the arguments -p|-n must be present"
EXC_TIMESTAMPS_TWO = "Timestamps argument cannot be used when both positive and negative samples are present"


class ArgParser(argparse.ArgumentParser):
    """Argument parser class for dataset_creator script."""

    def __init__(self) -> None:
        """Calls parrent constructor and presets argparser class values and expected arguments."""

        super().__init__()

        # Set argument parser properties
        self.add_help        = True
        self.description     = PROG_DESCRIPTION
        self.epilog          = PROG_EPILOG
        self.formatter_class = argparse.RawTextHelpFormatter
        self.prog            = PROG_NAME
        self.usage           = PROG_USAGE

        # Add argparser arguments
        self.add_argument("-c", "--config", type=str, required=True, metavar="CONFIG_FILE", help=ARG_HELP_CONFIG)
        self.add_argument("-C", "--caida", action="store_true", help=ARG_HELP_CAIDA)
        self.add_argument("-m", "--merge", action="store_true", help=ARG_HELP_MERGE)
        self.add_argument("-n", "--negative", type=str, metavar="PCAP_FILE", help=ARG_HELP_NEGATIVE)
        self.add_argument("-p", "--positive", type=str, metavar="PCAP_FILE", help=ARG_HELP_POSITIVE)
        self.add_argument("-t", "--timestamps", type=str, metavar="TSTAMPS_FILE", help=ARG_HELP_TSTAMPS)
        self.add_argument("output", type=str, metavar="OUT_FILE", help=ARG_HELP_OUTPUT)


    def parse_args(self, args: list):
        """Overridden parse_args function, performing the same functionality with additional semantics checks.

        Parameters:
            args List of arguments to be parsed

        Raises:
            ArgumentCombinationException if invalid argument combination is detected"""

        parsed_args = super().parse_args(args)

        # Perform arguments correct combinations and exclusivity checks
        if parsed_args.positive is None and parsed_args.negative is None:
            # At least one of the positive/negative options is required
            raise ArgumentCombinationException(EXC_NO_ACTION)

        # External timestamps feature cannot be used when processing positive and negative samples at once
        if parsed_args.timestamps is None and parsed_args.positive is not None and parsed_args.negative is not None:
            raise ArgumentCombinationException(EXC_TIMESTAMPS_TWO)

        return parsed_args
