"""
Argument parser for mitig_simulator script.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-17
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import argparse


PROG_DESCRIPTION = "Evaluates DDoS mitigation model capabilities"
PROG_EPILOG = "Configuration keys: mitig_simulator, logger"\
    "\n\nAuthor: Patrik Goldschmidt (xgolds00@stud.fit.vutbr.cz)\nVersion: 1.0. (07-2021)"
PROG_NAME = "mitig_simulator.py"
PROG_USAGE = "mitig_simulator.py [-h] | -p PCAP_FILE c CONFIG_FILE -m MODEL_FILE [-v]"\
    "[-P PREDICTIONS_FILE] [-a ATTACKERS_LIST] [-E OUT_FILE]"

ARG_HELP_ATTACKERS   = "Filepath to attackers' IP addresses delimited by newline for evaluation"
ARG_HELP_CONFIG      = "Path to the mitigation simulator configuration file"
ARG_HELP_PKT_DECS    = 'File to write per-packet mitigation decisions benign/malicious (0/1) to'
ARG_HELP_MODEL       = "Filepath of the pickled model to use"
ARG_HELP_PCAP        = "Filepath to the PCAP file for off-line evaluation"
ARG_HELP_PREDICTIONS = "Filepath to dump prediction values into. No file created if empty"
ARG_HELP_VERBOSE     = "Verbose output of the mitigation progress"


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
        self.add_argument('-a', '--attackers', action='store', required=False, metavar='ATTACKERS_LIST', help=ARG_HELP_ATTACKERS)
        self.add_argument("-c", "--config", type=str, required=True, metavar="CONFIG_FILE", help=ARG_HELP_CONFIG)
        self.add_argument('-d', '--decisions-pkts', action='store', required=False, metavar='PKTS_DECISIONS_FILE', help=ARG_HELP_PKT_DECS)
        self.add_argument('-m', '--model', action='store', required=True, metavar='MODEL_FILE', help=ARG_HELP_MODEL)
        self.add_argument('-p', '--pcap', action='store', required=True, metavar='PCAP_FILE', help=ARG_HELP_PCAP)
        self.add_argument('-P', '--predictions', action='store', required=False, metavar='PREDICTIONS_FILE', help=ARG_HELP_PREDICTIONS)
        self.add_argument('-v', '--verbose', action='store_true', required=False, help=ARG_HELP_VERBOSE)
