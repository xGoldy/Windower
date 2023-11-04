"""
 Configuration for flows2packets extractor for specific datasets

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-06-01
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

The structure of properties and colnames needs to be kept as is.
"""

import decimal
import pandas as pd


# Configuration dictionary root keys
CONFIG_KEY_COLUMNS = 'colnames'
CONFIG_KEY_PROPERTIES = 'properties'

# Number of packets to load into the memory at once
# Very low values lower memory requirements, yet decrease performance only marginally.
# However, very big values (say more than 1M) could also cause performance drops
# Keep between 1000 - 10000 for an optimal performance
PACKETS_BATCH_SIZE = 1000


###############################################################################
#############################    CONFIGURATIONS   #############################
###############################################################################
_DATASET_CONFIG_NDSEC = {
    CONFIG_KEY_PROPERTIES : {
        'DATASET_BIFLOW' : True,
        'DATASET_TSTAMP_PRECISION' : 3,
        # Leave to None, computed later
        'TIMESTAMP_MODIF_CONST' : None
    },
    CONFIG_KEY_COLUMNS : {
        'FLOWS_COL_TSTAMP_START' : 'start-time',
        'FLOWS_COL_TSTAMP_END'   : 'end-time',
        'FLOWS_COL_IP_SRC'       : 'srcip',
        'FLOWS_COL_IP_DST'       : 'dstip',
        'FLOWS_COL_PORT_SRC'     : 'srcport',
        'FLOWS_COL_PORT_DST'     : 'dstport',
        'FLOWS_COL_PROTO'        : 'protocol'
    }
}

_DATASET_CONFIG_UNSWNB15 = {
    CONFIG_KEY_PROPERTIES : {
        'DATASET_BIFLOW' : True,
        'DATASET_TSTAMP_PRECISION' : 0,
        # Leave to None, computed later
        'TIMESTAMP_MODIF_CONST' : None
    },
    CONFIG_KEY_COLUMNS : {
        'FLOWS_COL_TSTAMP_START' : 'stime',
        'FLOWS_COL_TSTAMP_END'   : 'ltime',
        'FLOWS_COL_IP_SRC'       : 'srcip',
        'FLOWS_COL_IP_DST'       : 'dstip',
        'FLOWS_COL_PORT_SRC'     : 'sport',
        'FLOWS_COL_PORT_DST'     : 'dport',
        'FLOWS_COL_PROTO'        : 'proto'
    }
}

###############################################################################
##########################    PREPARATION FUNCTIONS   #########################
###############################################################################
# Other settings
UNSW_NB15_PROTO_REPLACEDICT = {
    'icmp'  : 1,
    'tcp'   : 6,
    'udp'   : 17,
    'icmp6' : 58,
    'sctp'  : 132
}


# Functions themselves
def _preprocess_dataset_ndsec(dataset: pd.DataFrame) -> pd.DataFrame:
    """Prepares the NDSec dataset for flow membership determination by converting string timestamps
    to the epoch-like format while creating new columns based on names specified in the program
    header."""

    dataset['start-time'] = dataset['start-time'].apply(
        lambda x: pd.to_datetime(x, format='%Y-%m-%d %H:%M:%S.%f').timestamp())
    dataset['end-time'] = dataset['end-time'].apply(
        lambda x: pd.to_datetime(x, format='%Y-%m-%d %H:%M:%S.%f').timestamp())

    return dataset


def _preprocess_dataset_unswnb15(dataset: pd.DataFrame) -> pd.DataFrame:
    # Recode protocols to their respective numbers, throw uninteresting protocols away
    dataset = dataset[dataset['proto'].isin(['tcp', 'udp', 'icmp', 'sctp'])]

    dataset = dataset.copy(deep=True)       # Deep copy is needed otherwise pandas cries for no reason
    dataset['proto'] = dataset['proto'].replace(UNSW_NB15_PROTO_REPLACEDICT).astype(int)
    dataset = dataset.astype({'proto': int, 'sport': int, 'dport': int})

    return dataset


###############################################################################
#################################    PICKERS   ################################
###############################################################################
_PICKER_CONFIG = {
    'ndsec'     : _DATASET_CONFIG_NDSEC,
    'unswnb15'  : _DATASET_CONFIG_UNSWNB15
}

_PICKER_PREPARER = {
    'ndsec'     : _preprocess_dataset_ndsec,
    'unswnb15'  : _preprocess_dataset_unswnb15
}


###############################################################################
############################    PUBLIC INTERFACE   ############################
###############################################################################
def retrieve_dataset_specifics(dataset_type: str) -> tuple:
    dataset_cfg = _PICKER_CONFIG[dataset_type]

    # Add a specific constant for timestamps modification
    dataset_cfg[CONFIG_KEY_PROPERTIES]['TIMESTAMP_MODIF_CONST'] = float(
        decimal.Decimal(1).shift(dataset_cfg[CONFIG_KEY_PROPERTIES]['DATASET_TSTAMP_PRECISION']))

    return dataset_cfg, _PICKER_PREPARER[dataset_type]
