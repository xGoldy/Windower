"""
Windower feature processing for dataset creation and mitigation simulation.
Functions defined are used for preprocessing the windower dataset data, ranging
from simple columns deletion to feature normalization and standardization
according to the used model and its requirements on the data.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-17
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import pandas as pd

from common import defines


PREPROC_COLS_DROP = [defines.DATA_SRC_IP_COLNAME, 'window_count', 'window_span']
FRAG_COLS_DROP = ['pkts_frag_share', 'pkts_frag_share_std']


def preprocess(data: pd.DataFrame, del_frag: bool = False, *, additional = []) -> pd.DataFrame:
    """Preprocesses the data based on the implemented function. The current
    implementation removes IP, window count, window span columns, and
    alternatively other ones specified by the following parameters.

    Parameters:
        data       DataFrame to be processed
        del_frag   Whether to delete fragmentation-related features
        additional Additional column names to drop

    Returns:
        pd.DataFrame Dataframe prepared for handling within the model."""

    cols_to_delete = PREPROC_COLS_DROP + (FRAG_COLS_DROP if del_frag else []) + additional

    return data.drop(columns=cols_to_delete)


