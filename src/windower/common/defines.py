"""
Common defines and constants used across multiple files.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-22
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

# Dataset source IP column name
DATA_SRC_IP_COLNAME = 'src_ip'

# Dataset target variable name and values
DATASET_TARGET_COLNAME = "target"
DATASET_TARGET_VALUE_BENIGN = 0
DATASET_TARGET_VALUE_ATTACK = 1

# Configuration name defines
CONF_PARAMS_MANDATORY = "mandatory"
CONF_PARAMS_DEFAULTS  = "defaults"
CONF_PARAMS_INTS      = "ints"
CONF_PARAMS_FLOATS    = "floats"
CONF_PARAMS_STRINGS   = "strings"
CONF_PARAMS_BOOLS     = "bools"

# Standardization configuration naming
CONF_STD_AVG_COLNAME = "avg"
CONF_STD_STD_COLNAME = "std"
CONF_STD_MIN_COLNAME = "min"
CONF_STD_MAX_COLNAME = "max"
