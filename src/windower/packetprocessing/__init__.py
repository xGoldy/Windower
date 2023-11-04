"""
Packetprocessing package provides functions for processing raw packets, extracting their features, and
logging them into structures defined by time windows.  These can be used offline to generate datasets
and train the model, but online use is possible as well, although modules are not explicitly designed
with respect to performance, so packet throughput may be severely limited.  If modules from this
package would be implemented online, feature extraction is recommended to be performed in FPGA, and
logging/windowing in a lower level compiled language such as C/C++ or distributed using technologies
such as Apache Flink.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-04-21
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import packetprocessing.logtypes
import numpy as np
import sys

from packetprocessing.logtypes import NP_DTYPE_WINDOW_STATS


# Set the numpy array of dtype NP_DTYPE_WINDOW_STATS to its dynamic size so users may deduct how many elements
# can be stored in the memory
packetprocessing.logtypes.NP_WINDOW_STATS_ARRAY_SIZE = sys.getsizeof(np.zeros((1,), dtype=NP_DTYPE_WINDOW_STATS))
