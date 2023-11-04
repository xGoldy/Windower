"""
Strips columns unsuitble for ML purposes after creating the dataset with
the dataset_creator.py script.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-07-01
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Usage:
python strip_useless_cols.py <in_file> <out_file> [keepfrag]
"""

import pandas as pd
import sys


COLS_TO_DROP = ['src_ip', 'window_count', 'window_span', 'target']
FRAG_TO_DROP = ['pkts_frag_share', 'pkts_frag_share_std']

def main(args : list) -> None:
   # Load the desired dataset file
   dataset = pd.read_csv(args[1])

   columns = COLS_TO_DROP
   if len(args) <= 3 or args[3] != "keepfrag":
      columns += FRAG_TO_DROP

   dataset = dataset.drop(columns=columns)

   # Save the dataset back to the disk
   dataset.to_csv(args[2], index=False, header=False)


if __name__ == '__main__':
   main(sys.argv)
