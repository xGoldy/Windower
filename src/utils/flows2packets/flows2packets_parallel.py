"""
Worker-based parallel wrapper for the flows2packets script

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-21
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower

Usage:
    python flows2packets.py_parallel <inputPCAP> <outputPCAP> <flowfile> <datasetType> <workersCnt>

datasetType = {ndsec, unswnb15}
"""

import flows2packets as f2p

import multiprocessing as mp
import os
import pathlib
import shutil
import subprocess
import sys


# Parallel program settings
FILE_EXT='pcap'
TEMP_FOLDER='/tmp/flows2packets'


def init_pool(the_lock):
    '''Initialize each process with a global variable lock.
    Based on: https://stackoverflow.com/questions/69907453'''

    global lock
    lock = the_lock


def process_file(*args) -> None:
    """Process a file, redirecting its stdout and printing at the end"""
    redirect    = True      # Whether to redirect process streams
    stdout_orig = None      # Original stdout file
    stderr_orig = None      # Original stderr file

    # Who acquires the lock writes to stdout, others get redirected to NULL
    if lock.acquire(block=False):
        redirect = False
    else:
        stdout_orig = sys.stdout
        stderr_orig = sys.stderr
        sys.stdout  = open(os.devnull, 'w')
        sys.stderr  = open(os.devnull, 'w')

    # Call the file processing routine
    f2p.main([f2p.__file__] + list(args))

    # Restore the stdout file if it was redirected and print that we finished
    if redirect:
        sys.stdout = stdout_orig
        sys.stderr = stderr_orig
    else:
        lock.release()

    print(f'Finished: {os.path.basename(args[1])}')


def main(args: list) -> None:
    if len(args) != 6:
        raise Exception("Invalid number of arguments provided.")

    src_folder     = args[1]    # Source folder to process PCAPs from
    out_fpath      = args[2]    # Path to the final output filename
    flowfile_fpath = args[3]    # Path to the CSV flow file for reference
    dataset_type   = args[4]    # Type of the dataset to process
    workers_cnt    = int(args[5]) if args[5] != '-1' else None
    out_folder     = os.path.dirname(out_fpath)
    status_lock    = mp.Lock()

    # Create folders for output file and temporary extraction if they do not exist
    pathlib.Path(out_folder).mkdir(parents=True, exist_ok=True)
    pathlib.Path(TEMP_FOLDER).mkdir(parents=True, exist_ok=True)

    # Clean the contents of the temporary directory
    [file.unlink() for file in pathlib.Path(TEMP_FOLDER).glob("*")]

    # Determine files to process with a corresponding file extension
    files_to_proc  = [fname for fname in os.listdir(src_folder) if
        fname.endswith('.' + FILE_EXT) and os.path.isfile(os.path.join(src_folder, fname))]
    files_to_proc.sort()

    # Create tasks to execute and launch the parallel pool
    tasks = [(os.path.join(src_folder, fname), os.path.join(TEMP_FOLDER, fname), flowfile_fpath,
        dataset_type) for fname in files_to_proc]

    with mp.Pool(processes=workers_cnt, initializer=init_pool, initargs=(status_lock, )) as pool:
        pool.starmap(process_file, tasks)

    # Merge all created sub-pcaps into a single file and clean up
    subpcaps = [os.path.join(TEMP_FOLDER, subp) for subp in
                os.listdir(TEMP_FOLDER) if subp.endswith('.' + FILE_EXT)]
    subpcaps.sort()

    subprocess.run(f"mergecap -w {out_fpath} {' '.join(subpcaps)}", shell=True)
    shutil.rmtree(TEMP_FOLDER)


if __name__ == '__main__':
    main(sys.argv)
