# Bash wrapper around flows2packets script
#
# Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
# Author: Author: Jan Kučera (jan.kucera@cesnet.cz)
# Date: 2023-05-20
# Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
# Repository: https://github.com/xGoldy/Windower
#
#
# Supposes a directory as an input, containing multiple PCAP files
# Uses a single flow file, but runs in on multiple pcaps in parallel
#
# Usage:
# ./flows2packets_parallel SOURCE_DIR OUTPUT_FILE REFERENCE_FLOWS DATASET_TYPE


# Settings
FILE_EXT='pcap'
TEMP_FOLDER='/mnt/ssd4tb/xgolds00/temp'

# Flows2packets script settings
F2P_SCRIPT_PATH='./flows2packets.py'


function main {
    # Parse args into variables for better readability
    SRC_FOLDER=$1
    OUT_FILENAME=$2
    REFERENCE_FLOWS=$3
    DATASET_TYPE=$4

    OUT_FOLDER=$(dirname OUT_FILENAME)

    # Create folders for temporary extractions and output if they do not exist
    mkdir --parents $TEMP_FOLDER
    mkdir --parents $OUT_FOLDER

    # Run a parallel process for each each PCAP file within given folder
    #find -L $SRC_FOLDER -type f -name "*$FILE_EXT" -exec python $F2P_SCRIPT_PATH "{}" "$TEMP_FOLDER/\"{}\"_extracted$FILE_EXT" $REFERENCE_FLOWS $DATASET_TYPE \;

    shopt -s globstar
    for file in ${SRC_FOLDER}/**/*.${FILE_EXT}; do
        file_basename=$(basename $file)

        python $F2P_SCRIPT_PATH $file "${TEMP_FOLDER}/${file_basename%.*}_extracted.${FILE_EXT}" $REFERENCE_FLOWS $DATASET_TYPE &
    done

    # Wait for all processes to finish
    wait

    # Merge the created files into the output file
    PCAPS_EXTRACTED=$(find -L $TEMP_FOLDER -type f | grep $FILE_EXT | sort)

    mergecap -w $OUT_FILENAME $PCAPS_EXTRACTED

    # Remove temp directory
    rm -rf $TEMP_FOLDER

    return 0
}


main $1 $2 $3 $4
