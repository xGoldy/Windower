# Windower

This is an official repository for Windower, a feature-extraction mechanism for network intrusion detection presented at [IEEE NOMS 2024](https://noms2024.ieee-noms.org/).

Authors:

- Patrik Goldschmidt (<igoldschmidt@fit.vut.cz>)
- Jan Kučera (<jan.kucera@cesnet.cz>)

Link to the paper:

- https://ieeexplore.ieee.org/document/10575699

## Abstract

**Windower** is a feature-extraction method for real-time network-based intrusion (particularly DDoS) detection. It employs stream data mining and sliding window principles to compute statistical information directly from network packets. We summarize several such windows and compute inter-window statistics to increase detection reliability. Summarized statistics are then fed into an ML-based attack discriminator. If an attack is recognized, we drop the consequent attacking source's traffic using simple ACL rules.

The experimental results evaluated on several datasets indicate the ability to reliably detect an ongoing attack within the first six seconds of its start and mitigate 99\% of flood and 92\% of slow attacks while maintaining false positives below 1\%. In contrast to state-of-the-art, our approach provides greater flexibility by achieving high detection performance and low resources as flow-based systems while offering prompt attack detection known from packet-based solutions. Windower thus brings an appealing trade-off between attack detection performance, detection delay, and computing resources suitable for real-world deployments.

## Extracted Features

The following table provides a brief list of the collected traffic features. The list can also be found inside the `src/windower/packetprocessing/logtypes.py`, whereas the final statistics there correspond to the merging of `WINDOW_SUMMARY_STATS` and `INTERWINDOW_STATS`. Nevertheless, we list these statistics here for clarity. When the Windower evolves, new collected statistics will inevitably be added, and those listed in the paper will not correspond to the actual list of statistics anymore. For this reason, we aim to provide a current, always-updated version here in the GitHub repository.

**Current status:** Statistics **correspond** to the the paper.

| ID  | Name                         | Description                                  |
| --- | ---------------------------- | -------------------------------------------- |
| 1   | `src_ip`                     | Source IP address of the corresponding entry |
| 2   | `window_count`               | Number of summarized time windows            |
| 3   | `window_span`                | Summarized windows span (last ID - first ID) |
| 4   | `pkts_total`                 | The number of transferred packets            |
| 5   | `bytes_total`                | Sum of bytes within the trasnferred packets  |
| 6   | `pkt_rate`                   | Packets-per-second rate                      |
| 7   | `byte_rate`                  | Bytes-per-second rate                        |
| 8   | `pkt_arrivals_avg`           | Inter-arrival packet time (IAT) average      |
| 9   | `pkt_arrivals_std`           | Std of packet IAT values                     |
| 10  | `pkt_size_min`               | Minimum observed packet size                 |
| 11  | `pkt_size_min`               | Maximum observed packet size                 |
| 12  | `pkt_size_avg`               | Average observed packet size                 |
| 13  | `pkt_size_std`               | Std of observed packet sizes                 |
| 14  | `proto_tcp_share`            | TCP traffic share                            |
| 15  | `proto_udp_share`            | UDP traffic share                            |
| 16  | `proto_icmp_share`           | ICMP traffic share                           |
| 17  | `port_src_unique`            | Number of unique source ports                |
| 18  | `port_src_entropy`           | Source port entropy                          |
| 19  | `conn_pkts_avg`              | Packet average in socket-to-socket transfers |
| 20  | `pkts_frag_share`            | Share of fragmented packets                  |
| 21  | `hdrs_payload_ratio_avg`     | Average of header to packet size ratio       |
| 22  | `pkts_total_std`             | Std of a number of transferred packets       |
| 23  | `bytes_total_std`            | Std of a sum of transferred bytes            |
| 24  | `pkt_size_avg_std`           | Std of a packet size averags                 |
| 25  | `pkt_size_std_std`           | Std of packet size stds                      |
| 26  | `pkt_arrivals_avg_std`       | Std of average times between packet arrivals |
| 27  | `port_src_unique_std`        | Std of number of unique source ports         |
| 28  | `port_src_entropy_std`       | Std of source port entropy values            |
| 29  | `conn_pkts_avg_std`          | Std of packet count per connection averages  |
| 30  | `pkts_frag_share_std`        | Std of fragmented packets share              |
| 31  | `hdrs_payload_ratio_avg_std` | Std of header to whole packet ratios         |
| 32  | `dominant_proto_ratio_std`   | Std of ratios of the dominant L4 protocol    |
| 33  | `intrawindow_activity_ratio` | Estimate of IP activity within windows       |
| 34  | `interwindow_activity_ratio` | Estimate of IP activity during the period    |
| 35  | `target`                     | Target class (label)                         |

## Installation

In our experiments, we used `Python 3.11.6` and the newest package versions available in October 2023. In order to replicate our environment, we suggest performing the following steps:

1. Install Python Development headers on your machine, e.g.,:
   - `dnf install python3-devel` (Fedora)
   - `apt-get install python3-dev` (Debian)
2. Create a Python virtual environment, e.g.:
   - `python -m venv windower_venv`
   - You might need additional packages in your system, e.g., `python3-venv`
3. Activate the virtual environment, e.g.:
   - `source windower_venv/bin/activate`
4. Install the required packages, e.g.,:
   - `pip install -r requirements.txt`

## Datasets Replication

Due to copyright reasons, we are not able to directly provide dataset subsets that were used for evaluating the model. However, we list all the required steps and provide tools to reconstruct the datasets to make our research replicable. These tools can also facilitate the creation of other datasets for future research. Please refer to the `datasets.md` file for more information.

## Usage

Using the Windower for our experiments replication or a custom processing comprises the following steps.

0. Preparation of a dataset within a raw (PCAP) format.
1. Feature extraction for dataset creation.
2. Training and exporting the ML model.
3. Evaluation of the model's performance via a DDoS attack simulation deployment scenario.

The above steps require a series of commands, which we demonstrate in four Jupyter Notebooks in the `examples` folder. The first notebook (`00_dataset.ipynb`) demonstrates preparation of the raw PCAP dataset used for both original Kitsune and Windower methods. The notebook `01_kitsune.ipynb` shows specific data preprocessing, model training and evaluation for the Kitsune model, whereas `02_windower.ipynb` presents the data preparation, training and evaluating using the proposed Windower feature extraction mechanism. Finally, the `03_perf.comparison` analyzes and compares the performance of both methods.

When performing feature extraction and running mitigation simulation (notebook `02_windower.ipynb`), the Windower's behavior can be controlled via the `src/windower/config.yml` configuration file. This file provides a simple way to configure the most crucial settings like the window length in seconds, the minimum number of collected windows, or the minimum number of packets required in every window to consider it valid. Refer to the mentioned `config.yml` file for more information.

As mentioned, we cannot provide the exact utilized PCAPs due to copyright reasons, so the pipeline in the notebooks cannot be simply run as is due to the missing data. Nevertheless, the above example should provide an idea of how the pipeline is used, and insights in the `datasets.md` can help in data reconstruction or completely new datasets creation on demand.

## Modifying Windower

We encourage researchers and practitioners to play and extend the Windower, possibly accelerating its runtime, adding new statistical features, or providing additional functionality. This section briefly describes how to plug in your own model for simulating the mitigation process or further extend the Windower's capabilities.

### Plugging in Your Model

Creation of the dataset via the `windower/dataset_creator.py` is model-independent, as it works as a mere feature extractor and produces a CSV that can be used for training. Nevertheless, plugging in a custom model (other than KitNet) for mitigation process simulation requires a few minor changes to the source code.

More precisely, the script `windower/mitig_simulator.py` requires a trained model in its binary form exported using `pickle` via the `-m MODEL_FILEPATH` argument. After passing, the model is wrapped inside the `ModelWrapper` class in the `windower/mitig_simulator/model_wrapper.py` and used for the mitigation simulation as such. If you want to plug in your model, we first suggest modifying data preprocessing routines in `windower/common/feature_preproc.py` to fit the model-specific needs (e.g., data normalization). Afterward, define your own model wrapper inside the mentioned `model_wrapper.py` file. We already included wrappers for KitNet and Sklearn models as an inspiration. After modifying these functions, import and use them within the `windower/mitig_simulator.py` script when declaring the packet handler routine in the `__main__` function.

### Extending Windower

As mentioned, the Windower's routines might be extended with more collected features or additional functionality. For instance, in the case of more features, we first suggest analyzing the `windower/packetprocessing` package and its contents, which act as the heart of the Windower.

Regarding additional required information extracted from packets, `windower/packetprocessing/extractor.py` is the right file to look at. Additional features can be defined in `windower/packetprocessing/logtypes.py`. However, in order to compute them, changes within the `windower/packetprocessing/logger.py` have to be made. The logger acts as a collector of various statistics across time windows and is finally able to export them upon the window end.

The whole logging process is controlled via a packet handler routine, which processes packets and tracks ongoing time windows. There are separate handlers for dataset creation (`windower/dataset_creator/packet_handler.py`) and mitigation simulation (`windower/mitig_simulator/packet_handler.py`) as they perform slightly different functions. Although modifying them is unnecessary for adding additional collected features, they might be tweaked for performance improvements or additional functionality.

## Miscellaneous

### Licence

Our code, as well as the original Kitsune/KitNet's code, is published under the **MIT licence**. See the `LICENCE.txt` file for more information.

### Referencing

If you use our code or mention our article, please cite us using the following format:

#### Plaintext

P. Goldschmidt and J. Kučera, "Windower: Feature Extraction for Real-Time DDoS Detection Using Machine Learning," NOMS 2024-2024 IEEE Network Operations and Management Symposium, Seoul, Korea, Republic of, May 2024, pp. 1-10, doi: 10.1109/NOMS59830.2024.10575699.

#### BibTeX

```bibtex
@inproceedings{goldschmidt2024_windower,
  author    = {Patrik Goldschmidt and Jan Ku\v{c}era},
  title     = {Windower: Feature Extraction for Real-Time DDoS Detection Using Machine Learning},
  booktitle = {NOMS 2024-2024 IEEE Network Operations and Management Symposium}, 
  year      = {2024},
  month     = {may},
  volume    = {},
  number    = {},
  pages     = {1-10},
  publisher = {IEEEXplore},
  doi       = {10.1109/NOMS59830.2024.10575699},
  note      = {Online GitHub repository: \url{https://github.com/xGoldy/Windower}}
}
```
