# Windower

This is an official repository for Windower, a feature-extraction mechanism published as XXX in XXX on XXX 2024.

Authors:

- Patrik Goldschmidt (<igoldschmidt@fit.vut.cz>)
- Jan Kučera (<jan.kucera@cesnet.cz>)

Link to the paper:

- XXX

## Abstract

**Windower** is a feature-extraction method for real-time network-based intrusion (particularly DDoS) detection. It employs stream data mining and sliding window principles to compute statistical information directly from network packets. We summarize several such windows and compute inter-window statistics to increase detection reliability. Summarized statistics are then fed into an ML-based attack discriminator. If an attack is recognized, we drop the consequent attacking source's traffic using simple ACL rules.

The experimental results evaluated on several datasets indicate the ability to reliably detect an ongoing attack within the first six seconds of its start and mitigate 99\% of flood and 92\% of slow attacks while maintaining false positives below 1\%. In contrast to state-of-the-art, our approach provides greater flexibility by achieving high detection performance and low resources as flow-based systems while offering prompt attack detection known from packet-based solutions. Windower thus brings an appealing trade-off between attack detection performance, detection delay, and computing resources suitable for real-world deployments.

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

#### APA

Details will be filled in after the paper acceptance.

#### BibTeX

Details will be filled in after the paper acceptance.

```bibtex
@article{goldschmidt2023_windower,
  author    = {Patrik Goldschmidt and Jan Ku\v{c}era},
  title     = {Windower: Feature Extraction for Real-Time DDoS Detection Using Machine Learning},
  booktitle = {},
  year      = {2023},
  month     = {},
  volume    = {},
  number    = {},
  series    = {},
  pages     = {},
  publisher = {},
  note      = {Online GitHub repository: \url{https://github.com/xGoldy/Windower}}
}
```
