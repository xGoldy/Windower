# Evaluation Datasets Reconstruction

In our research, we utilized several public Network Intrusion Detection Systems (NIDSs) datasets and modified them in order to contain only DDoS traffic. Due to the fact that the original Kitsune model was extremely slow with its original feature extraction and per-packet evaluation (only dozens of pps), we needed to select a small subset even after DDoS extraction to make a comparison to our proposed extraction method, Windower. Aiming to allow the replicability of our experiments, this document the exact dataset composition process to compile the same dataset subsets.

For the evaluation, we used four datasets, namely:

- [CAIDA](#caida-dataset)
- [CTU-13](#ctu-13-dataset)
- [UNSW-NB15](#unsw-nb15-dataset)
- [2017-SUEE](#2017-suee-dataset)

The following sections will now briefly introduce each dataset and provide the steps in order to reconstruct the same subsets as we used. Furthermore, we provide information on how we labeled packets in each dataset in [Per-Packet Data Labeling](#per-packet-data-labeling) section for mitigation simulation performance evaluation.

If you need a quick example of how the dataset is reconstructed, see `examples/00_dataset.ipynb` Jupyter notebook, where we reconstruct a subset of CTU-13 Scenario 4.

## CAIDA Dataset

When referring to the CAIDA dataset, we refer to the custom mix of the CAIDA Anonymized Internet Traces Dataset (CAIDA passive capture) [1] and the CAIDA UCSD DDoS Attack 2007 Dataset [2]. CAIDA DDoS dataset is one of the few public datasets with real-world DDoS traffic, so we wanted to use it to evaluate our method. The attack was performed on August 4, 2007, on the CAIDA network. The dataset contains only attack traffic and responses to it. Data privacy was achieved by anonymizing IP addresses and trimming packets' payloads. Since our method works only with packet headers, this fact has not influenced the detection capabilities.

The DDoS dataset contains only attack traffic, so we had to provide benign samples to define a concept of normality for the detection model. The closest related dataset for such a purpose is the CAIDA Anonymized Internet Traces Dataset, collected from high-speed monitors on a commercial backbone link. Its capture started in April 2008 and Ended in January 2019. For our purpose, we used the capture from 2008, as this date is closest to the 2007 DDoS attack date, so the traffic characteristics (e.g., bitrates, protocols, applications) will be more similar in contrast to later years of the Internet traces capture.

Nevertheless, we are still aware of potential time window temporal bias and artifacts introduced by mixing the data from two different computer networks [3, 4, 5]. For this reason, we do not rely on a single dataset only but also evaluate using three different datasets, as described later in this document.

### Dataset Reconstruction

1. Request access to both datasets on the provided webpages [1, 2].
2. Download the data with your provided name and password. Example for CAIDA Anonymized Internet Traces 2008:

```shell
wget -np -m --http-password YOUR_PASSWORD --http-user YOUR_USERNAME --no-check-certificate https://data.caida.org/datasets/passive-2008/
```

#### Train Set: CAIDA Anonymized Traces

3. Navigate to the following directory in your CAIDA 2008 Traces folder:

```shell
data.caida.org/datasets/passive-2008/equinix-chicago/20080430-170000.UTC
```

4. Our method works only with unidirectional traffic, so we chose ingress traffic direction (`dirA`) using the following files:

```shell
equinix-chicago.dirA.20080430-170000.UTC.anon.pcap.gz
equinix-chicago.dirA.20080430-170100.UTC.anon.pcap.gz
equinix-chicago.dirA.20080430-170200.UTC.anon.pcap.gz
equinix-chicago.dirA.20080430-170300.UTC.anon.pcap.gz
equinix-chicago.dirA.20080430-170400.UTC.anon.pcap.gz
```

5. Unzip the mentioned files using `gunzip`.
6. Merge the unzipped PCAPs into a single PCAP using `mergecap`:

```shell
mergecap -w equinix.dirA.20080430-1700-1709.pcap FILES
```

7. Due to the immense size of the merged file, we needed to select a subset of the traffic to make processing computationally feasible within the slow Kitsune code. Therefore, we selected only the communication of 20 source IP addresses, which produced a "sufficient" amount of traffic within the extracted 5-minute interval. For this purpose, the script `src/utils/pcap/traintest_splitter.py` was used with the following parameters: `TRAIN_IPS_CNT = 0;
TEST_IPS_CNT = 20; SELECTION_PKTS_MIN = 75000; SELECTION_PKTS_MAX = 150000; IP_SELECTION_TECHNIQUE = 'random'`. This call efficiently selected 20 IP addresses from the merged PCAP file, which produced at least 75,000 but no more than 150,000 packets to limit the amount of analyzed communication. The following IPs were selected:

```shell
240.227.39.13
60.235.57.243
226.186.116.221
240.180.174.54
249.233.55.223
240.180.174.47
62.250.22.230
240.140.90.32
125.176.217.108
125.176.217.117
248.33.87.113
62.240.76.118
54.15.3.91
61.53.251.8
56.22.237.100
125.176.217.125
125.179.172.36
60.235.245.124
249.233.55.117
54.38.21.72
```

8. Extract the given source IP addresses from the merged PCAP using `tshark` or `tcpdump` tools using a simple BPF filter, e.g., `src host 240.227.39.13`, etc.

9. The final extracted file contains only background (supposed benign) traffic from 2008-04-30 17:00:00 - 17:04:59 limited to the 20 source IP addresses as specified above. Such a file can be considered an assembled CAIDA dataset train set: `caida_train.pcap`.

#### Test Set: CAIDA Anonymized Traces

10. Repeat the same process as in the CAIDA Anonymized Traces train set (steps 4-8), but in the `equinix-chicago/20081016-13000000.UTC/` directory with the following files:

```shell
equinix-chicago.dirA.20081016-130000.UTC.anon.pcap.gz
equinix-chicago.dirA.20081016-130100.UTC.anon.pcap.gz
equinix-chicago.dirA.20081016-130200.UTC.anon.pcap.gz
equinix-chicago.dirA.20081016-130300.UTC.anon.pcap.gz
equinix-chicago.dirA.20081016-130400.UTC.anon.pcap.gz
```

We decided to choose data from 2008-10-16 (6 months later than the train set) to simulate concept drift after some time of model deployment. Again, we merged the files into a single PCAP and selected a subset of IP addresses to limit the amount of data:

```shell
62.241.160.219
62.240.106.59
60.203.123.34
238.50.104.30
62.241.160.190
62.240.83.254
62.241.89.118
224.24.149.42
62.240.100.188
240.107.79.120
62.240.100.231
240.180.175.215
6.79.100.108
228.68.129.135
240.107.77.233
62.240.115.132
93.151.58.82
9.241.193.177
240.227.47.244
62.240.106.126
```

11. By performing these steps, we created a 5-minute testing set of background (supposed benign) traffic from 2008-10-16 13:00:00 to 13:04:59 consisting of 20 source IP addresses specified above. Let's name this part of the test set as: `caida_test_benign.pcap`.

#### Test Set: CAIDA DDoS Attack

Malicious (DDoS) traffic was provided by the CAIDA DDoS Attack 2007 test set. Since the first 25 minutes of the attack contain little traffic, we decided to use the attack from 2007-08-04 14:14:36 to 14:34:35. We decided to reserve the first 10 minutes for potential training of supervised models, so the latter 10 (14:24:36 - 14:34:35) were used for testing. The process goes as follows:

12. Since we are interested only in unidirectional attacking traffic, navigate to the `to-victim` folder in your CAIDA DDoS 2007 Dataset folder.

13. Only work with the following files:

```shell
ddostrace.to-victim.20070804_142436.pcap.gz
ddostrace.to-victim.20070804_142936.pcap.gz
```

14. Decompress the files using `gunzip`
15. Merge the files via `mergecap`
16. Using the already-mentioned script `src/utils/pcap/traintest_splitter.py` with the following parameters: `TRAIN_IPS_CNT = 0;
TEST_IPS_CNT = 20; SELECTION_PKTS_MIN = 35000; SELECTION_PKTS_MAX = 1000000; IP_SELECTION_TECHNIQUE = 'mostactive'`, we have selected the following 20 most active DDoSing hosts:

```shell
167.15.184.229
192.1.206.217
197.84.248.196
210.185.169.79
198.83.232.76
192.5.232.167
39.89.39.121
167.46.3.209
133.85.232.42
197.208.124.44
199.129.180.200
199.132.187.180
167.200.148.73
130.119.190.246
196.208.28.12
192.229.242.166
215.33.99.26
197.111.128.138
192.153.200.55
57.222.217.116
```

17. Extract the mentioned source IP addresses using `tshark` or `tcpdump` tools.
18. By the above steps, we have extracted a 10-minute capture of pure DDoS attack traffic. Note that this capture is twice as long as the benign attack capture. Nevertheless, the DDoS achieved much lower packets per second (pps) rates than the benign traffic, so we have extended the capture to span a longer time period to make the number of packets in both test subsets approximately the same. Therefore, we have composed a `caida_test_malicious.pcap` file.

#### Test Set: Merging Anonymized Traces With DDoS Traffic

After assembling both benign and malicious PCAPs, we need to merge them together into a single one. Before merging, we need to verify that some of the IP addresses in the train and test sets are not the same, which would make per-IP labeling inaccurate. After verification, we found out that there are no common IP addresses between the two subsets.

However, since the DDoS attack occurred one year before the benign capture, we need to shift the timestamps of packets so the attack and benign traffic look like they were happening consequently. For this purpose, we analyze the starting timestamp of both PCAPs (Benign: `1224162000.000409`, DDoS: `1186262676.485761`) and compute the difference as `37899323.5146`. We thus decide to shift the DDoS attack by the given timestamp (1y 2m 12d) to make the PCAPs intertwine:

19. Shift the DDoS attack trace to make both test parts intertwine:

```shell
editcap -t 37899323.6 caida_test_malicious.pcap caida_test_malicious_shifted.pcap
```

20. Finally, merge the both test parts and create the final test set:

```shell
mergecap -w caida_test.pcap caida_test_benign.pcap caida_test_malicious_shifted.pcap
```

## CTU-13 Dataset

CTU-13 dataset [6] is a collection of 13 scenarios consisting of real botnet traffic mixed with normal (benign) and background traffic. Each scenario executes a specific malware, which uses several protocols and performs different actions. Each scenario is provided in a raw PCAP format, as well as others such as NetFlows and WebLogs.

For our purposes, we experimented with scenarios 4, 10, and 11, declared to contain DDoS traffic. As scenarios 10 and 11 contained only 1 type of DoS, we opted for scenario 4 (named `CTU-Malware-Capture-Botnet-45`), which contains 2 attack types, namely UDP and ICMP DDoS. A huge advantage of this dataset is that it is not emulated but rather captures real infected computer traffic communicating with the C&C server and performing botnet tasks. Nevertheless, only a single bot is captured in scenario 4, significantly limiting the traffic characteristics diversity. Despite this fact, we believe that evaluating using CTU-13 is still valuable., as it shows the capability of the Windower to detect a single misbehaving host on a network, thus being suitable for small to medium-sized network monitoring purposes.

### Dataset Reconstruction

1. Download the CTU-13 dataset, scenario 4 as PCAP data:

```shell
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/capture20110815.truncated.pcap.bz2
```

The data itself are truncated to preserve privacy. Truncation is performed as follows: TCP: 54 bytes, UDP: 42 bytes, ICMP: 66 bytes. Similarly to other datasets, this fact has no impact on the Windower unless the temporal dependencies of data are kept and its headers are not corrupted.

2. Unzip the file using `bunzip`:

```shell
bunzip2 capture20110815.truncated.pcap.bz2
```

3. In order to simulate monitoring of a single network, we filter out only the traffic with the destination network `147.32.0.0/16`, which is considered a network of the Prague CVUT university, used for traffic capture of both benign traffic and bot attack data.

```shell
tcpdump -r capture20110815.truncated.pcap -w ctu13_cvutin.pcap 'dst net 147.32.0.0/16'
```

In addition to making the evaluation more realistic, limiting the `147.32.0.0/16` destination prefix efficiently decreased the number of packets from 62M in the full dataset version to 40M in the filtered one. This evaluation is, however, still not completely realistic, as situations when bi-directional traffic might be captured (e.g., both hosts from `147.32.0.0/16` subnet). Therefore, we also performed a "filtered" evaluation using only the source IP addresses specified in the dataset documentation (see `experiments` folder). These changes solve the issue as only uni-directional traffic is considered but limit the capture to very few IP addresses, making the evaluation less realistic and more lab-like. We thus continue with the `147.32.0.0/16` subnet with our dataset preparation and experiments discussed in our paper.

4. According to the documentation, the bot `147.32.84.165` strictly targeted one target - `147.32.96.69` with its DDoS traffic. Since the bot also performed other types of non-malicious communication. We need to extract malicious communication from benign. We use the following `tcpdump` commands for such purpose:

```shell
tcpdump -r ctu13_cvutin.pcap -w ctu_sc4_malicious.pcap 'ip and src host 147.32.84.165 and dst host 147.32.96.69'
tcpdump -r ctu13_cvutin.pcap -w ctu_sc4_benign.pcap 'ip and (not src host 147.32.84.165 or not dst host 147.32.96.69)'
```

After this phase, the files `ctu_sc4_malicious.pcap` and `ctu_sc4_benign.pcap` are obtained. Our manual analysis has shown that the malicious file contains no benign traffic and is consistent with the CTU-13 Scenario 4 documentation - the bot and the victim did not communicate except for the extracted attack scenarios.

5. Our manual analysis revealed that the benign dataset part contains several thousands of packets coming from the infected bot. As these packets cannot be considered malicious, we need to remap the IP address of the attacking traffic in order to perform proper per-packet labeling:

```shell
tcprewrite -i ctu_sc4_malicious.pcap -o ctu_sc4_malicious_remap.pcap --srcipmap=147.32.84.165/32:10.0.0.165/32
```

6. Merge the remapped attack traffic back to the benign one:

```shell
mergecap -w ctu_sc4_remap.pcap ctu_sc4_benign.pcap ctu_sc4_malicious_remap.pcap
```

7. Create train and test dataset subsets by splitting the remapped capture by the specified timestamp `2011-08-15 12:30:00`:

```shell
editcap -B "2011-08-15 12:30:00" ctu_sc4_malicious_remap.pcap ctu13_sc4_train.pcap
editcap -A "2011-08-15 12:30:00" ctu_sc4_malicious_remap.pcap ctu13_sc4_test.pcap
```

This step creates an attack-free train set and test set with UDP and ICMP DoS attacks performed by the bot. Despite the attack being declared to start at `12:21:33`, its true beginning was at `12:32:40`, so we utilized an extra 10 minutes to form a more robust train set.

8. Finally, create a file with the IP address of the attacking host to allow per-packet labeling:

```shell
echo 10.0.0.165 > ctu13_sc4_test_attack_ips.txt
```

## UNSW-NB15 Dataset

UNSW-NB15 [7] is one of the most popular datasets for NIDS evaluation nowadays. It contains 9 attack classes, including Denial of Service (`DoS`). We wanted to utilize this attack class along with the `normal` (benign) class to form another dataset to measure Windower's performance.

The dataset was captured in 2015 as a 2-day capture on 2015-01-22 and 2015-02-17 in a lab environment. Both benign and attack traffic were emulated via the traffic generation tool IXIA Perfect Storm. It consists of more than 2.5M records formed by 99GB of packets.

### Dataset Reconstruction

The community typically utilizes the dataset in its pre-extracted CSV format, which contains 49 features based on network bi-flows. However, Windower requires raw packet data (PCAP). UNSW-NB15 provides raw data as well, yet they are not separated by traffic classes but rather provided as a single continuous capture. For this purpose, we created a custom script `src/utils/flows2packets/flows2packets.py` to extract relevant packets based on flow data, as well as its parallel wrapper `flows2packets_parallel.py` to speed up the process.

The data reconstruction process is thus as follows:

1. Download the PCAP and CSV datasets from the source (folder `UNSW-NB15 - pcap files` and `UNSW-NB15 - CSV files`) under the root directory.

2. Merge 4 downloaded CSV dataset parts - `UNSW-NB15_{1,2,3,4}.csv` into a single file `unswnb15_full.csv`

3. Merge downloaded PCAPs by their day into `2015-01-22.pcap` and `2015-02-17.pcap`.

4. Since the CSV dataset is not split by the days, we need to split it manually to correspond with the PCAP version. We thus select a timestamp of `1422000000` corresponding to the 2015-01-23 date to split the data. All entries with a lesser timestamp correspond to `2015-01-22.csv`, while higher timestamps to `2015-02-17.csv`.

5. Select all flows corresponding to the relevant classes - `DoS` and benign class (value of `0` for the `label` feature), obtaining files `2015-01-22_benign.csv`, `2015-01-22_dos.csv`, `2015-02-17_benign.csv`, and `2015-02-17_dos.csv`.

6. Run the `flows2packets.py` script to extract relevant uni-directional traffic and obtain corresponding PCAP files.

```bash
flows2packets_parallel.py 2015-01-22.pcap 2015-01-22_benign.pcap 2015-01-22_benign.csv unswnb15 8
```

This command will run the parallel version of the script upon the capture from 2015-01-22 to extract only benign traffic from the UNSW-NB15 dataset with 8 parallel processes. Only uni-directional flow traffic will be considered after the extraction. This setting can be changed, and other datasets can be adapted by using `flows2packets_config.py` file, but the default configuration suffices our current needs. Repeat the same process for DoS traffic and the second capture day on 2015-02-17 by plugging relevant files. In the end, the following files should be available: `2015-01-22_benign.pcap`, `2015-01-22_dos.pcap`,
`2015-02-17_benign.pcap`, and `2015-02-17_dos.pcap`.

#### Train Set: 2015-01-22

7. Our training set only requires benign traffic, so we further focus on `2015-01-22_benign.pcap` file. In this case, we aim to extract benign traffic when no attack occurs. According to our analysis, such a period happened on 2015-01-22 15:00 - 16:00 GTM+1. Therefore, we extracted such a period using `editcap` and created a train set as:

```shell
editcap -A '2015-01-22 15:00' -B '2015-01-22 16:00' 2015-01-22_benign.pcap unsw_train.pcap
```

#### Test Set: 2015-02-17

8. In contrast to the train set, we wanted to choose a test set such that both benign and malicious traffic happen consequently. Since the traffic intensity was lower than during the training phase, we chose a 4-hour traffic block on 2015-02-18 between 8:00 and 12:00 when both benign and attacking traffic had the highest pps.

```shell
editcap -A '2015-02-18 08:00' -B '2015-01-22 12:00' 2015-02-18_benign.pcap 2015-02-18-0812_benign.pcap

editcap -A '2015-02-18 08:00' -B '2015-01-22 12:00' 2015-02-18_dos.pcap 2015-02-18-0812_dos.pcap
```

9. There were still many source IPs, so we limited their number to lower the amount of traffic and make the slow analysis within the original Kitsune feasible. We selected the following 10 source IPs from different prefixes to capture as general network characteristics as possible:

```shell
149.171.126.13
149.171.126.14
149.171.126.15
149.171.126.4
175.45.176.1
175.45.176.2
175.45.176.3
59.166.0.1
59.166.0.3
59.166.0.4
59.166.0.8
```

The extraction was performed via `tcpdump` and the final file was saved as `unsw_test_benign.pcap`.

10. Since the attack was performed from the same IP addresses as the benign traffic, attacking IP addresses need to be remapped to another subnet for packet labeling purposes (see - [Per-Packet Data Labeling](#per-packet-data-labeling)) section. We remap the IP addresses using `tcprewrite` and name the final file as `unsw_test_malicious.pcap`:

```bash
tcprewrite --infile 2015-02-18-0812_dos.pcap--outfile uni_02_partial_ready/2015-02-18_0812_dos_srcmapped.pcap --srcipmap '175.45.176.0/24:10.10.10.0/24'
```

11. Finally, both benign and malicious PCAPs can be merged into a final `unsw_test.pcap` file while keeping the list of remapped addresses (`unsw_test_attack_ips.txt`) for data labeling purposes.

## 2017-SUEE Dataset

In order to test our mechanism against low-rate (slow) DoS attacks, we employed the 2017-SUEE Dataset [8], which declares to provide SlowHTTP and Slowloris attacks by utilizing Slowloris, SlowHTTPTest, and Slowloris-ng tools. The attack was performed in November 2017 on the web server of the Student Union for Electrical Engineering (Fachbereichsvertretung Elektrotechnik) at Ulm University. The authors provide 2 versions of the dataset - SUEE1 with 2.1M packets comprising a 24h capture and SUEE8 with 19.3M packets captured over 8 days. IPs and MAC addresses were anonymized. Only TCP packets to or from ports 80 and 443 were captured.

Despite the authors' declarations, we noticed that the SUEE1 variant spans only 1h and 12m instead of declared 24h. Also, both dataset variants have invalid timestamps (timed to 1970), and packets are not ordered based on time. For these reasons, this dataset part significantly weakened its credibility. Therefore, we decided to use the SUEE8 version, which matched the declared capture duration of 8 days and contained packets with valid timestamps. The following subsection will describe how we selected a dataset subset for the Windower evaluation.

### Dataset Reconstruction

1. Download the 2017-SUEE dataset, SUEE8 variant:

```shell
wget https://github.com/vs-uulm/2017-SUEE-data-set/releases/download/v1.1/SUEE8.pcap
```

2. Packets are not ordered by the timestamps. Reoder the dataset using `reoderpcap`:

```shell
reordercap SUEE8.pcap suee8_reord.pcap
```

3. Use 80 minutes of the dataset to reduce the amount of data. 40 minutes for training, 40 minuts for testing. The attack lasts only 5 minutes, so choose a continuous traffic block and include the 5-minute attack traffic in the test only.

```shell
editcap -A '2017-11-05 14:30:00' -B '2017-11-05 15:10:00' suee8_reord.pcap suee8_train.pcap
editcap -A '2017-11-05 15:10:00' -B '2017-11-05 15:50:00' suee8_reord.pcap suee8_test.pcap
```

| **Part** | **Start**           | **End**             |
|----------|---------------------|---------------------|
| Train    | 2017-11-05 14:30:00 | 2017-11-05 15:10:00 |
| Test     | 2017-11-05 15:10:00 | 2017-11-05 15:50:00 |

4. Generate a list of attacking IP addresses for per-packet labeling:

```shell
for i in {1..150}; do
    echo 10.128.0.$i >> suee8_test_attack_ips.txt
done
```

## Per-Packet Data Labeling

Windower's design, as well as the mitigation simulation script, suppose that the set of attacking and non-attacking IP addresses is distinct. The mitigation simulation requires each packet to be labeled as benign/malicious in order to compute relevant mitigation metrics. Following the simplified case of non-overlapping attacking and non-attacking IPs, we performed per-packet labeling by IP addresses.

As discussed in previous sections concerning the reconstruction of particular datasets, in some cases, we needed to remap the IP addresses of attacking hosts to unique network subnets. Therefore, unique IP addresses marking attacking hosts must always be known. With such a list of IP addresses (e.g., obtained by `tshark -r DATASET_MALICIOUS.pcap -T fields -e ip.src | sort | uniq` command), we utilized a custom per-packet labeling script `dataset_label.py` located under the `src/utils/pcap/` folder.

Example run of the script to obtain `dataset_pktlabels.txt` file based on the list of malicious IPs `dataset_malicious_ips.txt` and a corresponding PCAP `dataset_test.pcap`:

```shell
dataset_label.py dataset_test.pcap dataset_malicious_ips.txt XXX_test_pktlabels.txt
```

## References

[1] The CAIDA UCSD Anonymized Internet Traces. Accessed 2023-10-30. Available at: <https://www.caida.org/catalog/datasets/passive_dataset>

[2] The CAIDA UCSD "DDoS Attack 2007" Dataset. Accessed 2023-10-30. Available at: <https://www.caida.org/catalog/datasets/ddos-20070804_dataset/>

[3] Apruzzese, G., Laskov, P., & Schneider, J. (2023). SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection. arXiv preprint arXiv:2305.00550. Available at: <https://arxiv.org/abs/2305.00550>

[4] Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C. (2022). Dos and don'ts of machine learning in computer security. In 31st USENIX Security Symposium (USENIX Security 22) (pp. 3971-3988). Available at: <https://www.usenix.org/conference/usenixsecurity22/presentation/arp>

[5] Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., & Cavallaro, L. (2019). TESSERACT: Eliminating experimental bias in malware classification across space and time. In 28th USENIX Security Symposium (USENIX Security 19) (pp. 729-746). Available at: <https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury>

[6] Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An empirical comparison of botnet detection methods. computers & security, 45, 100-123. Online dataset download: <https://www.stratosphereips.org/datasets-ctu13>

[7] Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)." Military Communications and Information Systems Conference (MilCIS), 2015. IEEE, 2015. Online dataset download: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

[8] Thomas Lukaseder. "2017-SUEE-data-set". 2017. GitHub repository. Available at: <https://github.com/vs-uulm/2017-SUEE-data-set>
