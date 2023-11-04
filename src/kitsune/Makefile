
SOURCES := $(shell find $(SOURCEDIR) -name '*.pcap')

OUTPUTS := $(SOURCES:%.pcap=%.tsv)

default: $(OUTPUTS)

%.tsv: %.pcap
	tshark -r $< -T fields -E header=y -E occurrence=f \
		-e frame.time_epoch -e frame.len \
		-e eth.src -e eth.dst \
		-e ip.src -e ip.dst \
		-e tcp.srcport -e tcp.dstport \
		-e udp.srcport -e udp.dstport \
		-e icmp.type -e icmp.code \
		-e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 \
		-e ipv6.src -e ipv6.dst \
		>$@
