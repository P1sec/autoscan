#!/bin/bash

err() {
	echo "ERROR: $1"
	exit 1
}

sudo PATH="./spoofbin/:$PATH" ../autoscan.py -v -p 127.0.0.1 -o test_output/ -r eth0 ||err "autoscan execution failed"

# XXX test output dirs
dir="test_output/$(ls -1 test_output |tail -n1)"
[[ -e $dir/pcap/tcpdump.pcap ]] ||err "pcap/tcpdump.pcap"
[[ $(cat $dir/ifconfig/ip4) = "10.137.2.9" ]] ||err "ifconfig/ip4"
[[ $(cat $dir/ifconfig/ip6) = "fe80::216:3eff:fe5e:6c07" ]] ||err "ifconfig/ip6"
[[ $(cat $dir/route/gw) = "10.137.2.1" ]] ||err "route/gw"
[[ $(cat $dir/pubip_ping/code) = "0" ]] ||err "pubip_ping/code"
[[ -e $dir/resolv/resolv.conf ]] ||err "resolv/resolv.conf"
[[ $(cat $dir/pubip_get/ip) = "1.2.3.4" ]] ||err "pubip_get/ip"
[[ -e $dir/pubip_traceroute/out ]] ||err "pubip_traceroute/out"
[[ -e $dir/resolv_traceroute/out ]] ||err "resolv_traceroute/out"
[[ -e "$dir/explor_traceroute/out_192.168.0.1" ]] ||err "explor_traceroute/out_192.168.0.1"
[[ -e $dir/explor_scan/localnet.nmap ]] ||err "explor_scan/localnet.nmap"

echo "TEST OK"
