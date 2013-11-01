## autoscan - automatic fingerprint of visited networks

autscan remembers network parameters (addresses, dns...) and runs a basic
fingerprinting (traceroute, scan) of the network you are connected to.

It has 2 modes:
* runnow: run the fingerprint on the specified interface
* monitor: wait on the specified interface, and everytime you
connect to a new network it will do the fingerprint

##### Fingerprinting steps:
```
_test_pcap
	records a 15s PCAP in the background (tcpdump)
_test_ifconfig
	remembers ipv4 and ipv6 attributed by DHCP (ifconfig)
_test_iwconfig
	remembers AP name and MAC (iwconfig)
_test_route
	remembers routing table (route -n)
_test_resolv
	remembers DNS attributed by dhcp (resolv.conf)
_test_pubip_get
	gets your internet public IP (curl ifconfig.me)
_test_pubip_ping
	tests if an arbitrary public IP answers to ping (ping 8.8.8.8)
_test_pubip_traceroute
	runs a traceroute to an arbitrary public IP (ping 8.8.8.8)
_test_resolv_traceroute
	runs a traceroute to the DNS given by dhcp (traceroute)
The following steps can be disabled using -x to run faster:
_test_explor_traceroute
	runs traceroute to arbitrary private IP ranges (traceroute)
_test_explor_scan
	runs an nmap scan on the local /24 IP range (nmap)
```

### Example usage: Run fingerprinting on wlan0

```bash
$ sudo ./autoscan.py wlan0
20130724-143501 [>] wlan0: _do_tests
20130724-143501 [-] wlan0: _test_pcap
20130724-143501 [-] wlan0: _test_ifconfig
20130724-143501 [-] wlan0: _test_iwconfig
20130724-143501 [-] wlan0: _test_route
20130724-143502 [-] wlan0: _test_resolv
20130724-143502 [-] wlan0: _test_pubip_get
20130724-143510 [-] wlan0: _test_pubip_ping
20130724-143510 [-] wlan0: _test_pubip_traceroute
20130724-143516 [-] wlan0: _test_resolv_traceroute
20130724-143527 [-] wlan0: _test_explor_traceroute
20130724-143710 [-] wlan0: _test_explor_scan
20130724-143725 [*] wlan0: ./20130724_123501_wlan0_82.247.82.44_freeflo
```

The last line indicates where the file where saved.
(Use -o to specify a parent directory).

##### List the generated files:
```bash
find ./20130724_123501_wlan0_82.247.82.44_freeflo
./20130724_123501_wlan0_82.247.82.44_freeflo
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv_traceroute
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv_traceroute/out
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_get
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_get/ip
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_traceroute
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_traceroute/out
./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig
./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig/ap
./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig/essid
./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig/out
./20130724_123501_wlan0_82.247.82.44_freeflo/route
./20130724_123501_wlan0_82.247.82.44_freeflo/route/gw
./20130724_123501_wlan0_82.247.82.44_freeflo/route/out
./20130724_123501_wlan0_82.247.82.44_freeflo/pcap
./20130724_123501_wlan0_82.247.82.44_freeflo/pcap/tcpdump.pcap
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv/dns0
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv/dns1
./20130724_123501_wlan0_82.247.82.44_freeflo/resolv/resolv.conf
./20130724_123501_wlan0_82.247.82.44_freeflo/ifconfig
./20130724_123501_wlan0_82.247.82.44_freeflo/ifconfig/up
./20130724_123501_wlan0_82.247.82.44_freeflo/ifconfig/ip4
./20130724_123501_wlan0_82.247.82.44_freeflo/ifconfig/ip6
./20130724_123501_wlan0_82.247.82.44_freeflo/ifconfig/out
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_scan
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_scan/localnet.nmap
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_scan/localnet.xml
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_scan/localnet.gnmap
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_scan/out
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute/out_172.16.0.1
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute/out_192.168.0.1
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute/out_192.168.2.1
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute/out_10.0.0.1
./20130724_123501_wlan0_82.247.82.44_freeflo/explor_traceroute/out_192.168.1.1
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_ping
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_ping/code
./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_ping/out
```

##### Look at the output of iwconfig:
```bash
$ more ./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig/out
wlan0     IEEE 802.11abgn  ESSID:"freeflo"  
          Mode:Managed  Frequency:2.462 GHz  Access Point: 7A:A4:42:11:E9:B3
          Bit Rate=54 Mb/s   Tx-Power=15 dBm   
          Retry  long limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off
          Link Quality=62/70  Signal level=-48 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:18  Invalid misc:1208   Missed beacon:0
```

##### Look at the SSID:
```bash
$ more ./20130724_123501_wlan0_82.247.82.44_freeflo/iwconfig/essid 
freeflo
```

##### Look at the public IP:
```bash
$ more ./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_get/ip 
82.247.82.44
```

### Example usage: Run in monitor mode on wlan0

I connect to WIFI networks "freeflo" then "FreeWifi"

```bash
sudo ./autoscan.py -m wlan0
20130724-144805 [>] wlan0: _wait_up        # autoscan waits for a network
20130724-144808 [>] wlan0: _do_tests       # I just connected to "freeflo"
20130724-144808 [-] wlan0: _test_pcap
20130724-144808 [-] wlan0: _test_ifconfig
20130724-144811 [-] wlan0: _test_iwconfig
20130724-144811 [-] wlan0: _test_route
20130724-144811 [-] wlan0: _test_resolv
20130724-144811 [-] wlan0: _test_pubip_get
20130724-144814 [-] wlan0: _test_pubip_ping
20130724-144815 [-] wlan0: _test_pubip_traceroute
20130724-144821 [-] wlan0: _test_resolv_traceroute
20130724-144842 [-] wlan0: _test_explor_traceroute
20130724-145041 [-] wlan0: _test_explor_scan
20130724-145050 [*] wlan0: ./20130724_124808_wlan0_82.247.82.44_freeflo
20130724-145050 [>] wlan0: _wait_down      # autoscan waits for me to disconnect
20130724-145455 [>] wlan0: _wait_up        # I disconnected from "freeflo"
20130724-145514 [>] wlan0: _do_tests       # I connect to "FreeWifi"
20130724-145514 [-] wlan0: _test_pcap
20130724-145514 [-] wlan0: _test_ifconfig
20130724-145514 [-] wlan0: _test_iwconfig
20130724-145514 [-] wlan0: _test_route
20130724-145514 [-] wlan0: _test_resolv
20130724-145514 [-] wlan0: _test_pubip_get
20130724-145515 [-] wlan0: _test_pubip_ping
20130724-145518 [-] wlan0: _test_pubip_traceroute
20130724-145549 [-] wlan0: _test_resolv_traceroute
20130724-145604 [-] wlan0: _test_explor_traceroute
20130724-145835 [-] wlan0: _test_explor_scan
20130724-150202 [*] wlan0: ./20130724_125514_wlan0_78.251.248.51_FreeWifi
20130724-150202 [>] wlan0: _wait_down
```

### Hint for showing results

```bash
find ./20130724_123501_wlan0_82.247.82.44_freeflo |while read a; do [[ -f $a ]] && echo -e "\n====== $a =====" && cat $a || echo -e "\n>>>>>> $a <<<<<<"; done |less

>>>>>> ./20130724_123501_wlan0_82.247.82.44_freeflo <<<<<<

>>>>>> ./20130724_123501_wlan0_82.247.82.44_freeflo/resolv_traceroute <<<<<<

====== ./20130724_123501_wlan0_82.247.82.44_freeflo/resolv_traceroute/out =====
traceroute to 212.27.40.241 (212.27.40.241), 30 hops max, 60 byte packets
 1  192.168.0.254 (192.168.0.254)  15.454 ms  15.740 ms  16.317 ms
 2  82.247.82.254 (82.247.82.254)  36.635 ms  36.634 ms  38.103 ms
 3  78.254.0.94 (78.254.0.94)  38.338 ms  39.373 ms  39.829 ms
 4  bob75-1-v900.intf.nra.proxad.net (78.254.255.9)  40.014 ms  41.213 ms  41.528 ms
 5  mna75-1-v902.intf.nra.proxad.net (78.254.255.5)  43.312 ms  43.646 ms  45.755 ms
 6  mna75-1-v904.intf.nra.proxad.net (78.254.254.33)  46.562 ms  20.566 ms  25.581 ms
 7  th2-6k-2-1-po1.intf.nra.proxad.net (78.254.255.1)  28.249 ms * *
 8  bzn-crs16-1-be1004.intf.routers.proxad.net (212.27.50.173)  35.308 ms  35.552 ms  35.797 ms
 9  bzn-6k-2-po20.intf.routers.proxad.net (212.27.50.62)  35.870 ms * *
10  bzn-49m-7-v940.intf.routers.proxad.net (212.27.56.78)  35.917 ms  37.020 ms  38.331 ms
11  dns2.proxad.net (212.27.40.241)  38.524 ms  38.589 ms  38.468 ms

>>>>>> ./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_get <<<<<<

====== ./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_get/ip =====
82.247.82.44

>>>>>> ./20130724_123501_wlan0_82.247.82.44_freeflo/pubip_traceroute <<<<<<
# [...]
```
