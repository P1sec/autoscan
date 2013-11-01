#!/usr/bin/env python

# autoscan - automatic fingerprint of visited networks
# 2013, Laurent Ghigonis at P1 Security <laurent@p1sec.com>

import sys
import os
import time
import subprocess
import traceback
import re
import argparse
import shutil
import errno
import logging

class Autoscan_iface(object):
        def __init__(self, iface, outdir=".", logfile=None, loglevel=logging.INFO, target_pubip="8.8.8.8", noexplore=False):
		logstream = None
		if not logfile:
			logstream = sys.stdout
		logging.basicConfig(filename=logfile, level=loglevel,
			stream=logstream,
			format='%(asctime)s %(message)s',
			datefmt="%Y%m%d-%H%M%S")
                self.iface = iface
                self.outdir = outdir
                self.target_pubip = target_pubip
		self.noexplore = noexplore
                self.date = None # set by _do_tests()
                if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
                        self.perm_uid = int(os.environ['SUDO_UID'])
                        self.perm_gid = int(os.environ['SUDO_GID'])
                else:
                        self.perm_uid = os.getuid()
                        self.perm_gid = os.getgid()
                self.found_ip4 = None
                self.found_ip6 = None
                self.found_pubip = None
                self.found_dns = list()
		self.found_essid = None

        def run_now(self):
                self._do_tests()

        def monitor(self):
		self._wait_up()
                self._do_tests()
                while True:
                        self._wait_down()
                        self._wait_up()
                        self._do_tests()

        def _wait_up(self):
		logging.info("[>] %s: _wait_up", self.iface)
                while True:
                        out, err, code = self._exec(
                                ['ifconfig', self.iface])
			# iface up
                        up = re.search(r'UP', out)
                        ip4 = re.search(r'inet (\S+)', out)
                        ip6 = re.search(r'inet6 (\S+)', out)
                        if up and ip4: # XXX no ip6 because too fast
                                break
			# loop
                        time.sleep(0.5)
		time.sleep(3) # XXX wait for network to be configured

        def _wait_down(self):
		logging.info("[>] %s: _wait_down", self.iface)
		last_ip4 = None
		last_ip6 = None
		last_t = None
                while True:
                        out, err, code = self._exec(
                                ['ifconfig', self.iface])
			# iface down
                        up = re.search(r'UP', out)
                        if not up:
                                break
			# iface ip change
                        ip4 = re.search(r'inet (\S+)', out)
			if ip4: ip4 = ip4.group(1)
			if (not ip4 and last_ip4) or \
					(ip4 and last_ip4 and ip4 != last_ip4):
				break
			last_ip4 = ip4
                        ip6 = re.search(r'inet6 (\S+)', out)
			if ip6: ip6 = ip6.group(1)
			if (not ip6 and last_ip6) or \
					(ip6 and last_ip6 and ip6 != last_ip6):
				break
			last_ip6 = ip6
			# sleep detection
			t = time.clock()
			if last_t and (t - last_t > 1):
				break
			last_t = t
			# loop
                        time.sleep(0.5)

        def _do_tests(self):
		logging.info("[>] %s: _do_tests", self.iface)
                self.date = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
                self._do_tests_run(self._test_pcap)
                self._do_tests_run(self._test_ifconfig)
                self._do_tests_run(self._test_iwconfig)
                self._do_tests_run(self._test_route)
                self._do_tests_run(self._test_resolv)
                self._do_tests_run(self._test_pubip_get)
                self._do_tests_run(self._test_pubip_ping)
                self._do_tests_run(self._test_pubip_traceroute)
                self._do_tests_run(self._test_resolv_traceroute)
		if not self.noexplore:
			self._do_tests_run(self._test_explor_traceroute)
			self._do_tests_run(self._test_explor_scan)
		self._storepath_rename()

        def _do_tests_run(self, func):
                try:
			logging.info("[-] %s: %s" % (self.iface, func.__name__))
                        func()
                except Exception, e:
			logging.info("[!] %s: test %s failed: %s" % (self.iface, func, e))
			logging.info(traceback.format_exc())

        def _test_pcap(self):
                if os.fork() != 0:
                        return
                # child
                os.system("$(tcpdump -ni %s -w %s 2>/dev/null & sleep 15; kill %%1) &" % (
                        self.iface, self._storepath_get("pcap/tcpdump.pcap")))
                sys.exit(0)

        def _test_ifconfig(self):
                out, err, code = self._exec(
                        ['ifconfig', self.iface])
                self._store("ifconfig/out", out)
                up = re.search(r'UP', out)
                if up: self._store("ifconfig/up", "")
                ip4 = re.search(r'inet (\S+)', out)
                if ip4:
                        self._store("ifconfig/ip4", ip4.group(1))
                        self.found_ip4 = ip4.group(1)
                ip6 = re.search(r'inet6 (\S+)', out)
                if ip6:
                        self._store("ifconfig/ip6", ip6.group(1))
                        self.found_ip6 = ip6.group(1)

        def _test_iwconfig(self):
		self.found_essid = None
                out, err, code = self._exec(
                        ['iwconfig', self.iface])
                if len(out) == 0:
                        return # not a WIFI interface
                self._store("iwconfig/out", out)
                essid = re.search(r'ESSID:(\S+)', out)
                if essid:
			essid = essid.group(1).replace("\"", "")
			self.found_essid = essid
			self._store("iwconfig/essid", essid)
                ap = re.search(r'Access Point: (\S+)', out)
                if ap:
			self._store("iwconfig/ap", ap.group(1))

        def _test_route(self):
                out, err, code = self._exec(
                        ['route', '-n'])
                self._store("route/out", out)
                gw = re.findall(r'(\S+)', out.split('\n')[2])[1]
                if gw: self._store("route/gw", gw)

        def _test_resolv(self):
                shutil.copy("/etc/resolv.conf", self._storepath_get("resolv/resolv.conf"))
                n = 0
                with open("/etc/resolv.conf") as f:
                        for line in f:
                                r = re.search('nameserver (\S+)', line)
                                if r:
                                        dns = r.group(1)
                                        self._store("resolv/dns%d" % n, dns)
                                        self.found_dns.append(dns)
                                        n += 1
                                        

        def _test_pubip_get(self):
                out, err, code = self._exec(
                        ['curl', '--retry', '3', 'ifconfig.me'])
		if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', out):
			self._store("pubip_get/ip", out)
			self.found_pubip = out.strip()
		else:
			self._store("pubip_get/out", out)
			self.found_pubip = None

        def _test_pubip_ping(self):
                out, err, code = self._exec(
                        ['ping', '-W', '3', '-c', '1', self.target_pubip])
                self._store("pubip_ping/code", code)
                self._store("pubip_ping/out", out)

        def _test_pubip_traceroute(self):
                self._store("pubip_traceroute/out",
                        self._util_traceroute(self.target_pubip))

        def _test_resolv_traceroute(self):
                for dns in self.found_dns:
                        self._store("resolv_traceroute/out",
                                self._util_traceroute(dns))

        def _test_explor_traceroute(self):
                targets = ["192.168.0.1", "192.168.1.1", "192.168.2.1", "10.0.0.1", "172.16.0.1"]
                for t in targets:
                        self._store("explor_traceroute/out_%s" % t,
                                self._util_traceroute(t))

        def _test_explor_scan(self):
                target = re.sub('\.[0-9]+$', '', self.found_ip4) + ".0/24" # XXX v6
                out, err, code = self._exec(
                        ['nmap', '-oA', self._storepath_get("explor_scan/localnet"), '-p', '21,22,23,445,80,443,8080,8081,8082,8083', target])
                self._store("explor_scan/out", out)
		if len(err) > 0:
			self._store("explor_scan/err", err)

        def _exec(self, cmd):
                p = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate()
                return out, err, p.returncode

        def _store(self, suffix, txt):
                name = self._storepath_get(suffix)
		logging.debug("%s = %s" % (name, txt))
                f = open(name, "w+")
                f.write(str(txt))
                f.close()
                os.chown(name, self.perm_uid, self.perm_gid)

        def _storepath_get(self, suffix=None):
                path = "%s/%s_%s" % (self.outdir, self.date, self.iface)
		if suffix:
			path += "/" + suffix
                d = os.path.dirname(path)
                if not os.path.isdir(d):
                        os.makedirs(d)
                        subprocess.check_output(['chown', '-R', '%s:%s' % (self.perm_uid, self.perm_gid), self.outdir]) # pythonic way is awefull
                return path

	def _storepath_rename(self):
		if self.found_pubip:
			suffix = self.found_pubip
		else:
			suffix = self.found_ip4
		if self.found_essid:
			suffix += "_" + self.found_essid
		newpath = self._storepath_get() + "_" + suffix
		logging.info("[*] %s: %s" % (self.iface, newpath))
		os.rename(self._storepath_get(), newpath)

        def _util_traceroute(self, target):
                out, err, code = self._exec(
                        ['traceroute', target])
                return out


# XXX all ifaces by default, use netifaces

parser = argparse.ArgumentParser()
parser.add_argument("interfaces", nargs='+',
                        help="Interface(s) to use")
parser.add_argument("-m", "--monitor", action="store_true",
                        help="Mode monitor: Stay in the background and automaticaly run when interface turns up")
parser.add_argument("-r", "--runnow", action="store_true",
                        help="Mode runnow (default): Run tests/scans now and exit")
parser.add_argument("-b", "--background", action="store_true",
                        help="Run in background for monitor mode, = daemonize")
parser.add_argument("-o", "--outdir", action="store", default=".",
                        help="Use DIR as output directory")
parser.add_argument("-x", "--noexplore", action="store_true",
                        help="Do not run explore tests (traceroute to arbitrary local ranges + nmap scan)")
parser.add_argument("-p", "--pubip", action="store", default="8.8.8.8",
                        help="Use target IP for public IP tests")
parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet logging (warning only)")
parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose logging")
args = parser.parse_args()

if args.runnow and args.monitor:
	print "Cannot specify both monitor and runnow modes !"
	sys.exit(1)
if args.runnow and args.background:
	print "Cannot specify background with runnow !"
	sys.exit(1)
if args.verbose and args.quiet:
	print "Cannot specify both verbose and quiet !"
	sys.exit(1)

if not args.runnow and not args.monitor:
	args.runnow = True
if args.runnow:
	args.background = False
if not args.background:
	logfile = None
else:
	logfile = "autoscan.log"
if args.verbose:
	loglevel = logging.DEBUG
elif args.quiet:
	loglevel = logging.WARN
else:
	loglevel = logging.INFO

if not os.geteuid() == 0:
        sys.exit('must be root')

for iface in args.interfaces:
        if os.fork() == 0:
                autoscan = Autoscan_iface(iface, args.outdir,
					logfile=logfile,
					loglevel=loglevel,
					target_pubip=args.pubip,
                                        noexplore=args.noexplore)
                if args.runnow:
                        autoscan.run_now()
                else:
                        autoscan.monitor()
                        # UNREACHED

if not args.background:
        while True:
                try: os.wait()
                except: break
        
