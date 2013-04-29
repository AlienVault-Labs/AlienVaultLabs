#!/usr/bin/env python

# yarad - Yara daemon
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# aortega@alienvault.com

import yara
from multiprocessing import Process
import socket
import os
import ConfigParser
import sys
import zlib
import unpack

config = ConfigParser.ConfigParser()
config.read("yarad.cfg")

daemonize = config.getint("server", "daemon")
if daemonize == 1:
	import daemon

rules_f = config.get("server", "rules_file")
pidfile = config.get("server", "pidfile")

srv_config = {}
srv_config["type"] = config.get("server", "type")
if srv_config["type"] == "unix":
	srv_config["file"] = config.get("unix", "socket_file")
elif srv_config["type"] == "inet":
	srv_config["host"] = config.get("inet", "host")
	srv_config["port"] = config.getint("inet", "port")
else:
	print "Invalid server config"
	sys.exit()

def dipatch_client_unix_file(conn, rules):
	f = ""
	while f != "!close":
		try:
			f = conn.recv(1024)
			if f == "!close":
				break
			if os.path.exists(f):
				uf = unpack.unpack(f)
				if uf:
					f = uf
				matches = []
				for i in rules.match(f):
					matches.append({
							"name": i.rule, "namespace": i.namespace,
							"meta": i.meta, "tags": i.tags
						       })
				conn.send(str(matches))
				if uf:
					unpack.delete(uf)
			else:
				conn.send("[]")
		except:
			break
	conn.close()

def dispatch_client_inet_socket(conn, rules):
	f = ""
	while f != "!close":
		try:
			f = conn.recv(16384)
			if f == "!close":
				break
			sample_stream = zlib.decompress(f)
			matches = []
			for i in rules.match(data=sample_stream):
				matches.append({
						"name": i.rule, "namespace": i.namespace,
						"meta": i.meta, "tags": i.tags
					       })
			conn.send(str(matches))
		except:
			break
	conn.close()

def write_pidfile(pidfile):
	f = open(pidfile, "w")
	f.write("%s\n" % (str(os.getpid())))
	f.close()

def mainloop(rules, srv_config):
	if srv_config["type"] == "unix":
		if os.path.exists(srv_config["file"]):
			os.unlink(srv_config["file"])
		server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		server.bind(srv_config["file"])
		dispatch_func = dipatch_client_unix_file
	else:
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.bind((srv_config["host"], srv_config["port"]))
		dispatch_func = dispatch_client_inet_socket
	server.listen(1)
	while True:
		conn, addr = server.accept()
		p = Process(target=dispatch_func, args=(conn, rules))
		p.start()
	server.close()

print "[*] Starting"
print "[*] Loading rules (%s) ... " % (rules_f),
sys.stdout.flush()
rules = yara.compile(filepath=rules_f, includes = True)
print "OK"

if daemonize == 1:
	print "[*] Forking ..."
	with daemon.DaemonContext():
		write_pidfile(pidfile)
		mainloop(rules, srv_config)
else:
	write_pidfile(pidfile)
	mainloop(rules, srv_config)

