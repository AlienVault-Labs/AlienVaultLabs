#!/usr/bin/env python

# PEiD signatures sanitizer
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# aortega@alienvault.com

import sys
import re
import os

if len(sys.argv) != 3:
	print "PEiD signatures sanitizer Help - AlienVault Labs"
	print "Usage: %s userdb.txt output.txt" % (sys.argv[0])
	sys.exit()

peid_file = sys.argv[1]
output_file = sys.argv[2]

if not os.path.exists(peid_file):
	print "Error, %s doesn't exist." % (peid_file)
	sys.exit()

peid_rules = []

f = open(peid_file, "r")
data = f.read()
f.close()

m1 = re.compile("^\[(?P<signame>.+)\].*$")
m2 = re.compile("^signature = (?P<signature>.+)$")
m3 = re.compile("^ep_only = (?P<ep>true|false).*$")
m4 = re.compile("^([\dABCDEF]{2} ?|\?\? ?)+$") # Signature bytes validator for PEiD

count = 0
for i in data.split("\n"):
	ln = i.rstrip()
	count += 1
	m = m1.match(ln)
	if m:
		signame = m.group("signame")
		skip = True
		continue
	m = m2.match(ln)
	if m:
		signature = m.group("signature")
		m = m4.match(signature)
		if not m:
			print "Signature [%s] malformed at line %s, skipping" % (signame, count)
			continue
		skip = False
		continue
	m = m3.match(ln)
	if m and skip != True:
		ep = m.group("ep")
		peid_rules.append({"name": signame, "signature": signature, "ep": ep})

f = open(output_file, "w")
f.write("; %s signatures added\n\n" % (len(peid_rules)))
for s in peid_rules:
	f.write("[%s]\n" % (s["name"]))
	f.write("signature = %s\n" % (s["signature"]))
	f.write("ep_only = %s\n\n" % (s["ep"]))
f.close()

