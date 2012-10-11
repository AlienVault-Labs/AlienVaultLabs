#!/usr/bin/env python

# PEiD 2 Yar
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# aortega@alienvault.com

import sys
import re
import os

if len(sys.argv) != 3:
	print "PEiD 2 Yar Help - AlienVault Labs"
	print "Usage: %s userdb.txt output.yar" % (sys.argv[0])
	sys.exit()

peid_file = sys.argv[1]
output_file = sys.argv[2]

if not os.path.exists(peid_file):
	print "Error, %s doesn't exist." % (peid_file)
	sys.exit()

peid_rules = {}

f = open(peid_file, "r")
data = f.read()
f.close()

m1 = re.compile("^\[(\* )?(?P<signame>.+)\]$")
m2 = re.compile("^signature = (?P<signature>.+)$")
m3 = re.compile("^ep_only = (?P<ep>true|false)$")

for i in data.split("\n"):
	ln = i.rstrip()
	m = m1.match(ln)
	if m:
		signame = "_" + m.group("signame").replace("+", "p").replace(" ", "_") + "_"
		for z in signame:
			if z.isalnum() == False and z != "_":
				signame = signame.replace(z, "")
		if signame not in peid_rules.keys():
			peid_rules[signame] = [{"desc": m.group("signame").replace("\"", "")}, []]
		continue
	m = m2.match(ln)
	if m:
		signature = m.group("signature")
		tmp = []
		cont = False
		for z in signature.split(" "):
			if cont == False and z == "??":
				continue
			else:
				cont = True
				tmp.append(z)
		signature = " ".join(tmp)
		continue
	m = m3.match(ln)
	if m:
		ep = m.group("ep")
		peid_rules[signame][1].append({"signature": signature, "ep": ep})

f = open(output_file, "w")
for i in peid_rules.keys():
	signame = i
	f.write("rule %s\n" % (signame))
	f.write("{\n")
	f.write("\tmeta:\n")
	f.write("\t\tdescription = \"%s\"\n" % (peid_rules[i][0]["desc"]))
	f.write("\tstrings:\n")
	count = 0
	for z in peid_rules[i][1]:
		f.write("\t\t$%s = {%s}\n" % (str(count), z["signature"]))
		count += 1
	f.write("\tcondition:\n\t\t")
	count = 0
	cond = ""
	for z in peid_rules[i][1]:
		cond = cond + "$%s" % (count)
		if z["ep"] == "true":
			cond = cond + " at entrypoint"
		cond = cond + " or "
		count += 1
	cond = cond[0:len(cond)-4]
	f.write(cond)
	f.write("\n}\n")
f.close()

