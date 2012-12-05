#!/usr/bin/env python

# pefile signatures file loader
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# aortega@alienvault.com

import peutils
import sys
import re
import os

if len(sys.argv) != 2:
	print "pefile signatures file loader Help - AlienVault Labs"
	print "Usage: %s userdb.txt" % (sys.argv[0])
	sys.exit()

peid_file = sys.argv[1]

if not os.path.exists(peid_file):
	print "Error, %s doesn't exist." % (peid_file)
	sys.exit()

peutils.SignatureDatabase(sys.argv[1])

print "OK"
