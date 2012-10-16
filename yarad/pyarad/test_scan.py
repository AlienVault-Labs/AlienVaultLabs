#!/usr/bin/env python

import pyarad
import sys

if len(sys.argv) != 2:
	print "%s file" % (sys.argv[0])
	sys.exit()

y = pyarad.pyarad()
y.init_unix_socket()
print y.scan_file(sys.argv[1])
y.close()

