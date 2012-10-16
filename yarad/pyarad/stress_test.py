#!/usr/bin/env python

import pyarad
from multiprocessing import Process
import sys

# Method 1

def run():
	y = pyarad.pyarad()
	y.init_unix_socket()
	print y.scan_file("/tmp/test.exe")
	y.close()

for i in range(1000):
	p = Process(target=run, args=())
	p.start()

###

# Method 2

y = pyarad.pyarad()
y.init_unix_socket()
for i in range(1000):
	print y.scan_file("/tmp/test.exe")
y.close()

###
