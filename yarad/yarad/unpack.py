#!/usr/bin/env python

# yarad - Yara daemon
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# earada@alienvault.com

import yara
import os
import tempfile
from zlib import decompress

finger_rules = yara.compile(filepath='fingerprints/index.yar', includes = True)

def flash_cws(f):
	tf = tempfile.NamedTemporaryFile(delete=False)
	with open(f, 'rb') as fh:
		try:
			c = fh.read()
			tf.file.write('FWS' + c[3] + c[4:8] + decompress(c[8:]))
			tf.file.flush()
		except:
			raise NameError("Corrupted File")
	print "[*] Created: %s" % (tf.name)
	return tf.name

filetypes = {'flash_cws' : flash_cws}

def unpack(f):
	for i in finger_rules.match(f):
		if (i.rule in filetypes):
			return filetypes[i.rule](f)
	return None

def delete(f):
	print "[*] Delete: %s" % (f)
	os.unlink(f)
