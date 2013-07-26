#!/usr/bin/env python

from distutils.core import setup
import glob
import os
from DistUtilsExtra.command import *

setup(name='clearcutter',
      version='0.2',
      description='ClearCutter Log Event Processor',
      author='Conrad Constantine',
      author_email='conrad@alienvault.com',
      url = 'http://code.google.com/p/alienvault-labs-garage/',
      packages = ['clearcutter'],
      scripts=['clear-cutter'],
      cmdclass = { "build" : build_extra.build_extra},
      requires = ['argparse'],
      )

#TODO: easy_install argparse
