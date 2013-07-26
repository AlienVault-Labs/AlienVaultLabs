'''Shared LogFile Class for Clearcutter Functions'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"

#TODO: Add transparent support and normalization for multiple log file formats
#TODO: Add remote retrieval of logs? perhaps from DB sources

import os, sys

class LogFile(object):
    '''
    Log File object with a few helper functions for other clearcutter modes
    '''    
    _filedata = ""
    Filename = ""
    Length = 0
    Position = 0
    
    def __init__(self, filename, verbose=False, memory=True):
        self.Filename = filename
        try:
            self.Length = os.path.getsize(filename)
        except IOError:  #problem loading file
            print "Could not open log file : " + filename + " - " + sys.exc_info()[2]
            sys.exit()
        
        if (memory == True and self.Length < 2147483648):
            if verbose == True: print "Loading file into RAM"
            filehandle = open(filename, 'r')            
            self._filedata = filehandle.readlines()
        else:
            if verbose == True: print "Reading from Disk"
            self._filedata = open(filename, 'r')
            
        try:             
            if verbose == True : print "Using File: " + filename
            self._filedata = open(filename, 'r')
        except ValueError:
            if verbose == True : print "Invalid Filename: " + sys.exc_info()[2]
            raise sys.exc_info()
        except IOError:
            if verbose == True : print "File Access Error: " + sys.exc_info()[2]
            raise sys.exc_info()
        self.Length = os.path.getsize(filename)
    
    def RetrieveCurrentLine(self, verbose=False):
        self.Position = self._filedata.tell()        
        return self._filedata.readline() #Fix for in-memory
        