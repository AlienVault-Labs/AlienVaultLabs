'''Identifies sequences of log messages that indicate a single thread of action'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"


# Find sequences in log events
# by event id (SID) or by threading variables

# Take Variable Fields and follow them through a thread of messages

# great for giving analysts the full sequencing of things, especially for writing rules.


class LogSequence(object):
    '''A Behavioral Sequence of Log Events'''
    def __init__(self):
        pass
    
    
    
class SequenceEntry(object):
    '''A particular log Event in a behavioral Sequence of Log Events'''
    def __init__(self):
        pass
    
