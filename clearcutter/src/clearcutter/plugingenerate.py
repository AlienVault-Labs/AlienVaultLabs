'''OSSIM detector plugin config file generation code for ClearCutter'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"

from ConfigParser import ConfigParser
import commonvars


class Generator(object):
    '''
    Creates an OSSIM collector plugin .cfg file
    '''

    SIDs = ''

    Plugin = ConfigParser()

    PluginFile = "testplugin.cfg"

    def __init__(self, entries):
        '''
        Build a new Plugin Generator
        '''
        #self.SIDs = entries
        #self.Plugin.add_section("DEFAULT")
        #self.Plugin.add_section("config")
        for SID in entries:
            
            
            self.Plugin.add_section(SID)
            self.Plugin.set(SID, "regexp", SID)
            options = commonvars.DefaultDirectives
            options.remove('regexp') #this is added later
            for directive in options:
                self.Plugin.set(SID, directive, "")

        
    def WritePlugin(self):
        outfile = open(self.PluginFile, "w")
        self.Plugin.write(outfile) 

    def WriteSQL(self):
        pass
    
        
        

