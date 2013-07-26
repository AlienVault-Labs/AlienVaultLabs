'''
Validates that an OSSIM plugin contains no syntactic errors

Displays information helpful to creating an internally-consistent plugin
'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.2"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"

import ConfigParser, commonvars, re, sys

class PluginValidator(object):
    """
    Locates common errors within an OSSIM plugin
    """
    
    _plugin = ""
    _valid = True
    _sids = []
    _userlabels = {
                   "userdata1" : [],
                   "userdata2" : [],
                   "userdata3" : [],
                   "userdata4" : [],
                   "userdata5" : [],
                   "userdata6" : [],
                   "userdata7" : [],
                   "userdata8" : [],
                   "userdata9" : []
                   }

    SECTIONS_NOT_RULES = ["config", "info", "translation"]
    ESSENTIAL_OPTIONS = ['regexp', 'event_type', 'plugin_sid']
    
    def __init__(self, plugin):
        self._plugin = plugin

    
    def IsValid(self):
        '''Process a plugin .cfg as the OSSIM agent would, noting any malformed or missing directives'''
        
        self.CheckSections()
        self.PrintLabelUsage()
        
        if self._valid is False: print "\nErrors detected in OSSIM Plugin file\n"
        return self._valid 
        # load each SID section
        
        # step through the remaining directives and make sure they're on the list
        # check for directives that end up being empty with the sample logs
        # Identify any labels in the regexp that aren't used in the userdata fields
        # for directive in plugingenerate.DefaultDirectives:
    
    def CheckSections(self):
        '''
        Step through each plugin section and validate contents are correct
        '''
        for rule in self._plugin.sections():
            if rule.lower() not in self.SECTIONS_NOT_RULES :
                self.CheckEssentials(rule)
                self.CheckOptions(rule)
                
    def CheckEssentials(self, section):
        '''
        Check that a plugin section contains the minimum necessary options
        '''
        for essential in self.ESSENTIAL_OPTIONS:
            if essential not in self._plugin.options(section): 
                print "\tsection '" + section + "' has no " + essential + " option!\n"
                self.valid = False
        
    def CheckOptions(self, rule):
        '''
        Iterate through options listed in each section, and test they are valid OSSIM agent options          
        '''

        print "\n-------------------\nProcessing Rule [" + rule + "]"
        
        for option in self._plugin.options(rule):
            if (option not in commonvars.DefaultDirectives):
                print "\tOption '" + option + "' in section '" + rule + "'is invalid"
                self._valid = False
            self.CheckValues(rule, option)

   
    
    def CheckValues(self, rule, option):
        '''
        Validate that the value of an option is properly-formed
        '''

        # check for empty directives        
        if option == 'regexp':
                self.CheckRegexValue(rule)
        
        if option == 'plugin_sid':
                self.CheckDuplicateSID(self._plugin.get(rule, option))
        
        if self._plugin.get(rule, option) is '':
            print "\tOption '" + option + "' has no assigned value"
            self._valid = False

        self.CheckLabelValue(rule, option)
        #TODO: figure out embedded groupnames in strings
        self.CheckUserConsistency(rule, option)

                           
    def CheckRegexValue(self, section):
        """
        Validate that the Regex directive contains a properly-formed Regular Expression
        """
        regex = self._plugin.get(section, 'regexp')
        try:
            re.compile(regex, flags=0)
            return True
        except re.error:
            sys.stdout.write("\tRegular Expression is not valid\n")
            sys.stdout.flush()
            self._valid = False
            return False 
        
    def CheckLabelValue(self, rule, option):
        '''
        Validate that a a regex group used as an directive value, exists in the regex directive
        '''
        group = self._plugin.get(rule, option)
        try:
            testreg = self._plugin.get(rule, 'regexp')
        except ConfigParser.NoOptionError:
            # user will have already been noted there is no such value
            return
        if group.startswith('{$'):  #groupname value
            if group.endswith('}') == False: print "\tmismatched brace in " + option
            group = group.replace('{$', '(?P<')
            group = group.replace('}', '>')  #convert it to regexp syntax
            if group not in testreg:
                print "\tOption '" + option + "' refers to non-existant regexp group '" + group + "'"
                self._valid = False            
    
    def CheckDuplicateSID(self, sid):
        '''
        check that plugin_sid values are not duplicated
        '''
        if sid.startswith("{$"):   #can't vald
            return
        if sid in self._sids:
            print "\tDuplicate plugin_sid value " + sid + " found"
            self._valid = False
        else:
            self._sids.append(sid)


    def CheckUserConsistency(self, rule, option):
        '''
        Collate the Regexp labels used in each UserData field to expose inconsistency to the user
        '''
        if option.lower() in self._userlabels:
            if self._plugin.get(rule, option) in self._userlabels[option]:
                pass   #We've seen this one before
            else:
                self._userlabels[option].append(self._plugin.get(rule, option))
        
        
    
    def PrintLabelUsage(self):
        print "\nThe Following Regex Labels are Assigned to UserData fields"
        udatafields = self._userlabels.keys()
        udatafields.sort()
        for udata in udatafields:
            udataresult = "\t" + udata + "\t" 
            for udataval in self._userlabels[udata]:
                udataresult += str(udataval) + ", "
            print udataresult
