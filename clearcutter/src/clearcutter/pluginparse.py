'''OSSIM Plugin Test-Run parsing code
Simulates loading a plugin into OSSIM and parsing sample log data.

For testing plugins before loading into OSSIM, and simulating the log parsing process and results

'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine", "Dominique Karg"]
__version__ = "0.2"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"


#TODO: duplicate entire plugin parsing to validate good plugin file and field assignment
#TODO: Identify plugin section that contains bad regexp

#TODO: Implement precheck

import sys, re, ConfigParser, pluginvalidate, commonvars

class ParsePlugin(object):
    """Processes Log Data against a list of regular expressions, possibly read from an OSSIM collector plugin"""
    
    #Commandline Options
    Args = ''
    
    #File containing regexps
    Plugin = ''
    
    #extracted regexps from file
    #regexps = {}

    SIDs = {}
    
    Log = ''
    
    sorted_ = {}
    rule_stats = []
    rule_precheck_stats = []
    
    line_match = 0

    #Common Log patterns, as used in OSSIM
    aliases = {
               'IPV4' :"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
               'IPV6_MAP' : "::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
               'MAC': "\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}",
               'PORT': "\d{1,5}",
               'HOSTNAME' : "((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)([a-zA-Z])+)",
               'TIME' : "\d\d:\d\d:\d\d",
               'SYSLOG_DATE' : "\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d",
               'SYSLOG_WY_DATE' : "\w+\s+\d{1,2}\s\d{4}\s\d\d:\d\d:\d\d",
              }

    def __init__(self, args):
        self.Args = args
        self.LoadPlugin()
        
    def hitems(self, config, section):
        itemhash = {}
        for item in config.items(section):
            itemhash[item[0]] = self._strip_value(item[1])
        return itemhash
    
    def _strip_value(self, value):
        from string import strip
        return strip(strip(value, '"'), "'")
    
    def get_entry(self, config, section, option):
        value = config.get(section, option)
        value = self._strip_value(value)
        return value

   
    def LoadPlugin(self):
        try:
            self.Plugin = ConfigParser.RawConfigParser()
            self.Plugin.read(self.Args.plugin)
        except ConfigParser.MissingSectionHeaderError:
            print self.Args.plugin + " Is not an OSSIM plugin file"
            sys.exit()
        
        for rule in self.Plugin.sections():
            if rule.lower() not in commonvars.SECTIONS_NOT_RULES :
                self.SIDs[rule] = self.Plugin.get(rule, 'regexp')
        
        validator = pluginvalidate.PluginValidator(self.Plugin)
        if validator.IsValid() == False: sys.exit()

    
    def ParseLogWithPlugin(self):
        '''Process a logfile according to SID entries in an OSSIM collector plugin'''
        keys = self.SIDs.keys()
        keys.sort()
        for line in self.Log:
            matched = False
            for rulename in keys:
                #match the line with precheck first
                if self.Args.precheck is True:
                    try:
                        precheck = self.get_entry(self.Plugin, rulename, 'precheck')
                        if precheck in line:
                            self.rule_precheck_stats.append(str(rulename))
                    except ConfigParser.NoOptionError:
                        pass
                
                
                regexp = self.get_entry(self.Plugin, rulename, 'regexp')
                if regexp is "":
                    continue
                # Replace vars
                for alias in self.aliases:
                    tmp_al = ""
                    tmp_al = "\\" + alias;
                    regexp = regexp.replace(tmp_al, ParsePlugin.aliases[alias])
                result = re.findall(regexp, line)
                try:
                    tmp = result[0]
                except IndexError:
                    continue
                # Matched
                matched = True

                if self.Args.quiet is False:
                    print "Matched using %s" % rulename
                if self.Args.verbose > 0:
                    print line
                if self.Args.verbose > 2:
                    print regexp
                    print line
                #TODO: Implement label Extraction
                #try:
                #    if self.Args.group != '':  #Change this to print positional
                #        print "Match $%d: %s" % (int(sys.argv[3]),tmp[int(sys.argv[3])-1])
                #    else:
                #        if self.Args.quiet == False:
                #            print result
                #except ValueError:
                #    if self.Args.quiet is False:
                #        print result
                # Do not match more rules for this line
                self.rule_stats.append(str(rulename))
                self.matched += 1
                break
            if matched is False and self.Args.nomatch is True:
                print 'NOT MATCHED: ' + line

    
               

    def Run(self):
        f = open(self.Args.logfile, 'r')   #REPLACE WITH ARGS 
        self.Log = f.readlines()
        self.line_match = 0    
        self.matched = 0
        self.ParseLogWithPlugin()


    def PrintResults(self):
        for key in self.SIDs:
            print "Rule: \t%s\n\t\t\t\t\t\tMatched %d times by Regexp" % (str(key), self.rule_stats.count(str(key)))
            if self.Args.precheck is True:
                print "\t\t\t\t\t\tMatched %d times by Precheck" % (self.rule_precheck_stats.count(str(key)))
   
        print "Counted", len(self.Log), "lines."
        print "Matched", self.matched, "lines."
     
    
                