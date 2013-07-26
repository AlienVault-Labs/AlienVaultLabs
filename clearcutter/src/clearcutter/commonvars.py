'''
Common Variables in System Logs, identified via Regex

Add extra variable pattern regex's here
'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"


import re

SECTIONS_NOT_RULES = ["config", "info", "translation"]

#BUG: [MAC] regexp doesn't catch addrs with trailing colon

aliases = {
    '[IPV4]' :"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    '[IPV6_MAP]' : "::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    '[MAC]' : "\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}",
    '[HOSTNAME]' : "((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)([a-zA-Z])+)",
    '[TIME]' : "\d\d:\d\d:\d\d",
    '[SYSLOG_DATE]' : "\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d",
    '[SYSLOG_DATE_SHORT]' : "\w+\s+\d{1,2}\s\d\d:\d\d:\d\d\s\d{4}",
    '[SYSLOG_WY_DATE]' : "\S+\s\w+\s+\d{1,2}\s\d\d:\d\d:\d\d\s\d{4}",
    '"[QUOTED STRING]"' : "\".*\"",
    '[NUMBER]' : "\s\d+{2:}\s"

    #TODO: URI
    #TODO: user@hostname
    #TODO Hexademical Number
    }

DefaultDirectives = [
        "regexp",
        "precheck",
        "event_type",
        "type",
        "date",
        "sensor",
        "interface",
        "plugin_id",
        "plugin_sid",
        "priority",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "username",
        "password",
        "filename",
        "userdata1",
        "userdata2",
        "userdata3",
        "userdata4",
        "userdata5",
        "userdata6",
        "userdata7",
        "userdata8",
        "userdata9",
        "occurrences",
        "log",
        "data",
        "snort_sid",
        "snort_cid",
        "fdate",
        "tzone",
        "ctx",
        "sensor_id",
        ]


def FindCommonRegex(teststring):
        """
        Test the string against a list of regexs for common data types, and return a placeholder for that datatype if found
        """
        #aliases['PORT']="\d{1,5}"

        
        returnstring = teststring
        replacements = aliases.keys()
        replacements.sort()
        for regmap in replacements:
                p = re.compile(aliases[regmap])
                returnstring = p.sub(regmap, returnstring)
        return returnstring
    
