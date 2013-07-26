"""
Clusters Locate clusters of test in Logfiles, to assist in processing discrete log messages,
from any given log data sample and assist in the creation of Regular Expression to parse those log entries
"""

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.2"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"


#TODO: More Regexp Patterns
#TODO: Levenshtein distance grouping (recurse window groupings

#TODO: Extract all unique words from a file
#cat comment_file.txt | tr " " "\n" | sort | uniq -c

#TODO: Print total matches for each identified log entry.


import sys, progressbar, commonvars, levenshtein, plugingenerate
from logfile import LogFile


class ClusterNode(object):
    """
    Linked list node for log patterns
    """

    Children = []
    Content = ""
    Parent = None
    ContentHash = ""
    
    
    def __init__(self, NodeContent="Not Provided"):
        self.Children = []
        self.Content = NodeContent
        #if verbose > 3 : print "Created new Node " + str(id(self)) + " with content : " + self.Content      
        self.ContentHash = hash(NodeContent)
    

    def GetChildren(self):
        return self.Children
    

    def GetContent(self):
        return self.Content


    def MatchChild(self, MatchContent):
        if len(self.Children) == 0:
            #print "No Children"
            return None
        else:
            for child in self.Children:
                if (child.ContentHash == hash(MatchContent)):
                    #print "Found Child Match : " + child.Content
                    return child
                else:
                    return None

              
    def MatchNephew(self, MatchContent):
        """Find Nephew Match"""
        if self.Parent == None: #This node is the root node
            return None
        for sibling in self.Parent.Children:
            if len(sibling.Children) > 0 :  # no point if sibling has no children
                for child in sibling.Children: #let's see which child node this matches  
                    if (child.Content == MatchContent):
                        return child
        return None
                    

    def AddChild(self, NodeContent):
        ChildContent = ClusterNode(NodeContent)
        ChildContent.Parent = self
        self.Children.append(ChildContent)
        return ChildContent
    
    def GeneratePath(self):
        #TODO: Compare siblings against regexps to suggest a regex replacement
        currentNode = self
        parentpath = ""
        while currentNode.Content != "ROOTNODE":
            if len(currentNode.Parent.Children) > ClusterGroup.VarThreshold:
                parentpath = "[VARIABLE]" + " " + parentpath
            else:
                parentpath = currentNode.Content + " " + parentpath
            currentNode = currentNode.Parent
        return parentpath

class ClusterGroup(object):
        """
        A Group of word cluster, representing the unique log types within a logfile
        """ 
        
        Args = ""
        Log = ""
        VarThreshold = 10  #How many siblings a string node must have before it is considered to be variable data
        VarDistance = 20
        rootNode = ClusterNode(NodeContent="ROOTNODE")
        entries = []
             
        def __init__(self, args):
                self.rootNode = ClusterNode(NodeContent="ROOTNODE")           
                self.Args = args

        def IsMatch(self, logline):  
                '''
                Test the incoming log line to see if it matches this clustergroup
                Return boolean match
                '''
                logwords = commonvars.FindCommonRegex(logline).split()
                
                #TODO Split at '=' marks as well
                
                currentNode = self.rootNode 
                for logword in logwords: #process logs a word at a time            
                        #match our own children first
                        match = currentNode.MatchChild(MatchContent=logword)

                        if match == None: #then try our siblings
                                match = currentNode.MatchNephew(MatchContent=logword)
                        if match == None:  #then add a new child
                                match = currentNode.AddChild(NodeContent=logword)

                        if match == None:
                                print "FAILED"    
                        else:
                                currentNode = match


        def IsEndNode(self, Node):
                '''
                Is This Node the final word of a log template?
                
                @return: True or False
                '''
                endnode = False
                hasNephews = False
                if (len(Node.Children) is 0):  #I'm an EndNode for a log wording cluster    
                        if Node.Parent is not None: #let's make sure our siblings are all endnodes too, and this is really var data                
                                for sibling in Node.Parent.Children:
                                        if len(sibling.Children) > 0 : 
                                                hasNephews = True 
                                if (hasNephews is False) and (len(Node.Parent.Children) >= ClusterGroup.VarThreshold):  #log event ends in a variable 
                                        endnode = True
                                if (hasNephews is False) and (len(Node.Parent.Children) == 1) : #log event ends in a fixed string
                                        endnode = True
                if endnode is True:
                        entry = Node.GeneratePath()
                        if entry not in self.entries: 
                                self.entries.append(entry)
                

        def BuildResultsTree(self, node):
                '''
                Recurse through the Node Tree, identifying and printing complete log patterns'
                
                @return: None (recursive function)
                '''
                if self.IsEndNode(node) == True : return None # no children so back up a level
                for childnode in node.Children:
                        self.BuildResultsTree(childnode)


        def Results(self):
                '''
                Display all identified unique log event types
                
                @return None
                '''
                #if options.outfile == true: dump to file 
                print "\n========== Potential Unique Log Events ==========\n"
                self.BuildResultsTree(self.rootNode)
                                    
                #Todo - commandline args to toggle levenshtein identification of dupes
                
                previous = ''          
                for entry in self.entries:
                    if levenshtein.levenshtein(entry, previous) < ClusterGroup.VarDistance : 
                        print "\t" + entry
                    else:
                        print entry
                    previous = entry
                
        def Run(self):
                try:
                    self.Log = LogFile(self.Args.logfile)
                except IOError:
                    print "File: " + self.Log.Filename + " cannot be opened : " + str(sys.exc_info()[1])
                    #TODO: log to stderr
                    raise IOError()
                #if args.v > 0 : print "Processing Log File "  + log.Filename + ":" + str(log.Length) + " bytes" 
                logline = self.Log.RetrieveCurrentLine() 
                widgets = ['Processing potential messages: ', progressbar.Percentage(), ' ', progressbar.Bar(marker=progressbar.RotatingMarker()), ' ', progressbar.ETA()]
                if self.Args.quiet is False : pbar = progressbar.ProgressBar(widgets=widgets, maxval=100).start()
                while logline != "": #TODO: Make this actually exit on EOF
                    self.IsMatch(logline)
                    if self.Args.quiet is False : pbar.update((1.0 * self.Log.Position / self.Log.Length) * 100)
                    logline = self.Log.RetrieveCurrentLine()
                    
                if self.Args.quiet is False : pbar.finish()
        
        def GenPlugin(self):
            '''
            Create a Template OSSIM agent plugin file using the identified log templates as SIDs
            
            @return: The filename of the generated plugin
            '''
            generator = plugingenerate.Generator(self.entries)
            generator.WritePlugin()
            return generator.PluginFile
            
#Take EndNode Strings
#Calculate Levenshtein distance between them
#Deduplicate from there.



