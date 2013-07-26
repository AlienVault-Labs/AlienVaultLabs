'''GTK User Interface code for ClearCutter'''

__author__ = "CP Constantine"
__email__ = "conrad@alienvault.com"
__copyright__ = 'Copyright:Alienvault 2012'
__credits__ = ["Conrad Constantine"]
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Prototype"
__maintainer__ = "CP Constantine"


import gtk, gtk.glade, pygtk

class ClearCutterUI:
    """ClearCutter GTK frontend"""

    gladefile = ""
    wTree = ""
    def __init__(self):
        
        self.wTree = gtk.glade.XML("ccui.glade") 
        
        #Get the Main Window, and connect the "destroy" event
        self.window = self.wTree.get_widget("MainWindow")
        if (self.window):
            self.window.connect("destroy", gtk.main_quit)


if __name__ == "__main__":
    hwg = ClearCutterUI()
    gtk.main()