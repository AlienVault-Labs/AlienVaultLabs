import pydasm
import pefile
import sys
from binascii import *
from optparse import OptionParser
import os

def lookAtEP(pe):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep:ep+10]

    return data, ep_ava


def opPrint(data, ep_ava):
    print hexlify(data)
    offset = 0
    while offset < len(data):
      i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
      if i:
          print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
      else:
          print "Unknown Opcode"
          break
      offset += i.length

def main():
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input",
                  help="Input file or directory", metavar="FILE")


    (opts, args) = parser.parse_args()

    if not opts.__dict__['input']:
        parser.print_help()
        exit(-1)


    if not os.path.isdir(opts.__dict__['input']):
        try:
            pe =  pefile.PE(opts.__dict__['input'])
        except pefile.PEFormatError:
            print "Not a PE32 file"
            exit(-1)
        data, ep_ava = lookAtEP(pe)
        opPrint(data, ep_ava)
    else:
        files = os.listdir(opts.__dict__['input'])
        for f in files:
            if os.path.isdir("%s/%s" % (opts.__dict__['input'], f)):
                continue
            try:
                pe =  pefile.PE("%s/%s" % (opts.__dict__['input'], f))
            except pefile.PEFormatError:
                continue
            print "%s/%s" % (opts.__dict__['input'], f)
            data, ep_ava = lookAtEP(pe)
            opPrint(data, ep_ava)



if __name__ == "__main__":
    main()
