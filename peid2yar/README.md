# PEiD 2 Yar

Tiny script to convert PEiD signatures file to Yara rules file.

# Usage

$ ./peid2yar.py dbs/userdb.txt outputs/panda\_userdb.txt

$ yara -m outputs/panda\_userdb.txt /tmp/borland.exe

\_BobSoft\_Mini\_Delphi\_\_BoB\_\_BobSoft\_ [description="BobSoft Mini Delphi -> BoB / BobSoft"] /tmp/borland.exe
