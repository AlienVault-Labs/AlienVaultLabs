# PEiD 2 Yar

Tiny script to convert PEiD signatures file to Yara rules file.

# Usage

$ ./peid2yar.py dbs/userdb.txt outputs/panda_userdb.txt

$ yara -m outputs/panda_userdb.txt /tmp/borland.exe 
_BobSoft_Mini_Delphi__BoB__BobSoft_ [description="BobSoft Mini Delphi -> BoB / BobSoft"] /tmp/borland.exe

