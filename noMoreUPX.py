#!/usr/bin/env python3
import os
import sys

#
#       .        :uuuuuuu                                 
#       8F          M$   'WWWWWWWi                        
#      '$$$$$$"`    'E       #$$$$$                       
#      t$$$$$       'E       '$$$$$$L    '$"              
#      $`````       'E       'E#$$$$$k   'E               
#     J&amp;.           'E       'E `$$$$$N  'E               
#  '$$$$$$$$$$L     'E       'E   $$$$$$ 'E               
#  9$#"`"#$$$$$k   'E       `@"    #$$$$$$E               
#         '$$$$$   'E        $      `$$$$$&amp;               
#   ..     9$$$$L..JBu       $        R$$$$N              
# d$$$R    9$$$F   'E        $         "$$$$$r            
# $$$$    J$$$F     {E      .$.         '$$$$$
#  "$$$$$$$$$"   ..u$$u..  uz$$bu         #$$$          
#                                          '$$k.
#                     noMoreUPX! build date 01/09/2026
#                                sintax@exploit.im
UPX_STRINGS = [
    b"$Id: UPX ",
    b'UPX!',
    b'$Info: This file is packed with the UPX executable packer http://upx.sf.net $',
    b'$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $',
    b'UPX!u',
    b"http://upx.sf.net" # Added: UPX website reference
]

def fuzz_file(filename):
   
    with open(filename, 'rb') as f:
        data = f.read()
    
    new_data = data
    for upx_str in UPX_STRINGS:
        new_data = new_data.replace(upx_str, b'\x00' * len(upx_str))
    
    if new_data != data:
        with open(filename, 'wb') as f:
            f.write(new_data)
        print(f"stripped: {filename}")
        return True
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>")
        sys.exit(1)
    
    dir_path = sys.argv[1]
    for fname in os.listdir(dir_path):
        full_path = os.path.join(dir_path, fname)
        if os.path.isfile(full_path):
            fuzz_file(full_path)
