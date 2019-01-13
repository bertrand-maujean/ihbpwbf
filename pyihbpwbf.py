#!/usr/bin/python3.5
"""
    ihbpwbf.py python module
    Copyright (C) 2018 Bertrand MAUJEAN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3
    as published by the Free Software Foundation
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    A copy of the GNU General Public License version 3 is distributed
    in the file LICENSE.txt, and available at <https://www.gnu.org/licenses/>.
"""

# Check documentation in README.md file

import hashlib
import mmap
import os
import sys


# Global parameters and variables
ihbpwbf_filterFileName = u"pwned-passwords-bf.bin"
ihbpwbf_filterSize = (1024*1024*1024) # Size of the filter in bytes - 1GiBytes = 8 GiBits
ihbpwbf_filterBits = 33               # Number of bits for each sub-hash, = log2(bloomSize in bits)
ihbpwbf_filterBitsMask = 0x1ffffffff  # 33 lowest bits mask
ihbpwbf_hashNumber = 12               # number of sub-hash in bloom filter

# Other globals (not parameters, nothing tunable)
ihbpwbf_filter       = None # Will be the bloom filter itself as a bytearray/mmap
ihbpwbf_filterFileNo = None # Will be the file handle with the mmap'ed filter


###########################################################
# Custom exception definitions
class error(Exception):
    pass

class invalidHash(error):
    def __init__(self):
        self.message = "An hash was given in an incorrect format or length"
        return


###########################################################
# Loading the database

def setFilterFileName(filename):
    global ihbpwbf_filterFileName
    ihbpwbf_filterFileName = filename
    return

# Load the filter if not aloready loaded (idempotent, will be called many times)
def loadFilter():
    global ihbpwbf_filter
    global ihbpwbf_filterFileNo
    if ihbpwbf_filter != None:
        return
    
    ihbpwbf_filterFileNo = os.open(ihbpwbf_filterFileName, os.O_RDONLY)

    # using 'access' parameter instead of 'prot' for Win/Linux compatibility
    ihbpwbf_filter = mmap.mmap(ihbpwbf_filterFileNo, 0, access=mmap.ACCESS_READ)
    
    return

# unallocated ressources
def unloadFilter():
    global ihbpwbf_filter
    global ihbpwbf_filterFileNo
    if ihbpwbf_filter != None:
        ihbpwbf_filter.close()
        os.close(ihbpwbf_filterFileNo)
        ihbpwbf_filter       = None
        ihbpwbf_filterFileNo = None
    
    return

###########################################################
# test of a given item in the forme of a SHA1
def checkSHA1(item):
    global ihbpwbf_filter
    loadFilter()

    if len(item) != 20:
        raise invalidHash()
    
    sha512=hashlib.sha512()
    sha512.update(item)
    sha512bytes = sha512.digest()
    sha512int = int.from_bytes(sha512bytes,byteorder='little')

    inFilter = True
    for i in range(0, ihbpwbf_hashNumber):
        # compute the number of the bit to set
        n = sha512int & ihbpwbf_filterBitsMask
        sha512int >>= ihbpwbf_filterBits

        # check the bit
        no = n >>3 # byte number
        nb = n & 7 # bit number
        if (ihbpwbf_filter[no]) & (1<<nb) == 0:
            inFilter = False
            break
          
    return inFilter


###########################################################
# test of a given item in the forme of a password
def checkPassword(pwd):
    sha1=hashlib.sha1()
    sha1.update(pwd)
    return checkSHA1(sha1.digest())


###########################################################
# Main program
if __name__ == "__main__":
    print("This is to be included as a module.")
