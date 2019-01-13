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

import os.path
import sys
import hashlib
import random




# Global parameters and variables
sourceFilename = u"pwned-passwords-ordered-by-hash.txt"
destBinFileName = u"pwned-passwords-ordered-by-hash.bin"
ihbpwbf_filterFileName = u"pwned-passwords-bf.bin"
ihbpwbf_filterSize = (1024*1024*1024) # Size of the filter in bytes - 1GiBytes = 8 GiBits
ihbpwbf_filterBits = 33 # Number of bits for each sub-hash, = log2(bloomSize in bits)
ihbpwbf_filterBitsMask = 0x1ffffffff # 33 lowest bits
ihbpwbf_hashNumber = 12 # number of sub-hash in bloom filter
testSamplingRate = 0.001
nTestOutside = 1000000 # Number of false positive (not in filter) test to check

# Other globals (not parameters, nothing to tune)
ihbpwbf_filter     = None # Will be the bloom filter itself as a bytearray


###########################################################
# Insert an item(=sha1 from IHBP's list) in filter
def processHash(item):
    global processedHashNumber
    global ihbpwbf_filter

    sha512=hashlib.sha512()
    sha512.update(item)
    sha512bytes = sha512.digest()
    sha512int = int.from_bytes(sha512bytes,byteorder='little')

    if len(sha512bytes) != 64:
        print("processHash(): runtime error sha512 len not 64B")
        sys.exit()       

    for i in range(0, ihbpwbf_hashNumber):
        # compute the number of the bit to set
        n = sha512int & ihbpwbf_filterBitsMask
        sha512int >>= ihbpwbf_filterBits

        # set the bit
        no = n >>3 # byte number
        nb = n & 7 # bit number
        ihbpwbf_filter[no] |= (1<<nb)          
    
    return


###########################################################
# test of a given item
def checkItem(item):
    global ihbpwbf_filter

    if len(item) != 20:
        print("Error : wrong hash length"+str(len(sha1)))
        return False
    
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


# Generate a random fake sha1 (used for negative testing)
def fakeSha1():
    r = bytearray(20)
    for i in range (0, 20):
        r[i] = random.randint(0,255)

    return r


###########################################################
# Main program

# Check if file exists or not
abortCond = False
if os.path.isfile(sourceFilename) == False:
    print("File does not exist : "+sourceFilename)
    abortCond = True

if os.path.isfile(destBinFileName):
    print("File does exist : "+destBinFileName)
    print("It can not be overwritten, you should rename or delete it before")
    abortCond = True

if os.path.isfile(ihbpwbf_filterFileName):
    print("File does exist : "+ihbpwbf_filterFileName)
    print("It can not be overwritten, you should rename or delete it before")
    abortCond = True

if abortCond:
    print("Aborting")
    sys.exit(0)

    
# Create the empty filter
ihbpwbf_filter = bytearray(ihbpwbf_filterSize)

# Test set
testSet = []
 
# Open the input file and binary hashes output (filter will be saved at the end)
sourceFile  = open(sourceFilename, "rt")
destBinFile = open(destBinFileName, "wb")


###########################################################
# Main processing loop
fin=False
lineNumber=0
processedHashCount = 0    # For progression status
while not fin:
    l=sourceFile.readline()
    lineNumber+=1
    if l=="":
        fin=1
    else:    
        shabin = bytes.fromhex(l[:40])
        if len(shabin) != 20:
            print("Syntax error line="+str(lineNumber)+"  hexfoundlen="+str(len(shabin))+" raw="+l)
            continue

        else:
            processedHashCount+=1
            if (processedHashCount%100000)==0:
                print("Process hash count="+str(processedHashCount)+"\r", end="")
            destBinFile.write(shabin) # Write to raw bin file
            processHash(shabin)       # insert in filter
            if random.random() < testSamplingRate:
                testSet.append(shabin)# and sometimes, keep for the test set

    #if processedHashCount > 500000:
    #    fin=True
                   
sourceFile.close()
destBinFile.close()
print("\n")


###########################################################
# Testing "in filter" items
print("Testing 'in filter' item. Number of items in test set="+str(len(testSet)))
errorDetected = False
for item in testSet:
        if not checkItem(item):
            print("Error on 'in filter' item !! Filter may be inconsistent")
            errorDetected = True
            
if not errorDetected:
    print("Every item is in filter. The filter seems consistent")

print("")

###########################################################
# Testing "not in filter" items
print("Testing 'not in filter' item. Number of items in test run="+str(nTestOutside))
fp=0
print("(Each dot is one false positive item)")
for i in range (0, nTestOutside):
    h = fakeSha1()
    if checkItem(h):
        print(".", end="")
        fp+=1

print("\nFalse positive ratio "+str(fp/nTestOutside)+"\n")


# Save the filter
f = open(ihbpwbf_filterFileName, "wb")
f.write(ihbpwbf_filter)
f.close()
print("\nDone, exiting. Thank you !\n")

