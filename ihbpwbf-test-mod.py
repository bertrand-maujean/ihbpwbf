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


import pyihbpwbf

#pyihbpwbf.setFilterFileName("pwned-passwords-bf.bin2") # temporary used to test file error and file specification
#pyihbpwbf.setFilterFileName(r"C:\Users\bmaujean\Desktop\pwned-passwords-bf.bin2")

while True:
    print("Enter a password to test (or nothing to exit program) : ", end="")
    givenPwd = input().encode('utf-8')
    if len(givenPwd) == 0:
        break
    
    if pyihbpwbf.checkPassword(givenPwd):
        print("Warning : probably compromised !")
    else:
        print("Good : This password is not in the filter")

    print("");

#pyihbpwbf.checkSHA1("jkhjkhk") # temporary used to test exeception throwing   
pyihbpwbf.unloadFilter()
    
    




