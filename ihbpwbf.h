/*  ihbpwbf.h Test program for ihbpwbf library
    Copyright (C) 2018-2019 Bertrand MAUJEAN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3
    as published by the Free Software Foundation
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    A copy of the GNU General Public License version 3 is distributed
    in the file LICENSE.txt, and available at <https://www.gnu.org/licenses/>.
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IHBPWBF_H

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define IHBPWBF_FILTER_SIZE (1024*1024*1024)

#define IHBPWBF_FILTER_BITS 33 /* Size of each sub hash */
#define IHBPWBF_FILTER_MASK 0x1ffffffff  /* 33 lowest bits mask */
#define IHBPWBF_HASH_NUMBER 12 /* number of sub-hashes */

void ihbpwbf_setFilterFileName(char *filename);
int ihbpwbf_loadFilter();
int ihbpwbf_unloadFilter();
int ihbpwbf_checkSHA1(char *item);
int ihbpwbf_checkPassword(char *pwd);

#endif /* IHBPWBF_H */

#ifdef __cplusplus
}
#endif
