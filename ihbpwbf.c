/*  ihbpwbf.c library module
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
#include "ihbpwbf.h"
#include <errno.h>

char* ihbpwbf_FilterFilename = "pwned-passwords-bf.bin";
uint8_t* ihbpwbf_filter = NULL; /* mapped memory */
int ihbpwbf_filter_fh = 0; /* file handle */


/* ihbpwbf_setFilterFileName(char *filename)
   Set the path of the binary filter on disk
*/
void ihbpwbf_setFilterFileName(char *filename) {
	ihbpwbf_FilterFilename = strdup(filename);
}


/* ihbpwbf_loadFilter()
 Load the binary filter in a maped memory region
 return : 0 if success, -1 if failure
 Note : you do not need to call this function, as it will be tested at each call to ihbpwbf_checkSHA1()
*/
int ihbpwbf_loadFilter() {
	if (ihbpwbf_filter != NULL) {
		return 0;
	
	} else {
		ihbpwbf_filter_fh = open(ihbpwbf_FilterFilename, O_RDONLY);
		if (ihbpwbf_filter_fh == -1) return -1; // an errored occured
		ihbpwbf_filter = mmap(NULL, IHBPWBF_FILTER_SIZE, PROT_READ, MAP_PRIVATE, ihbpwbf_filter_fh, 0);
		if (ihbpwbf_filter == MAP_FAILED) {
			close(ihbpwbf_filter_fh);
			fprintf(stderr, "%s() mmap() error - ", __func__);
			perror(NULL);
			ihbpwbf_filter = NULL;
			return -1; // an errored occured
		}
	}
	return 0;
}

/* ihbpwbf_unloadFilter()
 Release memory ressources
 return : always 0
*/
int ihbpwbf_unloadFilter() {
	if (munmap(ihbpwbf_filter, IHBPWBF_FILTER_SIZE) != 0) {
		fprintf(stderr, "%s() munmap() error - ", __func__);
		perror(NULL);
	}
	if (close(ihbpwbf_filter_fh) == -1) {
		fprintf(stderr, "%s() close() error - ", __func__);
		perror(NULL);
	}
	ihbpwbf_filter = NULL;
	return 0;
}


/* Test a password's sha1 (as in original DB)
   Return: 0=password in not in DB, 1=password may be in DB, -1=an error occured
*/

int ihbpwbf_checkSHA1(char *item){
	uint64_t result[8]; // Note : SHA512 will be interpreted as a little endian 512 bit int 
	
	if (ihbpwbf_loadFilter() == -1) {
			return -1; // An error occured
	}
	
	if (ihbpwbf_filter == NULL) {
			return -1; // An error occured. Covered by preceding case, should never happen	
	}
	
	SHA512_CTX hacheur;
	if (SHA512_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__, __LINE__);
		return -1; // An error occured
	}
	SHA512_Update(&hacheur, item, 20);
	SHA512_Final((char*)result, &hacheur);
	
	uint64_t sub_hash;
	int no, nb;
	for (int i =0; i<IHBPWBF_HASH_NUMBER; i++) {
		sub_hash = result[0] & IHBPWBF_FILTER_MASK;
		nb = sub_hash & 7;
		no = sub_hash >>3;
		if ((ihbpwbf_filter[no] & (1<<nb)) ==0 ) return 0; // Not in filter

		/* Right shift result by IHBPWBF_FILTER_BITS */
		for (int j=0; j<8; j++) {
				result[j] >>= IHBPWBF_FILTER_BITS;
				if (j<7) result[j] |= (result[j+1] & IHBPWBF_FILTER_MASK) << (64-IHBPWBF_FILTER_BITS); 
		}
	}
	return 1; // probably in filter
}

/* ihbpwbf_checkPassword(char *pwd)
   Check for a password given as an asciiz string
   Return: 0=password in not in DB, 1=password may be in DB, -1=an error occured
*/
int ihbpwbf_checkPassword(char *pwd) {
	uint8_t result[20];
	
	SHA_CTX hacheur;
	if (SHA1_Init(&hacheur) == 0) {
		fprintf(stderr, "%s runtime error file %s line %d\n", __func__, __FILE__, __LINE__);
		return -1; // An error occured
	}
	SHA1_Update(&hacheur, pwd, strlen(pwd));
	SHA1_Final((char*)result, &hacheur);

	return ihbpwbf_checkSHA1(result);
}

