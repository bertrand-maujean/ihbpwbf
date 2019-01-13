/*  ihbpwbf-test.c Test program for ihbpwbf library
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

/*
void test_pwd(char *password) {
	printf("%s - ", password);
	int r = ihbpwbf_checkPassword(password);
	switch (r) {
		case 0 :  printf("Not in filter\n"); break;
		case 1 :  printf("Probably in filter\n"); break;
		case -1 : printf("An error occured\n"); break;
		default : printf("Error : unexpected return value from ihbpwbf_checkPassword()\n");
	}
}
*/

/* Simple cat-like application. Just pipe an existing password list on stdin, 
   and it will pass every password that is probably in the filter
*/
void main(void) {
	char buf[256];
	
	while (!feof(stdin)) {
		fgets(buf, 255, stdin);
		for (int n=0; n<256; n++) if ((buf[n] == 10) || (buf[n] == 13)) buf[n] = 0;
		if (ihbpwbf_checkPassword(buf) == 1) {
			printf("%s\n", buf);
		} else {
			//printf("%s is not in filter\n", buf);
		}
	}
}