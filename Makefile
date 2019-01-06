all: ihbpwbf-test ihbpwbf.so ihbpwbf.a

ihbpwbf-test: ihbpwbf-test.c ihbpwbf.o
	cc -g -c -o ihbpwbf-test.o ihbpwbf-test.c
	cc -g -o ihbpwbf-test ihbpwbf-test.o ihbpwbf.o -lcrypto
	
ihbpwbf.o: ihbpwbf.c ihbpwbf.h
	cc -g -c -o ihbpwbf.o ihbpwbf.c	
	
ihbpwbf.so: ihbpwbf.c ihbpwbf.h
	cc -shared -o ihbpwbf.so -fPIC ihbpwbf.c
	
ihbpwbf.a: ihbpwbf.o
	ar rcs ihbpwbf.a ihbpwbf.o
	
clean:
	rm *.o
	rm *.so
	rm *.a
	rm ihbpwbf-test
	
	
	