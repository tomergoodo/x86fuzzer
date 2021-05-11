LIBNAME = capstone


injector: injector.o
	gcc -m64 -Wall -g -no-pie injector.o -l $(LIBNAME) -o injector

injector.o: injector.c
	gcc -m64 -Wall -c -g -no-pie injector.c -o injector.o

clean:
	rm injector *.o