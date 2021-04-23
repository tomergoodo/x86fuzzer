injector: injector.o
	gcc -m64 -g -no-pie injector.o -o injector

injector.o: injector.c
	gcc -m64 -c -g -no-pie injector.c -o injector.o

clean:
	rm injector *.o