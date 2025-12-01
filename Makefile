CC = gcc
CFLAGS = -Wall -Wextra -O2

all: runme
	
runme: runme.o liballocator.so
	$(CC) $(CFLAGS) runme.o -L. -lallocator -Wl,-rpath,. -o runme 

runme.o: runme.c allocator.h
	$(CC) $(CFLAGS) -c runme.c -o runme.o

liballocator.so: allocator.c allocator.h
	$(CC) $(CFLAGS) -shared -fPIC allocator.c -o liballocator.so

test: runme
	./runme

clean:
	rm -f runme runme.o liballocator.so
	
