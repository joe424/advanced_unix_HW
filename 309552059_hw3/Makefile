CC	    = gcc
CFLAGS	= -g -Wall -fno-stack-protector -nostdlib
ASM64	= yasm -f elf64 -DYASM -D__x86_64__ -DPIC

.PHONY: all clean

all: libmini.a libmini.so start.o 

libmini.a: libmini64.o libmini.o
	ar rc libmini.a libmini64.o libmini.o

libmini.so: libmini64.o libmini.o
	ld -shared -o libmini.so libmini64.o libmini.o

start.o: start.asm
	$(ASM64) start.asm -o start.o

libmini64.o:
	$(ASM64) libmini64.asm -o libmini64.o

libmini.o: libmini.c libmini.h
	$(CC) -c $(CFLAGS) -fPIC libmini.c

clean:
	rm libmini64.o libmini.o start.o libmini.a libmini.so

%:
	$(CC) -c $(CFLAGS) -I. -I.. -DUSEMINI $@.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ $@.o start.o -L. -L.. -lmini
	rm $@.o
