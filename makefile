all: myELF


myELF: myELF.o
	gcc -g -Wall -o myELF myELF.o
 
myELF.o: myELF.c elf.h
	gcc -g -m64 -Wall -c -o myELF.o myELF.c
	
	
.PHONY: clean

clean:
	rm -f *.o myELF
	

