#Makefile
#char code "LF(UNIX)" is required!!

OPTIONS = -O1
PROGS = main

all: $(PROGS)

main: main.o encapsulate.o session.o nat.o
	cc $(OPTIONS) -o map-e main.o encapsulate.o session.o nat.o -l rt
	rm *.o

main.o : main.c
	cc $(OPTIONS) -c main.c

encapsulate.o : encapsulate.c
	cc $(OPTIONS) -c encapsulate.c

session.o : session.c
	cc $(OPTIONS) -c session.c

nat.o : nat.c
	cc $(OPTIONS) -c nat.c
