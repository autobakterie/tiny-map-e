#Makefile
#char code "LF(UNIX)" is required!!

MAKEFLAGS += --no-builtin-rules

CC ?= cc
CFLAGS ?= -O1
CFLAGS += -D_GNU_SOURCE
LDFLAGS ?=
LDFLAGS += -l rt

SRC = main.c encapsulate.c session.c nat.c
DEPS = $(patsubst %.c, %.h, $(SRC))
OBJ = $(patsubst %.c, %.o, $(SRC))

.PHONY: all
all: map-e

.PHONY: clean
clean:
	rm -f map-e *.o

map-e: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ): %.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) -o $@ $<
