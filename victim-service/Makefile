.PHONY: all victim clean

CC = gcc
INCDIRS = -I.
OPT = -O0
CFLAGS = -Wall -Wextra -Wpedantic -g $(INCDIRS) $(OPT) -march=native $(SPECTRE_FLAGS)
LIBS = -lcrypto

SPECTRE_FLAGS := \
	-mindirect-branch=keep \
	-mfunction-return=keep \
	-fno-stack-protector \
	-fno-stack-clash-protection \
	-no-pie \
	-fno-pie

VICTIM_FILE = victim.c 
CFILES = $(VICTIM_FILE)

V_OBJS = victim.o
OBJECTS = $(V_OBJS)

VICTIM_BIN = bin/victim-service
BINARY = $(VICTIM_BIN) 

# executable binaries - make all, make victim, make attacker
all: $(BINARY) 
victim: $(VICTIM_BIN)

# links victim-service/victim.o into bin/victim_service
$(VICTIM_BIN): $(V_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# uses % (regex) to defone a generic rule to say how any .c file can be compiled to a .o file
%.o: %.c # @ is makefile variable for target (left side, i.e, %.o) and ^ is for dependencies (right side, i.e, %.c)
	$(CC) $(CFLAGS) -c -o $@ $^  
# @ = test.o and ^ = test.c
# $(CC) $(CFLAGS) -c -o $@ $^ = gcc -Wall -Wextra -Wpedantic -g -I. -O0 -c -o test.o test.c -> generates OBJECTS from CFILES


clean: # simple rule to delete all generated files
	rm -f $(OBJECTS) $(BINARY)
