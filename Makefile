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

VICTIM_FILE = victim-service/victim.c 
ATTACKER_FILE = attacker-spy-service/attacker-spy.c
LLC_A_FILE  = LLC-attacker/attacker.c
CFILES = $(VICTIM_FILE) $(ATTACKER_FILE) $(LLC_A_FILE)

V_OBJS = victim-service/victim.o
A_OBJS = attacker-spy-service/attacker-spy.o
LLC_A_OBJS = LLC-attacker/attacker.o
OBJECTS = $(V_OBJS) $(A_OBJS) $(LLC_A_OBJS) 

VICTIM_BIN = bin/victim-service
ATTACKER_BIN = bin/attacker-spy-service
LLC-ATTACKER_BIN = bin/attacker
BINARY = $(VICTIM_BIN) $(ATTACKER_BIN) $(LLC-ATTACKER_BIN)

# executable binaries - make all, make victim, make attacker
all: $(BINARY) 
victim: $(VICTIM_BIN)
attacker: $(ATTACKER_BIN)
llc-attacker: $(LLC-ATTACKER_BIN)
# links victim-service/victim.o into bin/victim_service
$(VICTIM_BIN): $(V_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# links attacker-spy-service/attacker-spy.o into bin/attacker_spy
$(ATTACKER_BIN): $(A_OBJS)
# takes @ = bin and ^ = test.o and does gcc -o bin test.o to generate binary from objects
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 

# links llc-attacker/attacker.o into bin/attacker
$(LLC-ATTACKER_BIN): $(LLC_A_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# uses % (regex) to defone a generic rule to say how any .c file can be compiled to a .o file
%.o: %.c # @ is makefile variable for target (left side, i.e, %.o) and ^ is for dependencies (right side, i.e, %.c)
	$(CC) $(CFLAGS) -c -o $@ $^  
# @ = test.o and ^ = test.c
# $(CC) $(CFLAGS) -c -o $@ $^ = gcc -Wall -Wextra -Wpedantic -g -I. -O0 -c -o test.o test.c -> generates OBJECTS from CFILES


clean: # simple rule to delete all generated files
	rm -f $(OBJECTS) $(BINARY)
