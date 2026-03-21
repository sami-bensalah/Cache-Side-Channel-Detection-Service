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
L1_ATTACKER_FILE = l1-attacker/attacker-spy.c
LLC_A_FILE  = LLC-attacker/attacker.c
RHOCP_A_FILE = RHOCP-attacker/cloud-attacker.c
NOISE_FILE = detector/server-noise.c
CFILES = $(VICTIM_FILE) $(L1_ATTACKER_FILE) $(LLC_A_FILE) $(RHOCP_A_FILE) $(NOISE_FILE)

V_OBJS = victim-service/victim.o
L1_A_OBJS = l1-attacker/attacker-spy.o
LLC_A_OBJS = LLC-attacker/attacker.o
RHOCP_A_OBJS = RHOCP-attacker/cloud-attacker.o
NOISE_OBJS = detector/server-noise.o
OBJECTS = $(V_OBJS) $(L1_A_OBJS) $(LLC_A_OBJS) $(RHOCP_A_OBJS) $(NOISE_OBJS)

VICTIM_BIN = bin/victim-service
L1-ATTACKER_BIN = bin/l1-attacker
LLC-ATTACKER_BIN = bin/llc-attacker
RHOCP_ATTACKS_BIN = bin/cloud-attacker
NOISE_BIN = bin/server-noise
BINARY = $(VICTIM_BIN) $(L1-ATTACKER_BIN) $(LLC-ATTACKER_BIN) $(RHOCP_ATTACKS_BIN) $(NOISE_BIN)

# executable binaries - make all, make victim, make attacker
all: $(BINARY) 
victim: $(VICTIM_BIN)
l1-attacker: $(L1-ATTACKER_BIN)
llc-attacker: $(LLC-ATTACKER_BIN)
cloud-attacker: $(RHOCP_ATTACKS_BIN)
server-noise: $(NOISE_BIN)
# links victim-service/victim.o into bin/victim_service
$(VICTIM_BIN): $(V_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# links attacker-spy-service/attacker-spy.o into bin/l1-attacker
$(L1-ATTACKER_BIN): $(L1_A_OBJS)
# takes @ = bin and ^ = test.o and does gcc -o bin test.o to generate binary from objects
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 

# links llc-attacker/attacker.o into bin/llc-attacker
$(LLC-ATTACKER_BIN): $(LLC_A_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


$(RHOCP_ATTACKS_BIN): $(RHOCP_A_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


$(NOISE_BIN): $(NOISE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# uses % (regex) to defone a generic rule to say how any .c file can be compiled to a .o file
%.o: %.c # @ is makefile variable for target (left side, i.e, %.o) and ^ is for dependencies (right side, i.e, %.c)
	$(CC) $(CFLAGS) -c -o $@ $^  
# @ = test.o and ^ = test.c
# $(CC) $(CFLAGS) -c -o $@ $^ = gcc -Wall -Wextra -Wpedantic -g -I. -O0 -c -o test.o test.c -> generates OBJECTS from CFILES


clean: # simple rule to delete all generated files
	rm -f $(OBJECTS) $(BINARY)
