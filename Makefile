CC = gcc
INCDIRS = -I.
OPT = -O0 
CFLAGS = -Wall -Wextra -Wpedantic -g $(INCDIRS) $(OPT)

VICTIM_FILE = victim-service/victim.c 
ATTACKER_FILE = attacker-spy-service/attacker-spy.c
CFILES = $(VICTIM_FILE) $(ATTACKER_FILE)

V_OBJS = victim-service/victim.o
A_OBJS = attacker-spy-service/attacker-spy.o
OBJECTS = $(V_OBJS) $(A_OBJS)

VICTIM_BIN = bin/victim-service
ATTACKER_BIN = bin/attacker-spy-service
BINARY = $(VICTIM_BIN) $(ATTACKER_BIN)

all: $(BINARY) # if i do make all the binary needs to be made first

# links victim-service/victim.o into bin/victim_service
$(VICTIM_BIN): $(V_OBJS)
	$(CC) -o $@ $^ 


# links attacker-spy-service/attacker-spy.o into bin/attacker_spy
$(ATTACKER_BIN): $(A_OBJS)
	$(CC) -o $@ $^ 
# takes @ = bin and ^ = test.o and does gcc -o bin test.o to generate binary from objects
# binary generated can then be executed using ./bin


# uses % (regex) to defone a generic rule to say how any .c file can be compiled to a .o file
%.o: %.c # @ is makefile variable for target (left side, i.e, %.o) and ^ is for dependencies (right side, i.e, %.c)
	$(CC) $(CFLAGS) -c -o $@ $^  
# @ = test.o and ^ = test.c
# $(CC) $(CFLAGS) -c -o $@ $^ = gcc -Wall -Wextra -Wpedantic -g -I. -O0 -c -o test.o test.c -> generates OBJECTS from CFILES


clean: # simple rule to delete all generated files
	rm -f $(OBJECTS) $(BINARY)
