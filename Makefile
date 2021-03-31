CC = gcc
CFLAGS  = -g -Wall
FILENAME = ipk-sniffer

all: $(FILENAME)

$(FILENAME): $(FILENAME).o
	$(CC) $(CFLAGS) -o $(FILENAME) $(FILENAME).o

$(FILENAME).o:  ipk-sniffer.c ipk-sniffer.h
	$(CC) $(CFLAGS) -c ipk-sniffer.c

clean:
	$(RM) $(FILENAME)  *.o