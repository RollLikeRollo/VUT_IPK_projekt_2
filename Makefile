CC = g++
CFLAGS = -Wall -std=c++11 -pedantic -g
OBJFILES =  
TARGET_MAIN = ipk-sniffer
LDFLAGS = -g -lpcap

all: $(TARGET_MAIN)

$(TARGET_MAIN) : $(OBJFILES) $(TARGET_MAIN).o
	$(CC) $(CFLAGS) -o $(TARGET_MAIN) $(TARGET_MAIN).o $(OBJFILES) $(LDFLAGS)

clean:
	$(RM) $(TARGET_MAIN)  *.o *.tgz *.gz *.tar ; rm -rf Docs/
doc:
	doxygen Doxyfile

pack:
	tar -czvf xzbori20.tar --exclude='Materials' *.c *.h README manual.pdf Makefile 