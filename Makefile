CC = g++
CFLAGS  = -g -Wall -std=c99 -pedantic
OBJFILES =  argcheck.o
TARGET_MAIN = ipk-sniffer

all: $(TARGET_MAIN)

$(TARGET_MAIN) : $(OBJFILES) $(TARGET_MAIN).o
	$(CC) $(CFLAGS) -o $(TARGET_MAIN) $(TARGET_MAIN).o $(OBJFILES) $(LDFLAGS)

clean:
	$(RM) $(TARGET_MAIN)  *.o *.tgz *.gz *.tar ; rm -rf Docs/
doc:
	doxygen Doxyfile

pack:
	tar -czvf xzbori20.tar --exclude='Materials' *.c *.h README manual.pdf Makefile 