CC = gcc
RUSTC = rustc
CFLAGS = -Wall
RFLAGS = --crate-type=staticlib --emit=obj

TARGET = chall

all: $(TARGET)

$(TARGET): main.o scan.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o scan.o -lpthread -ldl

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

scan.o: scan.rs
	$(RUSTC) --crate-type=staticlib --emit=obj scan.rs -o scan.o

.PHONY: clean
clean:
	rm -f *.o $(TARGET)
