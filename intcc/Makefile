CC = gcc
RUSTC = rustc
CFLAGS = -Wall
RFLAGS = --crate-type=staticlib

TARGET = chall

all: $(TARGET)

$(TARGET): main.o libscan.a
	$(CC) $(CFLAGS) -o $(TARGET) main.o libscan.a -lpthread -ldl

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

libscan.a: scan.rs
	$(RUSTC) --crate-type=staticlib scan.rs -o libscan.a

.PHONY: clean
clean:
	rm -f *.o libscan.a $(TARGET)
