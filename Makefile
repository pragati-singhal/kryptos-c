CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude -O2
TARGET = kryptos
SRCS = src/main.c src/crypto.c src/storage.c

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET) $(TARGET).exe kryptos_vault.dat kryptos_audit.txt