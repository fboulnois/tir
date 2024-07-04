CFLAGS = -std=gnu11 -O3
LDFLAGS = -municode -s
WARNINGS = -Wall -Wextra -Wpedantic
CC = x86_64-w64-mingw32-gcc

tir.exe: main.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(WARNINGS)

clean:
	$(RM) tir.exe
