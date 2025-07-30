main: main.c pastebeam.h
	gcc -ggdb -Wall -Wextra -Wswitch-enum -I/usr/local/ssl/include -L/usr/local/ssl/lib64 -o main main.c -lcrypto
