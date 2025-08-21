@echo off

cl /Zi /Fe:main.exe main.c /link bcrypt.lib Ws2_32.lib crypt32.lib
