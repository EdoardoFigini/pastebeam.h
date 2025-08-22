@echo off

cl /Zi /W4 /Fe:main.exe main.c /D_CRT_SECURE_NO_WARNINGS /link bcrypt.lib Ws2_32.lib crypt32.lib
