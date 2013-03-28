CC=gcc
CFLAGS=-O2 -Wall

all : obfstunnel

obfstunnel : obfstunnel.c obfstunnel.h udpsession.c udpsession.h
	gcc obfstunnel.c udpsession.c -o obfstunnel $(CFLAGS)

install : obfstunnel
	cp obfstunnel /usr/bin/ -v

clean : 
	rm obfstunnel -fv
