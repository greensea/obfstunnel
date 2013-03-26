all : obfstunnel.c obfstunnel.h udpsession.c
	gcc obfstunnel.c udpsession.c -O2 -o obfstunnel

install : all
	cp obfstunnel /usr/bin/ -v

clean : 
	rm obfstunnel -fv
