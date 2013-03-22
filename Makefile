all : obfstunnel.c
	gcc obfstunnel.c -O2 -o obfstunnel

install : all
	cp obfstunnel /usr/bin/ -v

clean : 
	rm obfstunnel -fv
