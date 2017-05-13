COPTS =
#COPTS = -Wall
CFLAGS = -O3 -Wall -c
LFLAGS = -static 
SERVER = 192.168.1.1
USERNAME = aa
PASSWORD = aa
PASSFILE = mypasswords.txt

all:
	@echo targets: build, test-server, test-client, clean, submit

build:
	make mradius

mradius: mradius.c mradius.h utils.o client.o server.o
	cc ${COPTS} -o $@ $< utils.o client.o server.o -lssl -lcrypto

mradius-client.o: client.c mradius.h
	cc ${COPTS} -c -o $@ $< -lssl -lcrypto

mradius-server.o: server.c mradius.h
	cc ${COPTS} -c -o $@ $< -lssl -lcrypto

utils.o: utils.c mradius.h
	cc ${COPTS} -c -o $@ $< -lssl -lcrypto 

test-client: mradius
	./mradius -v -h ${SERVER} ${USERNAME} ${PASSWORD}

test-server: mradius
	./mradius -v ${PASSFILE}

clean:
	-rm mradius utils.o client.o server.o *~

