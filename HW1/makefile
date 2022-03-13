all: client.o server.o
	gcc client.o -o client
	gcc server.o -o server
client.o: client.c

server.o: server.c

clean:
	rm -r *.o client server
