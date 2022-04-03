all: proxy proxy_client
	gcc proxy_client.o -o proxy_client
	gcc proxy.o -o proxy
proxy_client.o: proxy_client.c

proxy.o: proxy.c

clean:
	rm -r *.o proxy_client proxy
