#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct packet {
    unsigned short op;
    unsigned short shift;
    unsigned int length;
    char string[4];
} Packet;

int main(int argc, char* argv[])
{
    // 0. Declare variables
    // client file/socket descriptor
    int client_socket;
    // server socket address
    struct sockaddr_in server_address;
    // Packet
    Packet p_write;
    Packet p_read;
    char write_message[11]={0x00,0x00,0x01,0x00,
    0x00,0x00,0x00,0x0B,
    0x61,0x62,0x63};
    char read_message[15];
    // packet length
    int write_len;
    int read_len;

    if(argc != 3)
    {
        printf("%s <IP> <PORT>\n", argv[0]);
        exit(1);
    }

    // for test
    // initialize Packet
    p_write.op = 0;
    p_write.shift= 1;
    p_write.length=htonl(sizeof(p_write));
    strcpy(p_write.string, "abc");

    // 1. socket
    // creates socket with error handling.
    client_socket = socket(PF_INET,SOCK_STREAM,0);
    if(client_socket == -1) {
        fprintf(stderr,"socket() error\n");
        assert(0);
    }

    // 2. connect
    // clean server_address
    memset(&server_address,0,sizeof(server_address));
    // set server_address
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr=inet_addr(argv[1]); // IP address
    server_address.sin_port=htons(atoi(argv[2])); // Port no.
    // connect with error handling.
    if(connect(client_socket,(struct sockaddr*) &server_address, sizeof(server_address))==-1) {
        fprintf(stderr,"connect() error\n");
        assert(0);
    }

    // 3. write
    write_len = write(client_socket, &p_write, sizeof(p_write));
    if(write_len==-1) {
        fprintf(stderr,"send() error\n");
        assert(0);
    }

    // 4. read
    read_len = read(client_socket, &p_read, sizeof(p_read));
    if(read_len==-1) {
        fprintf(stderr,"recv() error\n");
        assert(0);
    }
    // print result to stdout
    printf("server : %s \n", p_read.string);
    
    // 5. close
    close(client_socket);
    return 0;
}