#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#define MAX_SIZE 10000000

typedef struct packet {
    unsigned short op;
    unsigned short shift;
    unsigned int length;
    char string[MAX_SIZE];
    //char *string;
} Packet;

int main(int argc, char* argv[])
{
    // 0. Declare variables
    // server and client file/socket descriptor
    int server_socket;
    int client_socket;
    // server and client socket address
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    socklen_t client_addr_size;
    // option variable
    char opt;
    // Packet
    Packet *p_write = (Packet *) malloc(sizeof(Packet));
    Packet *p_read = (Packet *) malloc(sizeof(Packet));
    // packet length
    int write_len;
    int read_len;
    // loop variable
    char c; // store stdin string
    int index = 0; // initilized as 0.
    unsigned short op;
    unsigned short shift;
    int length;

    // 0-1 Separate options
    // check if all options are involved.
    if(argc != 3) {
        fprintf(stderr,"need to contain -p <port> options\n");
        assert(0);
    }
    // clean server_address
    memset(&server_address,0,sizeof(server_address));
    // set server_address
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // set IP address to the current server.
    while( (opt = getopt(argc,argv,"p:")) != -1 ) {
        switch(opt) {
            case 'p':
                server_address.sin_port=htons(atoi(optarg)); // Port no.
                break;
            case '?':
                fprintf(stderr,"only -p is allowed for options\n");
                assert(0);
                break;
            default:
                fprintf(stderr,"only -p is allowed for options\n");
                assert(0);
                break;
        }
    }

    // 1. socket
    // creates socket with error handling.
    server_socket = socket(PF_INET,SOCK_STREAM,0);
    if(server_socket == -1) {
        fprintf(stderr,"socket() error\n");
        assert(0);
    }
    // 2. bind
    if(bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address)) == -1) {
        fprintf(stderr,"bind() error\n");
        assert(0);
    }
    // 3. listen
    if(listen(server_socket, 10)==-1) {
        fprintf(stderr,"listen() error\n");
        assert(0);
    }
    // 4. accept
    client_addr_size = sizeof(client_address);
    client_socket = accept(server_socket, (struct sockaddr*) &client_address, &client_addr_size); //4번
    if(client_socket == -1) {
        fprintf(stderr,"accept() error\n");
        assert(0);
    }

    // loop for data transmition.
    while(1){
        // 5. read & print
        // read twice because...
        read_len = recv(client_socket, p_read, (size_t) MAX_SIZE, MSG_PEEK); // PEEK for the size
        read_len = recv(client_socket, p_read, (size_t) read_len, MSG_WAITALL); // recieve all the length
        if(read_len==-1) {
            fprintf(stderr,"recv() error\n");
            assert(0);
        }
        else if(read_len==0) {
            fprintf(stderr,"server disconnected\n");
            break;
        }
        else if(read_len >= MAX_SIZE) {
            fprintf(stderr,"no more than 10MB\n");
            break;
        }
        // check specification
        // 5-1. op
        op = p_read->op;
        if ( op == 0 || op == 1) {
            p_write->op = op;
        }
        else break;
        // 5-2. shift
        shift = p_read->shift;
        if ( shift >= 0 && shift <= 65535 ) {
            p_write->shift = shift;
            shift = shift % ('z'-'a'+1);
        }
        else break;
        // 5-3. length
        length = ntohl(p_read->length);
        if ( length >= 0 && length <= MAX_SIZE ) {
            p_write->length = p_read->length;
        }
        else break;
        
        // do Caesar cypher until index becomes length
        while(index < length) {
            c = p_read->string[index];
            // break if EOF
            if(c == EOF) {
                break;
            }
            // in case of small letter.
            else if (c >= 'a' && c <= 'z') {
                // case of encode
                if (!op) {
                    c = c + shift;
                    if ( c > 'z') {
                        c = c - 'z' + 'a' - 1;
                    }
                }
                // case of decode
                else {
                    c = c - shift;
                    if ( c < 'a' ) {
                        c = c - 'a' + 'z' + 1;
                    }
                }
            }
            // in case of capital letter.
            else if (c >= 'A' && c <= 'Z') {
                // convert it to small letter first.
                c = c - 'A' + 'a';
                // case of encode
                if (!op) {
                    c = c + shift;
                    if ( c > 'z') {
                        c = c - 'z' + 'a' - 1;
                    }
                }
                // case of decode
                else {
                    c = c - shift;
                    if ( c < 'a' ) {
                        c = c - 'a' + 'z' + 1;
                    }
                }
            }

            // put it into string buffer.
            p_write->string[index] = c;
            // increase string length
            index++;
        }

        // 6. write
        write_len = send(client_socket, p_write, (size_t) length, 0);
        if(write_len==-1) {
            fprintf(stderr,"send() error\n");
            assert(0);
        }

        // break if EOF
        if(c == EOF) {
            break;
        }

        // reset p_write->string, p_read->string, string_length
        memset(p_write->string,0,sizeof(p_write->string));
        memset(p_read->string,0,sizeof(p_read->string));
        index = 0;
    }

    // 7. close
    free(p_write);
    free(p_read);
    close(server_socket);
    close(client_socket);
    return 0;
} 