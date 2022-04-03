#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_SIZE 1000000//50000

typedef struct buffer {
    char string[MAX_SIZE];
} Buffer;

// Wrapper for send()
// Send repeatedly until send all the data
int send_all(int s, void *buf, int len) {
    int b_total = 0; // byte we've sent
    int b_left = len; // byte to sent
    int n;

    while (b_total < len) {
        n = send(s, buf+b_total, (size_t) b_left, 0);
        if (n == -1) {
            break;
        }
        b_total += n;
        b_left -= n;
    }

    return (n == -1) ? -1 : b_total;
}

// Wrapper for recv()
// Receive repeatedly until receive all the data
/*int recv_all(int s, void *buf, int len) {
    int b_total = 0; // byte we've sent
    int b_left = len; // byte to sent
    int n;

    while (b_total < len) {
        n = recv(s, buf+b_total, (size_t) b_left, 0);
        if (n == -1) {
            break;
        }
        else if (n == 0) {
            break;
        }
        b_total += n;
        b_left -= n;
    }

    return (n == -1) ? -1 : 
           (n == 0) ? 0 : b_total;
}*/

int main(int argc, char* argv[])
{
    // 0. Declare variables
    // client file/socket descriptor
    int client_socket;
    // server socket address
    struct sockaddr_in server_address;
    // Packet
    Buffer *p_write = (Buffer *) malloc(sizeof(Buffer));
    // packet length
    int write_len = 0;
    // option variable
    char opt;
    // loop variable
    char c; // store stdin string
    int string_length = 0; // initilized as 0.

    // 0-1 Separate options
    // check if all options are involved.
    if(argc != 5) {
        fprintf(stderr,"need to contain -h <host> -p <port> options\n");
        free(p_write);
        exit(0);
    }
    // clean server_address
    memset(&server_address,0,sizeof(server_address));
    // set server_address
    server_address.sin_family = AF_INET; // IPv4
    while( (opt = getopt(argc,argv,"h:p:")) != -1 ) {
        switch(opt) {
            case 'h':
                server_address.sin_addr.s_addr=inet_addr(optarg); // IP address
                break;
            case 'p':
                server_address.sin_port=htons(atoi(optarg)); // Port no.
                break;
            case '?':
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                free(p_write);
                exit(0);
                break;
            default:
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                free(p_write);
                exit(0);
                break;
        }
    }
    
    // 1. socket
    // creates socket with error handling.
    client_socket = socket(PF_INET,SOCK_STREAM,0);
    if(client_socket == -1) {
        fprintf(stderr,"socket() error\n");
        assert(0);
    }

    // 2. connect
    // connect with error handling.
    if(connect(client_socket,(struct sockaddr*) &server_address, sizeof(server_address))==-1) {
        fprintf(stderr,"connect() error\n");
        close(client_socket);
        assert(0);
    }

    // loop for data transmition.
    while(1){
        // get c until string length becomes MAX_SIZE
        while(string_length < MAX_SIZE) {
            c = fgetc(stdin);
            // break if EOF
            if(c == EOF) {
                break;
            }
            // put it into string buffer.
            p_write->string[string_length] = c;
            // increase string length
            string_length++;
        }

        // 3. write
        //write_len = send(client_socket, p_write, (size_t) (string_length+8), 0);
        write_len = send_all(client_socket, p_write, string_length);
        if(write_len==-1) {
            fprintf(stderr,"send() error\n");
            close(client_socket);
            assert(0);
        }

        // break if EOF
        if(c == EOF) {
            break;
        }
        /*
        // reset p_write->string, p_read->string, string_length
        memset(p_write->string,0,sizeof(p_write->string));
        string_length = 0;
        */
    }
    
    // 5. close
    free(p_write);
    close(client_socket);
    printf("proxy server sent %d characters\n",string_length);
    printf("proxy client succeed\n");
    printf("client closed\n");
    return 0;
}
