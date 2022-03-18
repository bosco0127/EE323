#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_SIZE 1000000//50000

typedef struct packet {
    unsigned short op;
    unsigned short shift;
    unsigned int length;
    char string[MAX_SIZE];
    //char *string;
} Packet;

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
    Packet *p_write = (Packet *) malloc(sizeof(Packet));
    Packet *p_read = (Packet *) malloc(sizeof(Packet));
    // packet length
    int write_len = 0;
    int read_len = 0;
    // option variable
    char opt;
    // loop variable
    char c; // store stdin string
    int string_length = 0; // initilized as 0.

    // 0-1 Separate options
    // check if all options are involved.
    if(argc != 9) {
        fprintf(stderr,"need to contain -h <host> -p <port> -o <option> -s <shift> options\n");
        free(p_write);
        free(p_read);
        exit(0);
    }
    // clean server_address
    memset(&server_address,0,sizeof(server_address));
    // set server_address
    server_address.sin_family = AF_INET; // IPv4
    while( (opt = getopt(argc,argv,"h:p:o:s:")) != -1 ) {
        switch(opt) {
            case 'h':
                server_address.sin_addr.s_addr=inet_addr(optarg); // IP address
                break;
            case 'p':
                server_address.sin_port=htons(atoi(optarg)); // Port no.
                break;
            case 'o':
                if ( atoi(optarg) == 0 || atoi(optarg) == 1 ) {
                    p_write->op = (short) atoi(optarg); // op type.
                    break;
                }
                else {
                    fprintf(stderr,"only 0 or 1 is allowed for -o options\n");
                    free(p_write);
                    free(p_read);
                    exit(0);
                break;
                }
            case 's':
                if ( atoi(optarg) >= 0 && atoi(optarg) <= 65535 ) {
                    p_write->shift = (short) atoi(optarg); // shift number.
                    break;
                }
                else {
                    fprintf(stderr,"only 0 ~ 65535 is allowed for -s options\n");
                    free(p_write);
                    free(p_read);
                    exit(0);
                break;
                }
            case '?':
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                free(p_write);
                free(p_read);
                exit(0);
                break;
            default:
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                free(p_write);
                free(p_read);
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
        // write length into Network Byte order.
        p_write->length=htonl((size_t) (string_length+8));

        // 3. write
        //write_len = send(client_socket, p_write, (size_t) (string_length+8), 0);
        write_len = send_all(client_socket, p_write, (string_length+8));
        if(write_len==-1) {
            fprintf(stderr,"send() error\n");
            close(client_socket);
            assert(0);
        }

        // 4. read & print
        read_len = recv(client_socket, p_read, (size_t) (string_length+8), MSG_WAITALL); // recieve all the length
        //read_len = recv_all(client_socket, p_read, (string_length+8));
        if(read_len==-1) {
            fprintf(stderr,"recv() error\n");
            close(client_socket);
            assert(0);
        }
        else if(read_len==0) {
            fprintf(stderr,"server disconnected\n");
            break;
        }
        // print result to stdout
        for(int i = 0; i < string_length; i++)
            fprintf(stdout,"%c", p_read->string[i]);

        // break if EOF
        if(c == EOF) {
            break;
        }

        // reset p_write->string, p_read->string, string_length
        memset(p_write->string,0,sizeof(p_write->string));
        memset(p_read->string,0,sizeof(p_read->string));
        string_length = 0;
    }
    
    // 5. close
    free(p_write);
    free(p_read);
    close(client_socket);
    return 0;
}
