#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_SIZE 2500

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
    // client file/socket descriptor
    int client_socket;
    // server socket address
    struct sockaddr_in server_address;
    // Packet
    Packet *p_write = (Packet *) malloc(sizeof(Packet));
    Packet *p_read = (Packet *) malloc(sizeof(Packet));
    /* char write_message[11]={0x00,0x00,0x01,0x00,
    0x00,0x00,0x00,0x0B,
    0x61,0x62,0x63};
    char read_message[15]; */
    // packet length
    int write_len;
    int read_len;
    // option variable
    char opt;
    // loop variable
    char c; // store stdin string
    int string_length = 0; // initilized as 0.

    // 0-1 Separate options
    // check if all options are involved.
    if(argc != 9) {
        fprintf(stderr,"need to contain -h <host> -p <port> -o <option> -s <shift> options\n");
        assert(0);
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
                p_write->op = (short) atoi(optarg); // op type.
                break;
            case 's':
                p_write->shift = (short) atoi(optarg); // shift number.
                break;
            case '?':
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                assert(0);
                break;
            default:
                fprintf(stderr,"only -h -p -o -s is allowed for options\n");
                assert(0);
                break;
        }

    }

    // for test
    // initialize Packet
    // strcpy(p_write.string, "abc");
    //p_write->string = (char *) malloc(MAX_SIZE*sizeof(char));
    //p_read->string = (char *) malloc(MAX_SIZE*sizeof(char));
    while(string_length < MAX_SIZE) {
        c = getchar();
        if(c == EOF) {
            break;
        }
        p_write->string[string_length] = c;
        string_length++;
    }
    p_write->length=htonl((size_t) (string_length+8));
    
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
        write_len = write(client_socket, p_write, (size_t) (string_length+8));
        if(write_len==-1) {
            fprintf(stderr,"send() error\n");
            assert(0);
        }

        // 4. read
        read_len = read(client_socket, p_read, (size_t) (string_length+8));
        if(read_len==-1) {
            fprintf(stderr,"recv() error\n");
            assert(0);
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