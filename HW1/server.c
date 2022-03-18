#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_SIZE 10000000

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

// This function is cited in "Beej's Guide to Network Program" //
// Handles the zombie process.
void sigchild_handler (int s) {
    // waitpid() might overwrite errno, so we save and restore i
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)

    errno = saved_errno;
}

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
    int optval = 1; // for setsocketopt()
    char opt;
    // packet length
    int write_len;
    int read_len;
    int peak_len;
    // loop variable
    char c; // store stdin string
    int index = 0; // initilized as 0.
    unsigned short op;
    unsigned short shift;
    int length;
    // for signal handling
    struct sigaction sa;

    // 0-1 Separate options
    // check if all options are involved.
    if(argc != 3) {
        fprintf(stderr,"only need to contain -p <port> options\n");
        exit(0);
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
                exit(0);
                break;
            default:
                fprintf(stderr,"only -p is allowed for options\n");
                exit(0);
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
    // allow socket to bind this port
    if ( setsockopt(server_socket,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval)) == -1) {
        fprintf(stderr,"setsocketopt() error\n");
        close(server_socket);
        assert(0);
    }
    if(bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address)) == -1) {
        fprintf(stderr,"bind() error\n");
        close(server_socket);
        assert(0);
    }
    // 3. listen
    if(listen(server_socket, 10)==-1) {
        fprintf(stderr,"listen() error\n");
        close(server_socket);
        assert(0);
    }

    // signal handling
    // This part is cited in "Beej's Guide to Network Program" //
    sa.sa_handler = sigchild_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL)== -1) {
        perror("sigaction");
        exit(1);
    }

    while(1) {
        // 4. accept
        client_addr_size = sizeof(client_address);
        client_socket = accept(server_socket, (struct sockaddr*) &client_address, &client_addr_size); //4번
        if(client_socket == -1) {
            fprintf(stderr,"accept() error\n");
            close(server_socket);
            assert(0);
        }

        if(!fork()){ // child process
            close(server_socket); // child do not need this.
            
            // allocate memory to Packet
            Packet *p_write = (Packet *) malloc(sizeof(Packet));
            Packet *p_read = (Packet *) malloc(sizeof(Packet));

            // loop for data transmition.
            while(1){
                // 5. read & check protocol specification
                // read op
                read_len = recv(client_socket, &p_read->op, sizeof(p_read->op), MSG_WAITALL); // recieve all the length
                if(read_len==-1) {
                    fprintf(stderr,"recv() error @ op\n");
                    close(client_socket);
                    assert(0);
                }
                // 5-1. op
                op = p_read->op;
                if ( op == 0 || op == 1) {
                    p_write->op = op;
                }
                else break;
                // read shift
                read_len = recv(client_socket, &p_read->shift, sizeof(p_read->shift), MSG_WAITALL); // recieve all the length
                if(read_len==-1) {
                    fprintf(stderr,"recv() error @ shift\n");
                    close(client_socket);
                    assert(0);
                }
                // 5-2. shift
                shift = p_read->shift;
                if ( shift >= 0 && shift <= 65535 ) {
                    p_write->shift = shift;
                    shift = shift % ('z'-'a'+1);
                }
                else break;
                // read length
                read_len = recv(client_socket, &p_read->length, sizeof(p_read->length), MSG_WAITALL); // recieve all the length
                if(read_len==-1) {
                    fprintf(stderr,"recv() error @ shift\n");
                    close(client_socket);
                    assert(0);
                }
                // 5-3. length
                length = ntohl(p_read->length);
                if ( length >= 0 && length <= MAX_SIZE ) {
                    p_write->length = p_read->length;
                }
                else break;
                // break if string length is zero.
                if (length <= 8) break;
                // read string
                read_len = recv(client_socket, p_read->string, (size_t) (length-8), MSG_WAITALL); // recieve all the length
                if(read_len==-1) {
                    fprintf(stderr,"recv() error\n");
                    close(client_socket);
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

                // do Caesar cypher until index becomes length
                while(index < read_len) {
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
                write_len = send_all(client_socket, p_write, length);
                if(write_len==-1) {
                    fprintf(stderr,"send() error\n");
                    assert(0);
                }

                // break if EOF
                if(c == EOF) {
                    break;
                }

                // reset p_write->string, p_read->string, string_length
                memset(p_write,0,sizeof(p_write));
                memset(p_read,0,sizeof(p_read));
                index = 0;
            }

            // 7. close
            free(p_write);
            free(p_read);
            close(client_socket);
            exit(0); // close child process
        }
        close(client_socket); // parent should also close this.
    }
    
    return 0;
} 