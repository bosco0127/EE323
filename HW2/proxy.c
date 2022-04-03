/*
    Reference: Beej's Guide to Network Programming
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <assert.h>

#define MAX_SIZE 100000

typedef struct buffer {
    char string[MAX_SIZE];
} Buffer;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

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
// Receive until get CRLF.
int recv_request(int s, char *buf) {
    int b_length = 0; // buffer length
	int n = 0;
    int isCRLF = 0;

    while (!isCRLF) {
        n = recv(s, buf+b_length, (size_t) MAX_SIZE, 0);
        if (n == -1) {
            break;
        }
        else if (n == 0) {
			break;
		}
		if (strstr(buf,"\n\n") != NULL) // change \n -> \r\n
		{
			isCRLF = 1;
		}
		b_length += n;
    }
	buf[b_length] = '\0';

    return (n == -1) ? -1 : 
		   (n == 0) ? 0 : b_length;
}

// This function is cited in "Beej's Guide to Network Program" //
// Handles the zombie process.
void sigchild_handler (int s) {
    // waitpid() might overwrite errno, so we save and restore i
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)

    errno = saved_errno;
}

int RequestValid(char * buf, char **SL_token){
    char *CRLF[10];
    int CRLF_count = 0;
    int SL_count = 0;
    char *token, *save_ptr;

    // devide buf by CRLF
    token = strtok(buf, "\n");
    CRLF[CRLF_count] = token;
    for (CRLF_count = 1 ; CRLF_count < 10; CRLF_count++ ) { // change \n -> \r\n
        token = strtok(NULL, "\n");
        if ( token == NULL) {
            break;
        }
        CRLF[CRLF_count] = token;
    }
    CRLF[CRLF_count] = NULL;

    // devide CRLF by space character
    token = strtok(CRLF[0]," ");
    SL_token[SL_count] = token;
    for (SL_count = 1; SL_count < 10; SL_count++ ) {
        token = strtok(NULL, " ");
        if ( token == NULL) {
            break;
        }
        SL_token[SL_count] = token;
    }
    token = strtok(CRLF[1]," ");
    SL_token[SL_count] = token;
    for (SL_count++ ; SL_count < 10; SL_count++ ) {
        token = strtok(NULL, " ");
        if ( token == NULL) {
            break;
        }
        SL_token[SL_count] = token;
    }
    SL_token[SL_count] == NULL;

    return SL_count;
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
    // packet length
    int write_len;
    int read_len;
    // loop variable
    char c; // store stdin string
    int index = 0; // initilized as 0.
    unsigned short op;
    unsigned short shift;
    int length;
    // for signal handling
    struct sigaction sa;

    // 0-1 Get port number from the command line.
    // check if all options are involved.
    if(argc != 2) {
        fprintf(stderr,"type \"./proxy <port>\"\n");
        exit(0);
    }

    // clean server_address
    memset(&server_address,0,sizeof(server_address));
    // set server_address
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // set IP address to the current server.
	if( atoi(argv[1]) >= 0 && atoi(argv[1]) <= 65535) {
		server_address.sin_port=htons(atoi(argv[1])); // set port number.
	}
	else {
		fprintf(stderr,"port number should be from 0 to 65535\n");
        exit(0);
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

			// Allocate memory to the buffer.
			Buffer *read_buf = (Buffer *) malloc(sizeof(Buffer));
			Buffer *write_buf = (Buffer *) malloc(sizeof(Buffer));
            // SL_token
            char *SL_token[10];
            int SL_count = 0;

			// receive the request message.
			read_len = recv_request(client_socket, read_buf->string);
            /* debug */
			printf("%s\n",read_buf->string);
			printf("read_len is %d\n",read_len);
            /* debug */

			// Request Validation Check
            SL_count = RequestValid(read_buf->string, SL_token);
            /* debug */
            for(int i = 0; i < SL_count; i++){
                printf("SL_token[%d]: %s\n",i,SL_token[i]);
            }
            /* debug */

            // 7. close
            close(client_socket);
            exit(0); // close child process
        }
        close(client_socket); // parent should also close this.
    }
    
    return 0;
} 