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
		if (strstr(buf,"\r\n\r\n") != NULL) // change \n -> \r\n
		{
			isCRLF = 1;
		}
		b_length += n;
    }
	buf[b_length] = '\0';

    return (n == -1) ? -1 : 
		   (n == 0) ? 0 : b_length;
}

// Wrapper for recv()
// Receive form web.
int recv_web(int s, char *buf) {
    int b_length = 0; // buffer length
	int n = 0;

    while (b_length < MAX_SIZE) {
        n = recv(s, buf+b_length, (size_t) MAX_SIZE, 0);
        if (n == -1) {
            break;
        }
        else if (n == 0) {
			break;
		}
		b_length += n;
    }
	buf[b_length] = '\0';

    return (n == -1) ? -1 : b_length;
}

// This function is cited in "Beej's Guide to Network Program" //
// Handles the zombie process.
void sigchild_handler (int s) {
    // waitpid() might overwrite errno, so we save and restore i
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)

    errno = saved_errno;
}

// Extract Port Number from URL
// Return Port number unless URL is inValid.
// Invalid: return 0
int ExtractPortNum(char *buf) {
    int port = 0;
    // if buf+i is digit
    // => port = 10*port + *(buf+i)-'0'
    // else if '/' return port
    // else return 0
    for(int i=0; i<strlen(buf)+1 ; i++) {
        if(buf[i] >= '0' && buf[i] <= '9') {
            port = 10*port + (buf[i]-'0');
            /* debug */
            //printf("%d\n",port);
            /* debug */
            if(port > 65536) {
                port = 0;
                break;
            }
        }
        else if(buf[i] == '/') {
            //printf("reach valid\n");
            break;
        }
        else {
            port = 0;
            //printf("reach invalid\n");
            break;
        }
    }

    // return port number
    return port;
}

void ParseHeader(char * buf, char **CRLF){
    int CRLF_count = 0;
    char *token, *save_ptr;

    // devide buf by CRLF
    token = strtok(buf, "\r\n");
    CRLF[CRLF_count] = token;
    for (CRLF_count = 1 ; CRLF_count < 10; CRLF_count++ ) { // change \n -> \r\n
        token = strtok(NULL, "\r\n");
        if ( token == NULL) {
            break;
        }
        CRLF[CRLF_count] = token;
    }
    CRLF[CRLF_count] = NULL;
    return;
}

int ParseRequest(char **SL_token, char **CRLF){
    //int CRLF_count = 0;
    int SL_count = 0;
    char *token, *save_ptr;

    // devide buf by CRLF
    /*token = strtok(buf, "\r\n");
    CRLF[CRLF_count] = token;
    for (CRLF_count = 1 ; CRLF_count < 10; CRLF_count++ ) { // change \n -> \r\n
        token = strtok(NULL, "\r\n");
        if ( token == NULL) {
            break;
        }
        CRLF[CRLF_count] = token;
    }
    CRLF[CRLF_count] = NULL;*/

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

// Check Request Validation
// Valid: return port number(default 80 if not specified)
// Invaid: return 0
int RequestValid(char **SL_token, int SL_count) {
    char *http_form;
    char *host_ptr;
    char *path_ptr;
    int port;
    // The numbe of the token must be 5
    if(SL_count != 5) {
        return 0;
    }
    // HTTP methods must be GET
    if(strcmp(SL_token[0],"GET") != 0) {
        return 0;
    }
    // URL & Host header check.
    if((host_ptr = strstr(SL_token[1],SL_token[4])) == NULL) {
        return 0;
    }
    // HTTP version must be 1.0
    if(strcmp(SL_token[2],"HTTP/1.0") != 0) {
        return 0;
    }
    // Host header format validtation check.
    if(strcmp(SL_token[3],"Host:") != 0) {
        return 0;
    }
    /* debug */
    //printf("%s\n",SL_token[1]);
    //printf("%s\n",host_ptr);
    /* debug */
    // Check URL form starts with "http://"
    if ((host_ptr - SL_token[1]) != 7) {
        return 0;
    }
    if ( strncmp(SL_token[1],"http://",7) != 0) {
        return 0;
    }
    // check Host valid
    //path_ptr = strstr(host_ptr,"/");
    //if ( (path_ptr != NULL) && (strlen(SL_token[4]) != (host_ptr-path_ptr)) ){
    //    return 0;
    //}
    //http_form = strtok(SL_token[1], SL_token[4]);
    /* debug */
    //printf("/******************http form test*****************/\n");
    //printf("%s\n",http_form);
    //printf("%s\n",SL_token[1]);
    /* debug */
    /*if(http_form == NULL || strcmp(http_form,"http://") != 0) {
        return 0;
    }*/
    http_form = SL_token[1] + 7 + strlen(SL_token[4]);
    /* debug */
    //printf("/******************http form test*****************/\n");
    //printf("%s\n",http_form);
    /* debug */
    // Extract port if exist.
    if (http_form[0] == ':') {
        port = ExtractPortNum(&http_form[1]);
        return port;
    }
    // Else default port number
    else {
        // invalid if no path
        return 80;
    }
    /* debug */
    //printf("/******************RequestValid test*****************/\n");
    //printf("SHOULD NOT REACH HERE\n");
    /* debug */
    // should not reach here
    return 0;
}

/**This function is cited in "Beej's Guide to Network Program"**/
// Connect to the web server
// return server socket
int ConnectHost(char *host, int port){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char PORT[6];
    sprintf(PORT,"%d",port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 0;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("proxy: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("proxy: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "proxy: failed to connect\n");
        return -1;
    }

    return sockfd;
}

// Make Request Message
// return length of request message.
int MakeRequestMsg(char *request_buf, char **header) {
    int len_0 = strlen(header[0]);
    int len_1 = strlen(header[1]);
    int index = 0;

    for(index = 0; index < len_0; index++){
        request_buf[index] = header[0][index];
    }
    request_buf[index++] = '\r';
    request_buf[index++] = '\n';
    for(; index < len_0 + 2 + len_1; index++){
        request_buf[index] = header[1][index-len_0-2];
    }
    request_buf[index++] = '\r';
    request_buf[index++] = '\n';
    request_buf[index++] = '\r';
    request_buf[index++] = '\n';

    return index;
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
    // Bad Request Message
    char bad_request[30] = "HTTP/1.0 400 Bad Request\r\n\r\n";
    // black list
    char *black_list;
    int black_len=0;
    int isblack = 0;

    // 0-1 Get port number from the command line.
    // check if all options are involved.
    if(argc != 2) {
        fprintf(stderr,"type \"./proxy <port>\"\n");
        exit(0);
    }

    // Check if there's redirection: isatty(int fd) func, fd == 0 => stdin
    // return 0 if redirection.
    if(!isatty(0)) {
        isblack = 1;
        black_list = (char *) malloc(MAX_SIZE*sizeof(char));
        memset(black_list,0,MAX_SIZE*sizeof(char));
        while(black_len < MAX_SIZE) {
            c = fgetc(stdin);
            // break if EOF
            if(c == EOF) {
                break;
            }
            // put it into string buffer.
            black_list[black_len] = c;
            // increase string length
            black_len++;
        }
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
            char request_buf[100];
            int request_len = 0;
            char warning_buf[] = "GET http://warning.or.kr HTTP/1.0\r\nHost: warning.or.kr\r\n\r\n";
            char warning_len = strlen(warning_buf);
            // SL_token
            char *CRLF[10];
            char *header[2];
            char *SL_token[10];
            int SL_count = 0;
            // port number
            int port = 0;
            // web socket
            int web_socket;

			// receive the request message.
			read_len = recv_request(client_socket, read_buf->string);
            /* debug */
            //printf("/******************Receive test*****************/\n");
			//printf("%s\n",read_buf->string);
			//printf("read_len is %d\n",read_len);
            /* debug */

            // Parse the Request Message First
            ParseHeader(read_buf->string, CRLF);
            if ( CRLF[1] == NULL ) {
                // send 400 message
                send(client_socket, bad_request, (size_t) strlen(bad_request), 0);
                // 7. close
                close(client_socket);
                free(read_buf);
                free(write_buf);
                exit(0); // close child process
            }
            header[0] = (char *) malloc((strlen(CRLF[0])+1)*sizeof(char));
            header[1] = (char *) malloc((strlen(CRLF[1])+1)*sizeof(char));
            strcpy(header[0],CRLF[0]);
            strcpy(header[1],CRLF[1]);
            SL_count = ParseRequest(SL_token, CRLF);
            /* debug */
            //printf("/******************Parse test*****************/\n");
            //for(int i = 0; i < SL_count; i++){
            //    printf("SL_token[%d]: %s\n",i,SL_token[i]);
            //}
            //printf("SL_count: %d\n",SL_count);
            /* debug */

            // Request Validation Check
            if(!(port = RequestValid(SL_token, SL_count))){
                // send 400 message
                send(client_socket, bad_request, (size_t) strlen(bad_request), 0);
                // 7. close
                close(client_socket);
                free(read_buf);
                free(write_buf);
                free(header[0]);
                free(header[1]);
                exit(0); // close child process
            }
            /* debug */
            //printf("%s\n",SL_token[4]);
            //printf("%d\n",port);
            /* debug */

            // connect to the host with port.
            web_socket = ConnectHost(SL_token[4], port);
            if (web_socket == -1) {
                fprintf(stderr,"proxy: web connection failed!\n");
                assert(0);
            }
            // Invalid Host.
            if (web_socket == 0) {
                // send 400 message
                send(client_socket, bad_request, (size_t) strlen(bad_request), 0);
                // 7. close
                close(client_socket);
                free(read_buf);
                free(write_buf);
                free(header[0]);
                free(header[1]);
                if(isblack) {
                    free(black_list);
                }
                exit(0); // close child process
            }

            // Check if the host is in the black list.
            if(isblack && strstr(black_list,SL_token[4]) != NULL) {
                // set new web socket
                web_socket = ConnectHost("warning.or.kr", 80);
                strcpy(request_buf,warning_buf);
                request_len = warning_len;
                /* debug */
                //printf("blakclist!\n");
                //printf("%d\n",request_len);
                //printf("%s\n",request_buf);
                /* debug */
            }
            else {
                // Make Request Message
                request_len = MakeRequestMsg(request_buf, header);
                /* debug */
                //printf("%s\n",header[0]);
                //printf("%s\n",header[1]);
                //printf("The length should be: %ld\n", strlen(header[0])+2+strlen(header[1])+4);
                //printf("%d\n",request_len);
                //printf("%s\n",request_buf);
                /* debug */
            }

            // send request of client message to the web server.
            write_len = send_all(web_socket, request_buf, request_len);
            if(write_len==-1) {
                fprintf(stderr,"send() error\n");
                close(web_socket);
                assert(0);
            }

            // receive message from the web server.
            //read_len = recv(web_socket, write_buf->string, (size_t) MAX_SIZE, 0);
            read_len = recv_web(web_socket, write_buf->string);
            if(read_len==-1) {
                fprintf(stderr,"recv() error\n");
                close(web_socket);
                assert(0);
            }

            // close web socket
            close(web_socket);

            // send web messages to client host.
            write_len = send_all(client_socket, write_buf->string, read_len);
            if(write_len==-1) {
                fprintf(stderr,"send() error\n");
                close(client_socket);
                assert(0);
            }

            // 7. close
            close(client_socket);
            free(read_buf);
            free(write_buf);
            free(header[0]);
            free(header[1]);
            if(isblack) {
                free(black_list);
            }
            exit(0); // close child process
        }
        close(client_socket); // parent should also close this.
    }
    
    return 0;
} 