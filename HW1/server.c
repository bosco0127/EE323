#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>

int main(int argc, char* argv[])
{
    int serv_sock;
    int clint_sock;

    struct sockaddr_in serv_addr;
    struct sockaddr_in clint_addr;
    socklen_t clnt_addr_size;

    if(argc != 2)  
    {
        printf("%s <port>\n", argv[0]);
        exit(1);
    }
    serv_sock = socket(PF_INET, SOCK_STREAM,0); //1번
    if(serv_sock == -1)
        printf("socket error\n");
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if(bind(serv_sock,(struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) //2번
        printf("bind error\n");
    if(listen(serv_sock,5)==-1) //3번
        printf("listen error\n");
    
    clnt_addr_size = sizeof(clint_addr);
    clint_sock = accept(serv_sock,(struct sockaddr*)&clint_addr,&clnt_addr_size); //4번
    if(clint_sock == -1)
        printf("accept error\n");

    char message[] = "hello client";
    write(clint_sock, message, sizeof(message)); //5번
    close(serv_sock); //6번
    close(clint_sock);
    return 0;
}