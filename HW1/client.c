#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>

int main(int argc, char* argv[])
{
    int my_sock;
    struct sockaddr_in serv_addr;
    int str_len;
    if(argc != 3)
    {
        printf("%s <IP> <PORT>\n", argv[0]);
        exit(1);
    }
    my_sock = socket(PF_INET,SOCK_STREAM,0); //1번
    if(my_sock == -1)
        printf("socket error \n");
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
    serv_addr.sin_port=htons(atoi(argv[2]));

    if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2번
        printf("connect error\n");
    char message[15];
    str_len = read(my_sock,message,sizeof(message)-1); //3번
    if(str_len==-1)
        printf("read error\n");
    printf("서버에서 : %s \n", message);
    close(my_sock); //4번
    return 0;
}