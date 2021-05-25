#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define __NR_identity 440

long identity_syscall(int fd,char* buf,size_t sz)
{
    return syscall(__NR_identity,fd,buf,100);
}

int main(int argc, char *argv[])
{
    long activity;
    int fd;
    fd = open("/var/log/lol.txt", O_WRONLY|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
    printf("%d\n",fd);
    if(fd<0)
    {    
        perror("file not created");
        return 1;
    }
    char buf[] = "Hello_World";
    activity = identity_syscall(fd,buf,sizeof(buf));


    if(activity < 0)
    {
        perror("Implemented system call again");
    }

    else
    {
        printf("Yes Implemented now modify to use it\n");
    }

    int x;
    scanf("%d",&x);
    return 0;
}
