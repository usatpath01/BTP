#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define __NR_identity 440

long identity_syscall(int fd)
{
    return syscall(__NR_identity,fd);
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

    activity = identity_syscall(fd);


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
