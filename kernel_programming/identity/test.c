#include <sys/syscall.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define __NR_identity 440

long identity_syscall(int fd,char* buf,size_t sz)
{
    return syscall(__NR_identity,fd,buf,sz-1);
}

int main(int argc, char *argv[])
{
    long activity;
    int fd;
    fd = open("/var/log/apache2/lol.txt", O_WRONLY|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
    printf("%d\n",fd);
    if(fd<0)
    {    
        perror("file not created");
        return 1;
    }
    char buf[] = "New_world";
    
    printf("%d",identity_syscall(fd,buf,sizeof(buf)));

    //Check for invalid buffer
    // printf("%d",identity_syscall(fd,(char*)0x1020224,sizeof(buf)));
    
    //Check for write syscall
    // write(fd,buf,sizeof(buf)-1);

    //Check with printf and fclose fopen
    // FILE* fp;
    // fp = fopen("/var/log/apache2/lol.txt","w");
    // if(fp!=NULL)
    // {
    //     fprintf(fp, "%s\n", buf);    
    // }
    // fclose(fp);
    // printf("%d\n",sizeof(buf));
    
    if(activity < 0)
    {
        perror("Error! Implemented system call again");
    }

    else
    {
        printf("Yes Implemented now modify to use it\n");
    }

    return 0;
}

