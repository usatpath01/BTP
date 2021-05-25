#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/times.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

SYSCALL_DEFINE3(identity, int, fd, char*, buf, size_t, count)
{
	struct tm result;
	struct file* get_file;
  	struct fd get_file_pointer;
	
	struct dentry *parent;
	int safe = 4,var_flag=0,log_flag=0;
	char var_cmp[] = "var";
	char log_cmp[] = "log";
    long long totalsecs = 0;
  	int pid = 0;
  	int sz_tempstr = 0;
  	char tempstr[100];
  	int size_tempbuff = 0;
    char *tempbuff;
    
    get_file_pointer = fdget(fd);
    get_file = get_file_pointer.file;
    parent = get_file->f_path.dentry->d_parent;
  	

    while(safe-- && parent!=NULL)
    {
    	if(strcmp(parent->d_name.name,var_cmp)==0)
    		var_flag = 1;

    	if(strcmp(parent->d_name.name,log_cmp)==0)
    		log_flag = 1;

    	if(strcmp(parent->d_name.name,"/")==0)
    		break;
    	parent = parent->d_parent;
    }

   	if(var_flag && log_flag)
   	{
   	
   		totalsecs = ktime_get_real_seconds();
		pid = task_tgid_vnr(current);
		  time64_to_tm(totalsecs,0,&result);
     
      sz_tempstr = snprintf(tempstr, sizeof(tempstr), "pid = %d, date = [%ld/%d/%d %d:%d:%d]"
      ,pid,result.tm_year+1900,result.tm_mon+1,result.tm_mday
      ,result.tm_hour,result.tm_min,result.tm_sec); 

      size_tempbuff = count + (sizeof(char)*(sz_tempstr+1));
      tempbuff = (char*)(kmalloc(size_tempbuff,GFP_KERNEL));

       if(!tempbuff)
    	printk(KERN_ALERT "Error in creating memory");

      strlcpy(tempbuff,tempstr,size_tempbuff);
      strlcat(tempbuff,buf,size_tempbuff);

      printk(KERN_ALERT "%s\n",tempstr);
      printk(KERN_ALERT "%s\n",tempbuff);
   	}

    return 0;
}


