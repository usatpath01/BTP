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

SYSCALL_DEFINE1(identity, int, fd)
{
	struct tm result;
	struct file* get_file;
    struct fd get_file_pointer;
	
	struct dentry *parent;
	int safe = 8,var_flag=0,log_flag=0;
	char var_cmp[] = "var";
	char log_cmp[] = "log";
      
    get_file_pointer = fdget(fd);
    get_file = get_file_pointer.file;
    parent = get_file->f_path.dentry->d_parent;
  
    while(safe-- && parent!=NULL)
    {
    	printk(KERN_ALERT "File Path : %s\n",parent->d_name.name);
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
   		long long totalsecs = ktime_get_real_seconds();
		int pid = task_tgid_vnr(current);
		time64_to_tm(totalsecs,0,&result);
   		printk(KERN_ALERT "pid = %d, date = [%d/%d/%d %d:%d:%d]"
    	,pid,result.tm_year+1900,result.tm_mon+1,result.tm_mday
    	,result.tm_hour,result.tm_min,result.tm_sec);
   	}

    return 0;
}

