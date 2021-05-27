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
//
#include <linux/uaccess.h>
#include <asm/unistd.h>
//

static inline loff_t *file_ppos(struct file *file)
{
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

ssize_t my_ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = kernel_write(f.file, buf, count,ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}

SYSCALL_DEFINE3(identity, int, fd, char*, buf, size_t, count)
{
	struct tm result;
	struct file* get_file = NULL;
  	struct fd get_file_pointer;
	
	struct dentry *parent = NULL;
	int safe = 4,var_flag=0,log_flag=0;
	char var_cmp[] = "var";
	char log_cmp[] = "log";
    long long totalsecs = 0;
  	int pid = 0;
  	int sz_tempstr = 0;
  	char tempstr[100];
  	// int size_tempbuff = 0;
    // char *tempbuff = NULL;
    int val1 = 0,val2 = 0,val = 0;
    int ok=0;
    mm_segment_t oldfs;
    
    get_file_pointer = fdget(fd);
    get_file = get_file_pointer.file;
    if(get_file && get_file->f_path.dentry!=NULL)
	{   

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
	   		ok = 1;
	   		totalsecs = ktime_get_real_seconds();
			pid = task_tgid_vnr(current);
			time64_to_tm(totalsecs,0,&result);
	      	sz_tempstr = snprintf(tempstr, sizeof(tempstr), "pid = %d, date = [%ld/%d/%d %d:%d:%d]"
	      	,pid,result.tm_year+1900,result.tm_mon+1,result.tm_mday
	      	,result.tm_hour,result.tm_min,result.tm_sec); 

	      	if(sz_tempstr<0)
	      		ok = 0;

	      	// size_tempbuff = count+((sz_tempstr)*(sizeof(char)));
	      	// tempbuff = (char*)(kmalloc(size_tempbuff+1,GFP_KERNEL));

	      	// if(!tempbuff)
	      	// 	ok = 0;

	    	if(ok)
	    	{	
	      		strlcpy(tempbuff,tempstr,size_tempbuff+1);
	      		strlcat(tempbuff,buf,size_tempbuff+1);
	      		
	      		printk(KERN_ALERT "%d\n",sz_tempstr);
	      		printk(KERN_ALERT "%s\n",tempstr);
				
	      		
				return my_ksys_write(fd,tempstr,sz_tempstr);	      		

	      		// oldfs = getfs();
	      		// set_fs(KERNEL_DS);
	      		// val = ksys_write(fd,tempstr,sz_tempstr);
	      		// set_fs(oldfs);
	      		// return val;
	      		
	      		// return ksys_write(fd, buf, count);
	      	}

	      
	   	}
	}
   
	return ksys_write(fd, buf, count);

    return 0;
}



