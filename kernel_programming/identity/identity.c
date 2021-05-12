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

SYSCALL_DEFINE1(identity, int, fd)
{
	struct tm result;
	long long totalsecs = ktime_get_real_seconds();

	int pid = task_tgid_vnr(current);
	time64_to_tm(totalsecs,0,&result);

    printk(KERN_ALERT "pid = %d, date = [%d/%d/%d %d:%d:%d]"
    	,pid,result.tm_year+1900,result.tm_mon+1,result.tm_mday
    	,result.tm_hour,result.tm_min,result.tm_sec);
    
    
    struct file* get_file;
    get_file = fdget(fd);
    char buff[256];
    dentry_path_raw(get_file->f_path.dentry,buff,sizeof(buff));
    printk(KERN_ALERT "File Path at : %s\n", buff);

    return 0;
}
