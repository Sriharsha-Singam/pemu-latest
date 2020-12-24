/*
#
#  Copyright © 2014 The University of Texas System Board of Regents, All Rights Reserved.
#       Author:        The Systems and Software Security (S3) Laboratory.
#         Date:        March 12, 2015
#      Version:        1.0.0
#
*/


#include <linux/module.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
	#include <linux/sched.h>
#else
	#include <linux/sched/task.h>
#endif

#include <linux/mm.h>

int init_module(void)
{
    printk(KERN_INFO 
	   "       0x%08lX, /* task struct root */\n"
	   "       %d, /* offset of task_struct list */\n"
	   "       %d, /* offset of mm */\n"
	   "       %d, /* offset of pgd in mm */\n"
	   "       %d, /* offset of active_mm */\n"
	   "       %d, /* offset of pgd in active_mm */\n"
	   "       %d, /* offset of comm */\n"
	   "       %d, /* offset of pid */\n",
	   (long)&init_task, 
	   (int)&init_task.tasks - (int)&init_task,
	   (int)&init_task.mm - (int)&init_task,
	   (int)&init_task.mm->pgd - (int)init_task.mm,
	   (int)&init_task.active_mm - (int)&init_task,
	   (int)&init_task.active_mm->pgd - (int)init_task.active_mm,
           (int)&init_task.comm - (int)&init_task,
	   (int)&init_task.pid - (int)&init_task
	);
    

    printk(KERN_INFO "Information module retistered.\n");
    return -1;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Information module removed.\n");
}

MODULE_LICENSE("GPL"); 
