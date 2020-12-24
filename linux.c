/*
#
#  Copyright © 2014 The University of Texas System Board of Regents, All Rights Reserved.
#       Author:        The Systems and Software Security (S3) Laboratory.
#         Date:        March 12, 2015
#      Version:        1.0.0
#
*/

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <linux/sched.h>
#include "pemu.h"
#include "linux.h"

//OS specific information:
struct PEMU_guest_os pemu_guest_os;

void setup_guest_os_values() {
   system("pwd");
   FILE* file = fopen ("../../guest_os_values.txt", "r");
   int i = 0;
   size_t read = 0;
   char * line = NULL;
   size_t len = 0;
   int task_struct_root = 0;
   int counter = 0;
   int values[5] = {0};
   while ((read = getline(&line, &len, file)) != -1) {
        if (task_struct_root == 0) {  
            sscanf(line, "%x", &task_struct_root);
            printf("0x%x\n", task_struct_root);
        } else {
            values[counter] = atoi(line);
            printf("%i\n", values[counter]);
            counter++;
        }
   }
   pemu_guest_os.taskaddr = task_struct_root;
   pemu_guest_os.listoffset = values[0];
   pemu_guest_os.mmoffset = values[1];
   pemu_guest_os.pgdoffset = values[2];
   pemu_guest_os.commoffset = values[3];
   pemu_guest_os.pidoffset = values[4];
   fclose (file);   
}

///////////////////////////
static void get_mem_location(target_ulong addr, int offset, int size, void *buf)
{
   PEMU_read_mem(addr + offset, size, buf);
}

static void get_name(target_ulong addr, int size, char *buf)
{
   PEMU_read_mem(addr + pemu_guest_os.commoffset, 16, buf);
}

static target_ulong next_task_struct(target_ulong addr)
{
	target_ulong retval;
	target_ulong next;

    PEMU_read_mem(addr + pemu_guest_os.listoffset + sizeof(target_ulong), 
			sizeof(target_ulong), &next);
    retval = next - pemu_guest_os.listoffset;

  	return retval;
}

static target_ulong get_pgd(target_ulong addr)
{
	target_ulong mmaddr, pgd;
	PEMU_read_mem(addr + pemu_guest_os.mmoffset, sizeof(mmaddr), &mmaddr);
	
	if (0 == mmaddr) {
		PEMU_read_mem(addr + pemu_guest_os.mmoffset + sizeof(mmaddr), 
  				sizeof(mmaddr), &mmaddr);
		//fprintf(stdout, "PDG GETTING => (0 == mmaddr)\r\n");
	}
	//struct mm_struct*
	if (0 != mmaddr) {
	   	PEMU_read_mem(mmaddr + pemu_guest_os.pgdoffset, sizeof(pgd), &pgd);
		//fprintf(stdout, "PDG GETTING => (0 != mmaddr)\r\n");
	} else {
	   	memset(&pgd, 0, sizeof(pgd));
		//fprintf(stdout, "PDG GETTING => (mmaddr set to 0)\r\n");	
	}

	/*target_ulong active_mmaddr, active_pgd;
	PEMU_read_mem(addr + 760, sizeof(mmaddr), &active_mmaddr);
	
	if (0 == active_mmaddr)
		PEMU_read_mem(addr + 760 + sizeof(mmaddr), 
  				sizeof(mmaddr), &active_mmaddr);
	//struct mm_struct*
	if (0 != active_mmaddr)
	   	PEMU_read_mem(active_mmaddr + pemu_guest_os.pgdoffset, sizeof(pgd), &active_pgd);
	else
	   	memset(&active_pgd, 0, sizeof(active_pgd));

	if (pgd != active_pgd) {
		fprintf(stdout, "PDG NOT EQUAL. pgd: %lu and active_pgd: %lu\r\n", pgd, active_pgd);
	}*/


	return pgd;
}

#if 0
static uint32_t get_first_mmap(uint32_t addr)
{
	uint32_t mmaddr, mmap;
	PEMU_read_mem(addr + pemu_guest_os.mmoffset, sizeof(mmaddr), &mmaddr);

	if (0 == mmaddr)
		PEMU_read_mem(addr + pemu_guest_os.mmoffset + sizeof(mmaddr), 
                   sizeof(mmaddr), &mmaddr);

  	if (0 != mmaddr)
	 	PEMU_read_mem(mmaddr, sizeof(mmap), &mmap);
	else
		memset(&mmap, 0, sizeof(mmap));
	
	return mmap;
}

static void get_mod_name(uint32_t addr, char *name, int size)
{
	uint32_t vmfile, dentry;

	if(PEMU_read_mem(addr + pemu_guest_os.vmfileoffset, sizeof(vmfile), &vmfile) != 0
			|| PEMU_read_mem(vmfile + pemu_guest_os.dentryoffset, sizeof(dentry), &dentry) != 0
			|| PEMU_read_mem(dentry + pemu_guest_os.dinameoffset, size < 36 ? size : 36, name) != 0)
		name[0] = 0;
}

static uint32_t get_vmstart(uint32_t addr)
{
	uint32_t vmstart;
	PEMU_read_mem(addr + pemu_guest_os.vmstartoffset, sizeof(vmstart), &vmstart);
  	return vmstart;
}

static uint32_t get_next_mmap(uint32_t addr)
{
  	uint32_t mmap;
	PEMU_read_mem(addr + pemu_guest_os.vmnextoffset, sizeof(mmap), &mmap);
	return mmap;
}

static uint32_t get_vmend(uint32_t addr)
{
   	uint32_t vmend;
	PEMU_read_mem(addr + pemu_guest_os.vmendoffset, sizeof(vmend), &vmend);
	return vmend;
}

static uint32_t get_vmflags(uint32_t addr)
{
	uint32_t vmflags;
	PEMU_read_mem(addr + pemu_guest_os.vmflagsoffset, sizeof(vmflags), &vmflags);
	return vmflags;
}
#endif
/////////////////////////////

int PEMU_find_process(void *opaque)
{
	target_ulong nextaddr = 0;
	char comm[512];
	int count = 0;
	int pid = -1;
	//struct task_struct task_struct_;
	//struct mm_struct mm_struct_;
	//fprintf(stdout, "Starting PEMU_find_process()\r\n");

	if(!strcmp(pemu_exec_stats.PEMU_binary_name, "")) {
		return 0;
	}
	nextaddr = pemu_guest_os.taskaddr;
	do{
		if (++count > 1000)
			return 0;
	  	get_name(nextaddr, 16, comm);
		get_mem_location(nextaddr, pemu_guest_os.pidoffset, sizeof(int), (void*)&pid);

		/*fprintf(stdout, "%d: ", pid);
		for (int yx = 0; yx < 16; yx++) {
			fprintf(stdout, "%c", comm[yx]);
		}
	        fprintf(stdout, " ==> 0x%lx\r\n", (get_pgd(nextaddr) - 0xc0000000));
		*/

		if(!strncmp(comm, pemu_exec_stats.PEMU_binary_name, 6)) {
		//	get_mem_location(nextaddr, 0, sizeof(task_struct), (void*)&task_struct_);
			break;
		}
		
		nextaddr = next_task_struct(nextaddr);
	}while(nextaddr != pemu_guest_os.taskaddr);

	if(nextaddr != pemu_guest_os.taskaddr){
		//get_mem_location(nextaddr, task_struct_.mm, sizeof(mm_struct), (void*)&mm_struct_);
		//fprintf(stdout, "Testing Structs => struct_mm_pgd: %p vs get_pgd(): 0x%x", mm_struct_.pgd, get_pgd(nextaddr));
		pemu_exec_stats.PEMU_cr3 = get_pgd(nextaddr) - 0xc0000000;
		pemu_exec_stats.PEMU_task_addr = nextaddr;
		fprintf(stdout, "finding process\t%s\t0x%x\t0x%x\n", comm, pemu_exec_stats.PEMU_pid, pemu_exec_stats.PEMU_cr3);
		return 1;
	}
	return 0;
}

extern size_t sbuf_size;
extern target_ulong user_buf;
void inject_freeGuestPde(void)
{
	int i,j,pde,pte;
	unsigned int cr3 = pemu_cpu_state->cr[3];
	int flags = 0x67;
	unsigned long start;

	printf("inject_freeGuestPde ... \n");
	for(i = 0x800 - 0x4; i > 0; i -= 4) {
		cpu_physical_memory_rw(cr3 + i, (uint8_t*)&pde, 4, 0);
		if(pde == 0) {
			user_buf = i * 0x100000;
			pde = ram_size + sbuf_size;
			pde = pde | flags;
			cpu_physical_memory_rw(cr3 + i, (uint8_t*)&pde, 4, 1);
			start = ram_size;
			printf("PDE %x %x\n", i*0x100000, pde);
			pde = pde & 0xfffff000;
			for(j = 0 ; j < (sbuf_size) / 0x1000 * 4 ; j += 4) {
				pte = start | flags;
				cpu_physical_memory_rw(pde + j, (uint8_t*)&pte, 4, 1);
				start += 0x1000;
				//printf("pte %x %x\n", pde+j, pte);
			}
			break;
		}
	}
}
