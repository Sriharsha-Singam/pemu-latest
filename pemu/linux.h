/*
#
#  Copyright © 2014 The University of Texas System Board of Regents, All Rights Reserved.
#       Author:        The Systems and Software Security (S3) Laboratory.
#         Date:        March 12, 2015
#      Version:        1.0.0
#
*/

#ifndef __LINUX_H__
#define __LINUX_H__

//#include "cpu.h"
#include "qemu-pemu.h"

struct PEMU_guest_os {
	target_ulong taskaddr;
	int listoffset;
	int mmoffset;
	int pgdoffset;
	int commoffset;
	int pidoffset;
};

extern struct PEMU_guest_os pemu_guest_os;

void setup_guest_os_values();
int PEMU_find_process(void *opaque);

#endif
