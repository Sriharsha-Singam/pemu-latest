/*
#
#  Copyright © 2014 The University of Texas System Board of Regents, All Rights Reserved.
#       Author:        The Systems and Software Security (S3) Laboratory.
#         Date:        March 12, 2015
#      Version:        1.0.0
#
*/

#include <stdio.h>

#include "pemu.h"

void setup_guest_os_values();

struct PEMU_EXEC_STATS pemu_exec_stats = {0};
struct PEMU_HOOK_FUNCS pemu_hook_funcs = {0};
struct PEMU_BBL pemu_bbl = {0};
struct PEMU_INST pemu_inst = {0};

CPUState* pemu_cpu;
CPUX86State* pemu_cpu_state;

void init_inst(void)
{
	 xed_tables_init();
	 xed_state_zero(&pemu_inst.PEMU_dstate);

  	 xed_state_init(&pemu_inst.PEMU_dstate,
			 XED_MACHINE_MODE_LEGACY_32,
			 XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);

}

void init_bbl(void)
{
	memset(&pemu_bbl, 0, sizeof(struct PEMU_BBL));
	pemu_bbl.bbl = (BBL) malloc(sizeof(struct Bbl));
}

inline void inst_update(char *buf)
{
	xed_decoded_inst_zero_set_mode(&pemu_inst.PEMU_xedd_g, &pemu_inst.PEMU_dstate);
	xed_error_enum_t xed_error = xed_decode(&pemu_inst.PEMU_xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  buf), 15);
	if (xed_error == XED_ERROR_NONE) 
	{
	   xed_decoded_inst_dump_intel_format(&pemu_inst.PEMU_xedd_g, pemu_inst.PEMU_inst_str, 
			   sizeof(pemu_inst.PEMU_inst_str), 0);	
	}
}

void PEMU_update_cpux86(CPUX86State* env) {
	if (!pemu_exec_stats.PEMU_start) return;   
	pemu_cpu_state = env;
}

void PEMU_update_cpu(CPUState* env) {
    pemu_cpu = env;
    pemu_cpu_state = pemu_cpu->env_ptr;
}

int PEMU_init(CPUState* env)
{
	
        setup_guest_os_values();
        PEMU_update_cpu(env);

	init_pin_regmapping(env);
	init_inst();
	init_bbl();
	init_hashTable();
	init_disas();
	init_introspect();
	return 1;
}

int PEMU_exit(void)
{
	fprintf(stdout, "PEMU_exit()\r\n");
	pemu_exec_stats.PEMU_start = 0;
	pemu_exec_stats.PEMU_main_thread_started = 0;
	return 1;
}
