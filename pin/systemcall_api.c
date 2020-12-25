/*
#
#  Copyright © 2014 The University of Texas System Board of Regents, All Rights Reserved.
#       Author:        The Systems and Software Security (S3) Laboratory.
#         Date:        March 12, 2015
#      Version:        1.0.0
#
*/

#include "systemcall_api.h"
#include "../pemu.h"

VOID PIN_AddSyscallEntryFunction (SYSCALL_ENTRY_CALLBACK fun, VOID *val)
{
	pemu_hook_funcs.enter_syscall_hook = fun;
}

VOID PIN_AddSyscallExitFunction (SYSCALL_EXIT_CALLBACK fun, VOID *val)
{
	pemu_hook_funcs.exit_syscall_hook = fun;
}

VOID PIN_SetSyscallArgument (CONTEXT *ctxt, SYSCALL_STANDARD std, UINT32 argNum, ADDRINT val)
{
// TODO: Change all this to STYLE that works: res = pemu_cpu_state->regs[R_EAX]; BUT THIS IS VERY DANGEROUS... RETHINK.
	switch(std){
		case SYSCALL_STANDARD_INVALID:
			break;
		case SYSCALL_STANDARD_IA32_LINUX:
		case SYSCALL_STANDARD_IA32E_LINUX:
			switch(argNum){
				case 0:
					*ctxt[REG_EBX_] = val;
					break;
				case 1:
					*ctxt[REG_ECX_] = val;
					break;
				case 2:
					*ctxt[REG_EDX_] = val;
					break;
				case 3:
					*ctxt[REG_ESI_] = val;
					break;
				case 4:
					*ctxt[REG_EDI_] = val;
					break;
				case 5:
					*ctxt[REG_EBP_] = val;
					break;
				default:
					break;
			}
			break;
		case SYSCALL_STANDARD_IA32_MAC:
		case SYSCALL_STANDARD_IA32E_MAC:
		case SYSCALL_STANDARD_IA32_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32E_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32_WINDOWS_ALT:
		case SYSCALL_STANDARD_WOW64:
		case SYSCALL_STANDARD_WINDOWS_INT:
			break;
		default:
			break;	
	}

}

ADDRINT PIN_GetSyscallArgument (const CONTEXT *ctxt, SYSCALL_STANDARD std, UINT32 argNum)
{
// TODO: Change all this to STYLE that works: res = pemu_cpu_state->regs[R_EAX];
	ADDRINT res = 0;
	switch(std){
		case SYSCALL_STANDARD_INVALID:
			break;
		case SYSCALL_STANDARD_IA32_LINUX:
		case SYSCALL_STANDARD_IA32E_LINUX:
			switch(argNum){
				case 0:
					res = *ctxt[REG_EBX_];
					break;
				case 1:
					res = *ctxt[REG_ECX_];
					break;
				case 2:
					res = *ctxt[REG_EDX_];
					break;
				case 3:
					res = *ctxt[REG_ESI_];
					break;
				case 4:
					res = *ctxt[REG_EDI_];
					break;
				case 5:
					res = *ctxt[REG_EBP_];
					break;
				default:
					break;
			}
			break;
		case SYSCALL_STANDARD_IA32_MAC:
		case SYSCALL_STANDARD_IA32E_MAC:
		case SYSCALL_STANDARD_IA32_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32E_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32_WINDOWS_ALT:
		case SYSCALL_STANDARD_WOW64:
		case SYSCALL_STANDARD_WINDOWS_INT:
			break;
		default:
			break;	
	}
	return res;
}

VOID PIN_SetSyscallNumber (CONTEXT *ctxt, SYSCALL_STANDARD std, ADDRINT val)
{
	switch(std){
		case SYSCALL_STANDARD_INVALID:
			break;
		case SYSCALL_STANDARD_IA32_LINUX:
		case SYSCALL_STANDARD_IA32E_LINUX:
			//*ctxt[REG_EAX_] = val; TODO:: THIS DOES NOT WORK. It really should not be used in general. It is dangerous.
			break;
		case SYSCALL_STANDARD_IA32_MAC:
		case SYSCALL_STANDARD_IA32E_MAC:
		case SYSCALL_STANDARD_IA32_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32E_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32_WINDOWS_ALT:
		case SYSCALL_STANDARD_WOW64:
		case SYSCALL_STANDARD_WINDOWS_INT:
			break;
		default:
			break;	
	}

}

ADDRINT PIN_GetSyscallNumber (const CONTEXT *ctxt, SYSCALL_STANDARD std)
{
	ADDRINT res = 0;
	switch(std){
		case SYSCALL_STANDARD_INVALID:
			break;
		case SYSCALL_STANDARD_IA32_LINUX:
		case SYSCALL_STANDARD_IA32E_LINUX:
			res = pemu_cpu_state->regs[R_EAX];
			break;
		case SYSCALL_STANDARD_IA32_MAC:
		case SYSCALL_STANDARD_IA32E_MAC:
		case SYSCALL_STANDARD_IA32_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32E_WINDOWS_FAST:
		case SYSCALL_STANDARD_IA32_WINDOWS_ALT:
		case SYSCALL_STANDARD_WOW64:
		case SYSCALL_STANDARD_WINDOWS_INT:
			break;
		default:
			break;	
	}
	return res;
}

ADDRINT PIN_GetSyscallReturn (const CONTEXT *ctxt, SYSCALL_STANDARD std)
{
	return pemu_cpu_state->regs[R_EAX];
}

ADDRINT PIN_GetSyscallErrno (const CONTEXT *ctxt, SYSCALL_STANDARD std)
{
	return 0;
}
