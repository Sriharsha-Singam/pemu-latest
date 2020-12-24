#include <stdio.h>
#include "pin.h"

VOID SysBefore(ADDRINT ip, ADDRINT num) {
	char syscall_finder[256];
	snprintf(syscall_finder, sizeof syscall_finder, "ausyscall i386 %d", num);
	fprintf(stdout,"SysBefore() ==> 0x%lx: %ld ==> ",
		(unsigned long)ip, (long)num);
	fflush(stdout);
	system(syscall_finder);
	fprintf(stdout, "\n");
}

VOID SyscallEntry(THREADID threadIndex,
			CONTEXT*ctxt, SYSCALL_STANDARD std, VOID*v) {
	SysBefore(PIN_GetSyscallReturn(ctxt, std),
			PIN_GetSyscallNumber(ctxt, std));
}

VOID Fini(INT32 code, VOID*v) {
	fprintf(stdout, "STRACE.SO Plugin FINISH \r\n");
}

INT32 Usage(VOID){
	return 0;
}

int main(int argc, char*argv[]) {
	fprintf(stdout, "STRACE.SO Plugin Main() -- SyscallEntry(): %p\r\n", SyscallEntry);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
