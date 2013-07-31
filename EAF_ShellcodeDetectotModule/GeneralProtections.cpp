#include "GeneralProtections.h"

STATUS
EnablePermanentDep(
	BOOL bDisableExceptionChainValidation
	)
{
	NTSTATUS Status;
	ULONG ExecuteFlags;
	NtSetInformationProcess_ NtSetInformationProcess;

	NtSetInformationProcess = (NtSetInformationProcess_)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtSetInformationProcess"));
	if ( NtSetInformationProcess != NULL )
	{
        /* Set up proper flags, call NtSetInformationProcess to disble RW memory execution and make it permanent */
		ExecuteFlags = MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT;
		if(bDisableExceptionChainValidation)
		{
			ExecuteFlags |= MEM_EXECUTE_OPTION_DISABLE_EXCEPTION_CHAIN_VALIDATION;
		}
		Status = NtSetInformationProcess( GetCurrentProcess(),
										  ProcessExecuteFlags,
										  &ExecuteFlags,
										  sizeof(ExecuteFlags));
		if ( NT_SUCCESS(Status) )
		{
			DEBUG_PRINTF(LDBG, NULL, "Permanent DEP Enabled!\n");
			return MCEDP_STATUS_SUCCESS;
		}
	}

	return MCEDP_STATUS_INTERNAL_ERROR;
}

STATUS
EnableNullPageProtection(
	VOID
	)
{
	NTSTATUS Status;
	SIZE_T RegionSize;
	LPVOID lpBaseAddress;
	NtAllocateVirtualMemory_ NtAllocateVirtualMemory;

	NtAllocateVirtualMemory = (NtAllocateVirtualMemory_)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtAllocateVirtualMemory"));
	if ( NtAllocateVirtualMemory != NULL )
	{
        /* Allocate null page and first 0x1000 bytes proceeding it */
		RegionSize = 0x1000;
		lpBaseAddress= (PVOID)0x1;
		Status = NtAllocateVirtualMemory( GetCurrentProcess(), 
			                              &lpBaseAddress, 
										  0L, 
										  &RegionSize, 
										  MEM_COMMIT | MEM_RESERVE, 
										  PAGE_NOACCESS);
		if ( NT_SUCCESS(Status) )
		{
			DEBUG_PRINTF(LDBG, NULL, "NULL Page Allocation Prevention Enabled!\n");
			return MCEDP_STATUS_SUCCESS;
		}
	}

	return MCEDP_STATUS_INTERNAL_ERROR;
}

STATUS
EnableHeapSprayProtection(
	IN PCHAR szHeapAddressArray
	)
{
	PCHAR szHeapAddress;
	DWORD dwHeapAddress;

	szHeapAddress = strtok (szHeapAddressArray,";");
	while (szHeapAddress != NULL)
	{
        /* Preallocate common Heap Spray address */
		dwHeapAddress = strtol(szHeapAddress, NULL, 0);
		VirtualAlloc((LPVOID)dwHeapAddress, 0x400, MEM_RESERVE, PAGE_NOACCESS);
		szHeapAddress = strtok (NULL,";");
	}

	return MCEDP_STATUS_SUCCESS;
}

STATUS
EnableExceptionChainValidation(
	VOID
	)
{
	NTSTATUS Status;
	ULONG uSize;
	ULONG ExecuteFlags;
	HMODULE hNtdll;
	NtQueryInformationProcess_ NtQueryInformationProcess;
	NtSetInformationProcess_ NtSetInformationProcess;

	hNtdll = GetModuleHandle("ntdll.dll");
	if(hNtdll != NULL)
	{
		NtQueryInformationProcess = (NtQueryInformationProcess_)
			(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
		NtSetInformationProcess = (NtSetInformationProcess_)
			(GetProcAddress(hNtdll, "NtSetInformationProcess"));
		if (NtQueryInformationProcess != NULL &&
			NtSetInformationProcess != NULL )
		{
			Status = NtQueryInformationProcess( GetCurrentProcess(),
				ProcessExecuteFlags,
				&ExecuteFlags,
				sizeof(ExecuteFlags),
				&uSize );
			if(NT_SUCCESS(Status))
			{
				if(!(ExecuteFlags & MEM_EXECUTE_OPTION_PERMANENT))
				{
					ExecuteFlags &= ~(MEM_EXECUTE_OPTION_DISABLE_EXCEPTION_CHAIN_VALIDATION);
					Status = NtSetInformationProcess( GetCurrentProcess(),
						ProcessExecuteFlags,
						&ExecuteFlags,
						sizeof(ExecuteFlags));
					if ( NT_SUCCESS(Status) )
					{
						DEBUG_PRINTF(LDBG, NULL, "ExceptionChainValidation of current process is enabled.\n");
						return MCEDP_STATUS_SUCCESS;
					}
				}
				else
				{
					/* The permanent flag is set */
					DEBUG_PRINTF(LDBG, NULL, "Cannot set ExecuteOption flag as it is set as Permanent, "
						"current flag = %x.\n", ExecuteFlags);
					return MCEDP_STATUS_SUCCESS;
				}
			}
		}
	}

	return MCEDP_STATUS_INTERNAL_ERROR;
}