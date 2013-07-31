#include <Windows.h>
#include <stdlib.h>
#include "ParsConfig.h"
#include "LogInfo.h"
#pragma once

#define ProcessExecuteFlags				0x22
#define MEM_EXECUTE_OPTION_DISABLE		0x01
#define MEM_EXECUTE_OPTION_ENABLE		0x02
#define MEM_EXECUTE_OPTION_PERMANENT	0x08
#define MEM_EXECUTE_OPTION_DISABLE_EXCEPTION_CHAIN_VALIDATION	0x40
#define NT_SUCCESS(Status)				(((NTSTATUS)(Status)) >= 0)

extern MCEDPREGCONFIG MCEDP_REGCONFIG;

typedef
NTSTATUS
(NTAPI *NtSetInformationProcess_)(
	__in HANDLE ProcessHandle, 
	__in ULONG ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
	);

typedef
NTSTATUS
(NTAPI* NtQueryInformationProcess_)(
	IN HANDLE ProcessHandle,
	IN ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT ULONG *ReturnLength
	);

typedef
NTSTATUS
(NTAPI *NtAllocateVirtualMemory_)(
	__in     HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__in     ULONG_PTR ZeroBits,
	__inout  PSIZE_T RegionSize,
	__in     ULONG AllocationType,
	__in     ULONG Protect
);

STATUS
EnablePermanentDep(
	BOOL bDisableExceptionChainValidation
	);


STATUS
EnableNullPageProtection(
	VOID
	);

STATUS
EnableHeapSprayProtection(
	IN PCHAR szHeapAddressArray
	);

STATUS
EnableExceptionChainValidation(
	VOID	
	);