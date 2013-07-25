#include <Windows.h>
#include <stdlib.h>
#include "ParsConfig.h"
#include "LdrList.h"
#include "XmlLog.h"
#include "LogInfo.h"
#include "ETAV_DebugBreak.h"
#include "InsSimulator.h"
#include "distorm\include\distorm.h"
#include "distorm\include\mnemonics.h"
#pragma once

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;

typedef enum _ROP_CALLEE { 
	CalleeVirtualAlloc          = 0,
	CalleeVirtualAllocEx        = 1,
	CalleeVirtualProtect        = 2,
	CalleeVirtualProtectEx      = 3,
	CalleeMapViewOfFile         = 4,
	CalleeMapViewOfFileEx		= 5,
	CalleeHeapCreate			= 6,
	CalleeWriteProcessMemory	= 7,
	CalleeNtAllocateVirtualMemory = 8,
	CalleeNtProtectVirtualMemory = 9,
	CalleeMax					= 10 /* A pseudo entry */
} ROP_CALLEE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect,
	IN ULONG GeneralRegisters
	);

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	);

STATUS
DbgSetRopFlag(
	VOID
	);

STATUS
DbgGetRopFlag(
	VOID
	);

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	);

BOOL
CheckCaller(
	IN ULONG_PTR lpReturningAddress,
	IN BOOL bExactCheck,
	IN ROP_CALLEE RopCallee,
	IN ULONG *GeneralRegisters);

STATUS
InitializeCriticalFunctionDefTable(
	VOID
	);

FARPROC
GetCriticalFunctionAddress(
	IN ROP_CALLEE RopCallee
	);

DWORD
GetCriticalFunctionPoppingDwordsBeforeRet(
	IN ROP_CALLEE RopCallee
	);