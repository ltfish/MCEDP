#include "RopDetection.h"

#define GENERAL_REGISTER(x) pGeneralRegisters[7 - (x - R_EAX)]

BOOL bRopDetected = FALSE;
BOOL bRopLoged = FALSE;

typedef struct _CRITICALFUNCTIONDEF
{
	FARPROC pAddress;
	DWORD dwDwordsToPopBeforeRet;
} CRITICALFUNCTIONDEF, *PCRITICALFUNCTIONDEF;

CRITICALFUNCTIONDEF CriticalFunctions[(DWORD)CalleeMax] = {0};

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect,
	IN ULONG GeneralRegisters /* edi, esi, ebp, esp, ebx, edx, ecx, eax */
	)
{
	PNT_TIB ThreadInfo;
	
	if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_NOT_SET )
	{
		/* get the thread stack range from TIB. */
		ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );

		/* monitor esp value if we supposed to */
		if ( MCEDP_REGCONFIG.ROP.STACK_MONITOR )
		{
			/* check if thread is passing the actual stack boundaries */
			if ( lpEspAddress < (DWORD)ThreadInfo->StackLimit || lpEspAddress >= (DWORD)ThreadInfo->StackBase ) 
			{
				/* set ROP flags */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG,NULL,"ROP Detected by STACK_MONITOR, out of bound stack!\n");
			}
		}

		/* Monitor stack page permission change value if we supposed to */
		if ( MCEDP_REGCONFIG.MEM.STACK_RWX )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				/* if it is going to make the stack executable */
				if ( ( flProtect & PAGE_EXECUTE )           ||  
					 ( flProtect & PAGE_EXECUTE_READWRITE ) || 
					 ( flProtect & PAGE_EXECUTE_READ )      ||
					 ( flProtect & PAGE_EXECUTE_WRITECOPY ) )
				{
					/* set ROP flag */
					DbgSetRopFlag();
					DEBUG_PRINTF(LDBG,NULL,"ROP Detected by STACK_RWX, stack permission changed to be executable!\n");
				}
			}
		}

		if ( MCEDP_REGCONFIG.ROP.PIVOT_DETECTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( MCEDP_REGCONFIG.ROP.CALL_VALIDATION )
		{
			/*
			 * Performing following checks on the caller
			 *  - The address of [esp - 4] could not be the starting address of current function,
			 *	  otherwise this function is reached via retn instead of a call
			 *	- The returning point must points to an executable space
			 *  - A 'call' instruction should be existing preceeding to the returning point
			 *  - Under most cases, the 'call' instruction should (in)directly points to the start
			 *	  of current function
			 */

			ULONG_PTR* lpPreviousStackPointer = (ULONG_PTR*)(lpEspAddress - sizeof(ULONG));
			if(*lpPreviousStackPointer == 
				(ULONG_PTR)GetCriticalFunctionAddress(RopCallee))
			{
				/* Set ROP flag */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG, NULL, "ROP detected by CALL_VALIDATION, "
					"the address before [esp] points to function start."
					" [esp] = 0x%x, FunctionStart = 0x%x\n", *lpPreviousStackPointer, GetCriticalFunctionAddress(RopCallee));
			}

			ULONG_PTR lpReturningAddress = *(ULONG_PTR*)lpEspAddress;
			
			// TODO: Cache it!
			MEMORY_BASIC_INFORMATION MemInfo = {0};
			if(!VirtualQuery((VOID*)lpReturningAddress, &MemInfo, sizeof(MemInfo)))
			{
				DEBUG_PRINTF(LDBG, NULL, "Error in calling VirtualQuery() in ValidateCallAgainstRop().\n");
			}
			else
			{
				if(!((MemInfo.Protect & PAGE_EXECUTE) ||
					(MemInfo.Protect & PAGE_EXECUTE_READ) ||
					(MemInfo.Protect & PAGE_EXECUTE_READWRITE) ||
					(MemInfo.Protect & PAGE_EXECUTE_WRITECOPY)))
				{
					// The target page cannot be executed
					DbgSetRopFlag();
					DEBUG_PRINTF(LDBG, NULL, "ROP detected by CALL_VALIDATION, "
						"the returning address 0x%08x cannot be executed.\n",
						lpReturningAddress);
				}
			}
			
			// Is there a call instruction preceeding to the returning address?
			if(!CheckCaller(
				lpReturningAddress, 
				TRUE,
				RopCallee, 
				&GeneralRegisters))
			{
				/* Set ROP flag */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG, NULL, "ROP detected by CALL_VALIDATION, "
					"the returning address 0x%08x is not preceeded by a valid call instruction.\n",
					lpReturningAddress);
			}
		}

		if ( MCEDP_REGCONFIG.ROP.FORWARD_EXECUTION )
		{
			/* Start simulation from the ret of current call */
			ULONG* pGeneralRegisters = &GeneralRegisters;
			STATUS statSimulation;
			if((statSimulation = SimulateExecution(
				*(ULONG_PTR*)lpEspAddress,
				lpEspAddress, 
				GENERAL_REGISTER(R_EBP),
				GetCriticalFunctionPoppingDwordsBeforeRet(RopCallee)
				)) == MCEDP_STATUS_POSSIBLE_ROP_CHAIN)
			{
				/* Set ROP flag */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG, NULL, "ROP detected by FORWARD_EXECUTION\n");
			}
			else if(statSimulation != MCEDP_STATUS_SUCCESS)
			{
				/* Other errors occured */
				switch(statSimulation)
				{
				case MCEDP_STATUS_INSUFFICIENT_BUFFER:
					DEBUG_PRINTF(LDBG, NULL, "FORWARD_EXECUTION returns MCEDP_STATUS_INSUFFICIENT_BUFFER, "
						"the stack space is not enough.\n");
					break;
				case MCEDP_STATUS_INTERNAL_ERROR:
					DEBUG_PRINTF(LDBG, NULL, "FORWARD_EXECUTION returns MCEDP_STATUS_INTERNAL_ERROR.\n");
					break;
				case MCEDP_ERROR_NOT_DECODABLE:
					DEBUG_PRINTF(LDBG, NULL, "FORWARD_EXECUTION returns MCEDP_ERROR_NOT_DECODABLE, "
						"we came across an undecodable instruction.\n");
					break;
				default:
					DEBUG_PRINTF(LDBG, NULL, "FORWARD_EXECUTION returns %x.\n",
						statSimulation);
					break;
				}
			}
		}

		if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_SET )
		{
			if ( MCEDP_REGCONFIG.ROP.DUMP_ROP )
				DbgReportRop((PVOID)lpEspAddress, RopCallee);

			if ( MCEDP_REGCONFIG.ROP.KILL_ROP)
				TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}
	}
}



STATUS
DbgSetRopFlag(
	VOID
	)
{
    ERRORINFO err;

	/* set the ROP flag */
	bRopDetected = TRUE;

    /* init log path */
    if ( InitLogPath( MCEDP_REGCONFIG.LOG_PATH, MAX_PATH ) != MCEDP_STATUS_SUCCESS )
	{
		REPORT_ERROR("InitLogPath()", &err);
		return MCEDP_STATUS_GENERAL_FAIL;
	}

	return MCEDP_STATUS_SHELLCODE_FLAG_SET;
}

STATUS
DbgGetRopFlag(
	VOID
	)
{
	/* get current value of ROP flag */
	if ( bRopDetected )
		return MCEDP_STATUS_ROP_FLAG_SET;

	return MCEDP_STATUS_ROP_FLAG_NOT_SET;
}

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	DWORD ModuleCount = 0;

    /* translate StackPointerAddress to module name */
	if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)StackPointerAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
	{
		wcstombs( ModuleFullName, TableEntry->FullDllName.Buffer, dwSize );
		return MCEDP_STATUS_SUCCESS;
	} 

	return MCEDP_STATUS_INTERNAL_ERROR;
}

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	LPVOID lpAddress;
	LPVOID lpCodeSectionAddress;
	CHAR szAssciFullModuleName[MAX_MODULE_NAME32];
	CHAR szAssciModuleName[MAX_MODULE_NAME32];
	PCHAR szRopInst;
	DWORD dwCodeSectionSize;
	DWORD i;
	PXMLNODE XmlLogNode;
	PXMLNODE XmlIDLogNode;;

	XmlIDLogNode = CreateXmlElement( XmlShellcode, "row");
    // type
	XmlLogNode = mxmlNewElement( XmlIDLogNode, "type");
	mxmlNewText( XmlLogNode, 0, "0");
    // data
	XmlLogNode = CreateXmlElement( XmlIDLogNode, "function");
	SecureZeroMemory(szAssciFullModuleName, MAX_MODULE_NAME32);
	SecureZeroMemory(szAssciModuleName, MAX_MODULE_NAME32);
	szRopInst = (PCHAR)LocalAlloc(LMEM_ZEROINIT, 2048);
	lpAddress = Address;
	bRopDetected = TRUE;

    /* Get function name which reports rop */
	switch (APINumber)
	{
	case CalleeVirtualAlloc:
		SetTextNode( XmlLogNode, 0, "VirtualAlloc");
		break;
	case CalleeVirtualAllocEx:
		SetTextNode( XmlLogNode, 0, "VirtualAllocEx");
		break;
	case CalleeVirtualProtect:
		SetTextNode( XmlLogNode, 0, "VirtualProtect");
		break;
	case CalleeVirtualProtectEx:
		SetTextNode( XmlLogNode, 0, "VirtualProtectEx");
		break;
	case CalleeMapViewOfFile:
		SetTextNode( XmlLogNode, 0, "MapViewOfFile");
		break;
	case CalleeMapViewOfFileEx:
		SetTextNode( XmlLogNode, 0, "MapViewOfFileEx");
		break;
	case CalleeNtAllocateVirtualMemory:
		SetTextNode(XmlLogNode, 0, "NtAllocateVirtualMemory");
		break;
	case CalleeNtProtectVirtualMemory:
		SetTextNode(XmlLogNode, 0, "NtProtectVirtualMemory");
		break;
	}

    /* Get the module that used for rop gadgets */
	if ( DbgGetRopModule( lpAddress, szAssciFullModuleName, MAX_MODULE_NAME32) == MCEDP_STATUS_SUCCESS )
	{
		XmlLogNode = CreateXmlElement( XmlIDLogNode, "module");
		SetTextNode( XmlLogNode, 0, szAssciFullModuleName);
		SaveXml( XmlLog );
	}

    /* Dump possible ROP gadgets */
	if ( MCEDP_REGCONFIG.ROP.DUMP_ROP == TRUE )
	{
		lpAddress = (PVOID)((DWORD_PTR)lpAddress - MCEDP_REGCONFIG.ROP.ROP_MEM_FAR);
		for ( i = 0 ; i <= MCEDP_REGCONFIG.ROP.MAX_ROP_MEM ; i++ , lpAddress = (LPVOID)((DWORD)lpAddress + 4) )
		{
			if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)lpAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
			{
				/* get module name */
				wcstombs( szAssciModuleName, TableEntry->FullDllName.Buffer, TableEntry->FullDllName.Length );

				/* Get module .text section start address */
				if ( ( lpCodeSectionAddress = PeGetCodeSectionAddress( TableEntry->DllBase ) ) == NULL )
				{
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD -- MODULE CODE SECTION ADDRESS NULL]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					break;
				}

				/* Get module .text section size */
				if ( ( dwCodeSectionSize = PeGetCodeSectionSize( TableEntry->DllBase ) ) == NULL )
				{
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD - MODULE CODE SECTION SIZE NULL]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					break;
				}

				/* Check if instruction lies inside the .text section */
				if ( (*(ULONG_PTR *)lpAddress) >= (ULONG_PTR)lpCodeSectionAddress && (*(ULONG_PTR *)lpAddress) < ( (ULONG_PTR)lpCodeSectionAddress + dwCodeSectionSize ) )
				{

					if ( ShuDisassmbleRopInstructions( (PVOID)(*(ULONG_PTR *)lpAddress), szRopInst, MCEDP_REGCONFIG.ROP.MAX_ROP_INST ) == MCEDP_STATUS_SUCCESS )
					{
						DEBUG_PRINTF(LROP, NULL, "[ 0x%p ] %s + 0x%p :\n", (*(ULONG_PTR *)lpAddress), szAssciModuleName, (*(ULONG_PTR *)lpAddress - (ULONG_PTR)TableEntry->DllBase));
						DEBUG_PRINTF(LROP, NULL, "%s", szRopInst);
					} else
					{
						DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [FAILD TO DISASSMBLE]\n", lpAddress, (*(ULONG_PTR *)lpAddress));
					}

					SecureZeroMemory(szRopInst, 2048);

				} else
					DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p [OUT OF CODE SECTION]\n", lpAddress, (*(ULONG_PTR *)lpAddress));

			} else
				DEBUG_PRINTF(LROP, NULL, "[ 0x%p ]\t\t\t\tDB 0x%p\n", lpAddress, (*(ULONG_PTR *)lpAddress));
		}
	}

	LocalFree(szRopInst);
}

// - 'call dword ptr [0xC0DEC0DE]' (6 bytes)
// - 'call dword ptr <reg + 32bit_displacement>' (6 bytes)
// - 'call 0xC0DEC0DE' (5 bytes)
// - 'call dword ptr <reg>' (2 bytes)
// - 'call dword ptr <reg + 8bit_displacement>' (3 bytes)
// - 'call dword ptr <reg1 + reg2 + 8bit_displacement>' (4 bytes)
// - 'call dword ptr <reg1 + reg2 + 32bit_displacement>' (7 bytes)
// 
// bExactCheck decides whether we checks target of the call instruction
// matches critical function.
BOOL
CheckCaller(
	IN ULONG_PTR lpReturningAddress,
	IN BOOL bExactCheck,
	IN ROP_CALLEE RopCallee,
	IN ULONG *pGeneralRegisters)
{
	CONST DWORD CallInstructionLength[] = {6, 5, 2, 3, 4, 7};
	CONST DWORD dwMaxInstructions = 7;
	_DInst DecodedInstructions[dwMaxInstructions]; /* There might be 7 instructions in all */
	DWORD dwDecodedInstructionsCount = 0;
	_CodeInfo ci;

	for(DWORD i = 0; 
		i < sizeof(CallInstructionLength) / sizeof(DWORD); 
		++i)
	{
		ci.code = (BYTE*)(lpReturningAddress - CallInstructionLength[i]);
		ci.codeLen = CallInstructionLength[i];
		ci.codeOffset = 0;
		ci.dt = Decode32Bits;
		ci.features = DF_NONE;
		distorm_decompose(&ci, 
			DecodedInstructions, 
			dwMaxInstructions,
			(unsigned int*)&dwDecodedInstructionsCount);

		if(dwDecodedInstructionsCount != 1 ||
			DecodedInstructions[0].flags == FLAG_NOT_DECODABLE)
		{
			continue;
		}

		ULONG_PTR lpCallingTarget = 0;

		if(DecodedInstructions[0].opcode == I_CALL)
		{
			if(!bExactCheck)
			{
				return TRUE;
			}
			else
			{
				_DInst* pInstr = &DecodedInstructions[0];
				/* Single operand only for call instructions */
				switch(pInstr->ops[0].type)
				{
				case O_REG:
					lpCallingTarget = GENERAL_REGISTER(pInstr->ops[0].index);
					break;
				case O_SMEM:
					lpCallingTarget = 
						*(ULONG_PTR*)(GENERAL_REGISTER(pInstr->ops[0].index) + pInstr->disp);
					break;
				case O_MEM:
					lpCallingTarget = *(ULONG_PTR*)
						(
						GENERAL_REGISTER(pInstr->base) /* base */
						+ GENERAL_REGISTER(pInstr->ops[0].index) * pInstr->scale /* index and scale */
						+ pInstr->disp /* displacement */
						);
					break;
				case O_PC:
					lpCallingTarget = (ULONG_PTR)INSTRUCTION_GET_TARGET(pInstr);
					break;
				case O_DISP:
					lpCallingTarget = *(ULONG_PTR*)(pInstr->disp);
					break;
				default:
					DEBUG_PRINTF(LDBG, NULL, "Error occurs in CALL_VALIDATION. Operand type = %x.\n",
						pInstr->ops[0].type);
					break;
				}
			}

			if(lpCallingTarget == 
				(ULONG_PTR)GetCriticalFunctionAddress(RopCallee))
			{
				return TRUE;
			}
		}

		/* TODO: Handle those more complicated cases, like jmp and so on */
	}

	return FALSE;
}

STATUS
InitializeCriticalFunctionDefTable(
	VOID
	)
{
	HMODULE hModule = LoadLibrary("Kernel32.dll");
	if(hModule == NULL)
	{
		return MCEDP_STATUS_INTERNAL_ERROR;
	}
	CriticalFunctions[(DWORD)CalleeVirtualAlloc].pAddress = GetProcAddress(hModule, "VirtualAlloc");
	CriticalFunctions[(DWORD)CalleeVirtualAlloc].dwDwordsToPopBeforeRet = 4;
	CriticalFunctions[(DWORD)CalleeVirtualAllocEx].pAddress = GetProcAddress(hModule, "VirtualAllocEx");
	CriticalFunctions[(DWORD)CalleeVirtualAllocEx].dwDwordsToPopBeforeRet = 5;
	CriticalFunctions[(DWORD)CalleeVirtualProtect].pAddress = GetProcAddress(hModule, "VirtualProtect");
	CriticalFunctions[(DWORD)CalleeVirtualProtect].dwDwordsToPopBeforeRet = 4;
	CriticalFunctions[(DWORD)CalleeVirtualProtectEx].pAddress = GetProcAddress(hModule, "VirtualProtectEx");
	CriticalFunctions[(DWORD)CalleeVirtualProtectEx].dwDwordsToPopBeforeRet = 5;
	CriticalFunctions[(DWORD)CalleeMapViewOfFile].pAddress = GetProcAddress(hModule, "MapViewOfFile");
	CriticalFunctions[(DWORD)CalleeMapViewOfFile].dwDwordsToPopBeforeRet = 5;
	CriticalFunctions[(DWORD)CalleeMapViewOfFileEx].pAddress = GetProcAddress(hModule, "MapViewOfFileEx");
	CriticalFunctions[(DWORD)CalleeMapViewOfFileEx].dwDwordsToPopBeforeRet = 6;
	CriticalFunctions[(DWORD)CalleeHeapCreate].pAddress = GetProcAddress(hModule, "HeapCreate");
	CriticalFunctions[(DWORD)CalleeHeapCreate].dwDwordsToPopBeforeRet = 3;
	CriticalFunctions[(DWORD)CalleeWriteProcessMemory].pAddress = GetProcAddress(hModule, "WriteProcessMemory");
	CriticalFunctions[(DWORD)CalleeWriteProcessMemory].dwDwordsToPopBeforeRet = 5;
	/* KiFastSystemCall() is hooked */
	CriticalFunctions[(DWORD)CalleeNtAllocateVirtualMemory].pAddress = (FARPROC)(*(PVOID*)0x7ffe0300);
	CriticalFunctions[(DWORD)CalleeNtAllocateVirtualMemory].dwDwordsToPopBeforeRet = 0;
	CriticalFunctions[(DWORD)CalleeNtProtectVirtualMemory].pAddress = (FARPROC)(*(PVOID*)0x7ffe0300);
	CriticalFunctions[(DWORD)CalleeNtProtectVirtualMemory].dwDwordsToPopBeforeRet = 0;

	return MCEDP_STATUS_SUCCESS;
}


FARPROC
GetCriticalFunctionAddress(
	IN ROP_CALLEE RopCallee
	)
{
	if((DWORD)RopCallee < (DWORD)CalleeMax)
	{
		return CriticalFunctions[RopCallee].pAddress;
	}
	else
	{
		return NULL;
	}
}

DWORD
GetCriticalFunctionPoppingDwordsBeforeRet(
	IN ROP_CALLEE RopCallee
	)
{
	if((DWORD)RopCallee < (DWORD)CalleeMax)
	{
		return CriticalFunctions[RopCallee].dwDwordsToPopBeforeRet;
	}
	else
	{
		return NULL;
	}
}