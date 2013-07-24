#include "RopDetection.h"

BOOL bRopDetected = FALSE;
BOOL bRopLoged = FALSE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect,
	IN ULONG uEax,
	IN ULONG uEcx,
	IN ULONG uEdx,
	IN ULONG uEbx,
	IN ULONG uEsi
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
			 * Performing following checks on the callsite
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
						"the returning address cannot be executed.");
				}
			}
			
			// Is there a call instruction preceeding to the returning address?
			// - 'call dword ptr [0xC0DEC0DE]' (6 bytes)
			// - 'call 0xC0DEC0DE' (5 bytes)
			// - 'call <reg>' (2 bytes)
			BOOL bCheckPassed = FALSE;

			if(*(WORD*)(lpReturningAddress - 6) == 0x15ff)
			{
				ULONG_PTR lpCallingTarget = *(*(ULONG_PTR**)(lpReturningAddress - 4));
				if(lpCallingTarget == 
					(ULONG_PTR)GetCriticalFunctionAddress(RopCallee))
				{
					bCheckPassed = TRUE;
				}
				else
				{
					/* We don't set the ROP flag here, as it might be a call eax instruction */
				}
			}

			if(!bCheckPassed && 
				*(BYTE*)(lpReturningAddress - 5) == 0xeb)
			{
				ULONG_PTR lpCallingTarget = *(ULONG_PTR*)(lpReturningAddress - 4);
				if(lpCallingTarget == 
					(ULONG_PTR)GetCriticalFunctionAddress(RopCallee))
				{
					bCheckPassed = TRUE;
				}
				else
				{
					/* We don't set the ROP flag here, as it might be a call eax instruction */
				}
			}

			if(!bCheckPassed &&
				*(BYTE*)(lpReturningAddress - 2) == 0xff)
			{
				BYTE TargetReg = *(BYTE*)(lpReturningAddress - 1);
				ULONG_PTR lpCallingTarget;
				switch(TargetReg)
				{
				case 0xd0:
					/* eax */
					lpCallingTarget = uEax;
					break;
				case 0xd1:
					/* ecx */
					lpCallingTarget = uEcx;
					break;
				case 0xd2:
					/* edx */
					lpCallingTarget = uEdx;
					break;
				case 0xd3:
					/* ebx */
					lpCallingTarget = uEbx;
					break;
				case 0xd6:
					/* esi */
					lpCallingTarget = uEsi;
					break;
				default:
					lpCallingTarget = 0xffffffff;
					break;
				}
				if(lpCallingTarget == 
					(ULONG_PTR)GetCriticalFunctionAddress(RopCallee))
				{
					bCheckPassed = TRUE;
				}
			}

			if(!bCheckPassed)
			{
				/* Set ROP flag */
				DbgSetRopFlag();
				DEBUG_PRINTF(LDBG, NULL, "ROP detected by CALL_VALIDATION, "
					"the returning address %08x is not preceeded by a valid call instruction.",
					lpReturningAddress);
			}
		}

		if ( MCEDP_REGCONFIG.ROP.FORWARD_EXECUTION )
		{
			/* NOT IMPLEMENTED */
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

FARPROC
GetCriticalFunctionAddress(
	IN ROP_CALLEE RopCallee
	)
{
	// TODO: Make it a table-lookup approach
	HMODULE hModule = LoadLibrary("Kernel32.dll");
	switch(RopCallee)
	{
	case CalleeVirtualAlloc:
		return GetProcAddress(hModule, "VirtualAlloc");
	case CalleeVirtualAllocEx:
		return GetProcAddress(hModule, "VirtualAllocEx");
	case CalleeVirtualProtect:
		return GetProcAddress(hModule, "VirtualProtect");
	case CalleeVirtualProtectEx:
		return GetProcAddress(hModule, "VirtualProtectEx");
	case CalleeMapViewOfFile:
		return GetProcAddress(hModule, "MapViewOfFile");
	case CalleeMapViewOfFileEx:
		return GetProcAddress(hModule, "MapViewOfFileEx");
	case CalleeHeapCreate:
		return GetProcAddress(hModule, "HeapCreate");
	case CalleeWriteProcessMemory:
		return GetProcAddress(hModule, "WriteProcessMemory");
	case CalleeNtAllocateVirtualMemory:
	case CalleeNtProtectVirtualMemory:
		/* Return the address of KiSystemCall */
		return (FARPROC)(*(PVOID*)0x7ffe0300);
	default:
		return NULL;
	}
}