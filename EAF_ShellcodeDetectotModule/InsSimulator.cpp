#include "InsSimulator.h"
#include "RopDetection.h"

#define MAX_STACK_SIZE 65536 /* in bytes */

/* helper macros */
#define STACK(x) SimulatedStack[(MAX_STACK_SIZE - (dwStackBase - x)) / 4]
#define STACK_SANITY_CHECK() StackSanityCheck(dwStackBase, c.GeneralReg.esp)
#define POP_STACK_DWORD() (STACK_SANITY_CHECK() ? STACK(c.GeneralReg.esp) : 0); \
	c.GeneralReg.esp += 4; \
	if(!STACK_SANITY_CHECK()) { \
		return MCEDP_STATUS_INSUFFICIENT_BUFFER; \
	}
#define PUSH_STACK_DWORD(x) c.GeneralReg.esp -= 4; \
	if(!STACK_SANITY_CHECK()) \
	{ \
		return MCEDP_STATUS_INSUFFICIENT_BUFFER; \
	} \
	else \
	{ \
		STACK(c.GeneralReg.esp) = x; \
	}
#define GENERAL_REGISTER_32Bit(x) ((DWORD*)&c.GeneralReg)[7 - (x - R_EAX)] /* w/out any checks */
#define GENERAL_REGISTER(x) ((x >= R_EAX && x <= R_EDI) ? \
	((DWORD*)&c.GeneralReg)[7 - (x - R_EAX)] : \
	0)
#define GET_DWORD(x) *(DWORD*)(x)

struct _GENERAL_REG
{
	DWORD edi;
	DWORD esi;
	DWORD ebp;
	DWORD esp;
	DWORD ebx;
	DWORD edx;
	DWORD ecx;
	DWORD eax;
};

typedef struct _CPU_REGISTERS
{
	struct _GENERAL_REG GeneralReg;
	
	DWORD eip;
} CPU_REGISTERS;

DWORD SimulatedStack[MAX_STACK_SIZE / 4];

BOOL
StackSanityCheck(
	DWORD dwStackBase,
	DWORD dwCurrentEsp
	)
{
	if(dwStackBase - dwCurrentEsp < MAX_STACK_SIZE)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

STATUS
SimulateExecution(
	IN ULONG_PTR uEip,
	IN ULONG_PTR uEsp,
	IN ULONG_PTR uEbp,
	IN DWORD dwDwordsToPop
	)
{
	PNT_TIB ThreadInfo;
	DWORD dwStackBase;
	CPU_REGISTERS c;
	_DInst DecodedIns;
	DWORD dwDecodedInstructionsCount = 0;
	_CodeInfo ci;
	DWORD dwInsFollowed = 0;
	DWORD i;
	MEMORY_BASIC_INFORMATION MemInfo = {0};
	BOOL bBreakSimulation = FALSE;
	DWORD dwBytesToCopy = 0;
	DWORD dwExecutionDepth = 0;

	ThreadInfo = (PNT_TIB)__readfsdword(0x18);
	dwStackBase = (DWORD)ThreadInfo->StackBase;

	/* Copy the stack */
	if(uEsp < dwStackBase && uEsp >= (DWORD)ThreadInfo->StackLimit)
	{
		dwBytesToCopy = dwStackBase - uEsp;
	}
	else
	{
		/* stack might be changed to another memory region! */
		if(!VirtualQuery((VOID*)uEsp, &MemInfo, sizeof(MemInfo)))
		{
			DEBUG_PRINTF(LDBG, NULL, "Error in calling VirtualQuery() in SimulateExecution().\n");
			return MCEDP_STATUS_INTERNAL_ERROR;
		}
		else
		{
			dwStackBase = (DWORD)MemInfo.BaseAddress + MemInfo.RegionSize;
			dwBytesToCopy = dwStackBase - uEsp;
		}
	}
	
	if(dwBytesToCopy >= MAX_STACK_SIZE)
	{
		dwBytesToCopy = MAX_STACK_SIZE / 2;
		dwStackBase = uEsp + MAX_STACK_SIZE / 2;
	}
	memcpy(&STACK(uEsp),
		(PVOID)uEsp, 
		(dwStackBase - uEsp));

	/* Initialize CPU */
	memset(&c, 0, sizeof(c));
	c.eip = uEip;
	c.GeneralReg.esp = uEsp;
	c.GeneralReg.ebp = uEbp;

	/* a trick ;) */
	DecodedIns.opcode = I_RET;
	DecodedIns.imm.qword = dwDwordsToPop;

	/* Step from eip */
	while(TRUE)
	{
		switch(DecodedIns.opcode)
		{
		case I_RET:
			{
				ULONG_PTR lpReturningAddress =
					STACK(c.GeneralReg.esp);
				/* perform return address check */
				// TODO: Cache it!
				if(!VirtualQuery((VOID*)lpReturningAddress, &MemInfo, sizeof(MemInfo)))
				{
					DEBUG_PRINTF(LDBG, NULL, "Error in calling VirtualQuery() in SimulateExecution().\n");
				}
				else
				{
					if(!((MemInfo.Protect & PAGE_EXECUTE) ||
						(MemInfo.Protect & PAGE_EXECUTE_READ) ||
						(MemInfo.Protect & PAGE_EXECUTE_READWRITE) ||
						(MemInfo.Protect & PAGE_EXECUTE_WRITECOPY)))
					{
						DEBUG_PRINTF(LDBG, NULL, "Address 0x%x is not executable.\n", (VOID*)STACK(c.GeneralReg.esp));
						return MCEDP_STATUS_POSSIBLE_ROP_CHAIN;
					}
				}

				/* perform caller check */
				if(!CheckCaller(lpReturningAddress, FALSE, CalleeMax, NULL))
				{
					return MCEDP_STATUS_POSSIBLE_ROP_CHAIN;
				}

				c.eip = POP_STACK_DWORD();
				for(i = 0; i < DecodedIns.imm.qword; ++i)
				{
					POP_STACK_DWORD();
				}

				++dwExecutionDepth;
			}
			break;
		case I_POP:
			if(DecodedIns.ops[0].index >= R_EAX &&
				DecodedIns.ops[0].index <= R_EDI)
			{
				/* 32bit general registers */
				GENERAL_REGISTER_32Bit(DecodedIns.ops[0].index) = POP_STACK_DWORD();
			}
			else
			{
				// TODO
			}
			c.eip += DecodedIns.size;
			break;
		case I_PUSH:
			if(DecodedIns.ops[0].index >= R_EAX &&
				DecodedIns.ops[0].index <= R_EDI)
			{
				/* 32bit general registers */
				PUSH_STACK_DWORD(GENERAL_REGISTER_32Bit(DecodedIns.ops[0].index));
			}
			else
			{
				// TODO
			}
			c.eip += DecodedIns.size;
			break;
		case I_ADD:
			if(DecodedIns.ops[0].type == O_REG &&
				DecodedIns.ops[0].index == R_ESP)
			{
				if(DecodedIns.ops[1].type == O_IMM)
				{
					// add esp, <imm>
					c.GeneralReg.esp += DecodedIns.imm.dword;
				}
				else if(DecodedIns.ops[1].type == O_REG)
				{
					// add esp, <reg>
					c.GeneralReg.esp += GENERAL_REGISTER(DecodedIns.ops[1].index);
				}
				else if(DecodedIns.ops[1].type == O_SMEM)
				{
					c.GeneralReg.esp += GET_DWORD(GENERAL_REGISTER(DecodedIns.ops[1].index));
				}
				else if(DecodedIns.ops[1].type == O_MEM)
				{
					c.GeneralReg.esp += GET_DWORD(GENERAL_REGISTER(DecodedIns.base) + 
						GENERAL_REGISTER(DecodedIns.ops[1].index) * DecodedIns.scale + DecodedIns.disp);
				}
			}
			break;
		case I_SUB:
			if(DecodedIns.ops[0].type == O_REG &&
				DecodedIns.ops[0].index == R_ESP)
			{
				if(DecodedIns.ops[1].type == O_IMM)
				{
					// sub esp, <imm>
					c.GeneralReg.esp -= DecodedIns.imm.dword;
				}
				else if(DecodedIns.ops[1].type == O_REG)
				{
					// sub esp, <reg>
					c.GeneralReg.esp -= GENERAL_REGISTER(DecodedIns.ops[1].index);
				}
				else if(DecodedIns.ops[1].type == O_SMEM)
				{
					// sub esp, [reg]
					c.GeneralReg.esp -= GET_DWORD(GENERAL_REGISTER(DecodedIns.ops[1].index));
				}
				else if(DecodedIns.ops[1].type == O_MEM)
				{
					// sub esp, [base + index * scale + disp]
					c.GeneralReg.esp -= GET_DWORD(GENERAL_REGISTER(DecodedIns.base) + 
						GENERAL_REGISTER(DecodedIns.ops[1].index) * DecodedIns.scale + DecodedIns.disp);
				}
			}
			break;
		case I_INC:
			if(DecodedIns.ops[0].type == O_REG &&
				DecodedIns.ops[0].index == R_ESP)
			{
				++c.GeneralReg.esp;
			}
			break;
		case I_DEC:
			if(DecodedIns.ops[0].type == O_REG &&
				DecodedIns.ops[0].index == R_ESP)
			{
				--c.GeneralReg.esp;
			}
			break;
		case I_JMP: case I_JMP_FAR: case I_JZ: case I_JNZ: case I_JA: case I_JAE:
		case I_JB: case I_JBE: case I_JG: case I_JGE: case I_JL: case I_JLE:
		case I_CALL:
			/* branching instructions, exit simulation */
			bBreakSimulation = TRUE;
			break;
		default:
			/* simply step over! */
			c.eip += DecodedIns.size;
			break;
		}

		if(bBreakSimulation)
		{
			break;
		}

		++dwInsFollowed;

		if(dwInsFollowed >= MCEDP_REGCONFIG.ROP.FE_MAX_INS_COUNT)
		{
			break;
		}
		if(dwExecutionDepth >= MCEDP_REGCONFIG.ROP.FE_MAX_DEPTH)
		{
			break;
		}

		/* Decode the next instruction */
		ci.code = (BYTE*)c.eip;
		ci.codeLen = 16;
		ci.codeOffset = 0;
		ci.dt = Decode32Bits;
		ci.features = DF_NONE;
		distorm_decompose(&ci, 
			&DecodedIns, 
			1,
			(unsigned int*)&dwDecodedInstructionsCount);

		if(dwDecodedInstructionsCount < 1 ||
			DecodedIns.flags == FLAG_NOT_DECODABLE)
		{
			return MCEDP_ERROR_NOT_DECODABLE;
		}
	}

	return MCEDP_STATUS_SUCCESS;
}