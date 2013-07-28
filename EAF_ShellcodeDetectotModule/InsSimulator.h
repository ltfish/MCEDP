
/*
 * Instruction Simulator
 * 
 * This simulator only tries to simulator the simplest instructions that
 * appear in common gadgets. Simulation ends after stepping a certain amount
 * of instructions, or when coming across a branching instruction like jmp 
 * or call.
 *
 * For each 'ret', we check whether the target address is preceeded by a valid
 * 'call' instruction. If not, it's likely to be an ROP attack. Other checks
 * are soon to follow.
 * 
 */

#include "LogInfo.h"
#include "ParsConfig.h"
#include "distorm\include\distorm.h"
#include "distorm\include\mnemonics.h"
#pragma once

STATUS
SimulateExecution(
	IN ULONG_PTR uEip,
	IN ULONG_PTR uEsp,
	IN ULONG_PTR uEbp,
	IN DWORD dwDwordsToPop
	);