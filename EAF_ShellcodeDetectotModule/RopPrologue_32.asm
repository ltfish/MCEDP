.486
.MODEL FLAT, STDCALL
OPTION CASEMAP :NONE
OPTION PROLOGUE	:SaveFreedStack_Prologue
OPTION EPILOGUE	: SaveFreedStack_Epilogue

_ValidateCallAgainstRop PROTO SYSCALL

.DATA

; User-defined prologue

SaveFreedStack_Prologue MACRO procname, flags, argbytes, localbytes, reglist, userparms:VARARG
    sub esp, 40h ; Save the unused stack for further checking
	IF localbytes GT 0
        push    ebp
        mov     ebp, esp
		add		ebp, 40h ; Fix ebp
        sub     esp, localbytes
    ELSEIF argbytes GT 0
        push    ebp
        mov     ebp, esp
		add		ebp, 40h ; Fix ebp
    ELSEIFNB <userparms>
      IF @InStr(1, <userparms>, <FORCEFRAME>)
        push    ebp
        mov     ebp, esp
		add		ebp, 40h ; Fix ebp
      ENDIF
    ENDIF

    ;; USES clause
    IFNB <reglist>
        FOR reg,reglist
            push reg
        ENDM
    ENDIF

    EXITM <localbytes>
ENDM

; User-defined epilogue

SaveFreedStack_Epilogue MACRO procname, flags, argbytes, localbytes, reglist, userparms:VARARG
    ;; USES clause
    IFNB <reglist>
        FOR reg,reglist
            pop reg
        ENDM
    ENDIF

    IF (argbytes GT 0) OR (localbytes GT 0)
		sub		ebp, 40h
        leave
		add		esp, 40h
    ELSEIFNB <userparms>
      IF @InStr(1,<userparms>,<FORCEFRAME>)
		sub		ebp, 40h
        leave
		add		esp, 40h
      ENDIF
    ENDIF

    IF flags AND 10h
        ;; caller will restore stack
        retn 0
    ELSE
        ;; callee must restore stack
        retn argbytes
    ENDIF
ENDM


.FARDATA
EXTERN VirtualAlloc_	:DWORD
EXTERN VirtualProtect_	:DWORD
EXTERN VirtualAllocEx_	:DWORD
EXTERN VirtualProtectEx_:DWORD
EXTERN MapViewOfFile_	:DWORD
EXTERN MapViewOfFileEx_	:DWORD
EXTERN HeapCreate_		:DWORD

.CODE

HookedVirtualAlloc PROC lpAddress:DWORD, dwSize:DWORD, flAllocationType:DWORD, flProtect:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	xor		eax, eax 
	push	eax		; flProtect
	push	eax		; lpAddress
	push	eax		; RopCallee
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		edx, DWORD PTR [flProtect]
	push	edx  
	mov		eax, DWORD PTR [flAllocationType]  
	push	eax  
	mov		ecx, DWORD PTR [dwSize]  
	push	ecx  
	mov		edx, DWORD PTR [lpAddress]  
	push	edx  
	call	VirtualAlloc_
	ret		10h 
HookedVirtualAlloc ENDP

HookedVirtualAllocEx PROC hProcess:DWORD, lpAddress:DWORD, dwSize:DWORD, flAllocationType:DWORD, flProtect:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	xor		eax, eax 
	push	eax		; flProtect
	push	eax  	; lpAddress
	push	1		; RopCallee
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		eax, DWORD PTR [flProtect]  
	push	eax  
	mov		ecx, DWORD PTR [flAllocationType]  
	push	ecx  
	mov		edx, DWORD PTR [dwSize]  
	push	edx  
	mov		eax, DWORD PTR [lpAddress]  
	push	eax  
	mov		ecx, DWORD PTR [hProcess]  
	push	ecx
	call	VirtualAllocEx_ 
	ret		14h
HookedVirtualAllocEx ENDP

HookedVirtualProtect PROC lpAddress:DWORD, dwSize:DWORD, flNewProtect:DWORD, lpflOldProtect:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	mov		eax, DWORD PTR [flNewProtect]  
	push	eax								; flProtect
	mov		ecx, DWORD PTR [lpAddress]  	
	push	ecx  							; lpAddress
	push	2  								; RopCallee
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress						; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		edx, DWORD PTR [lpflOldProtect]
	push	edx  
	mov		eax, DWORD PTR [flNewProtect]  
	push	eax  
	mov		ecx, DWORD PTR [dwSize]  
	push	ecx  
	mov		edx, DWORD PTR [lpAddress]  
	push	edx  
	call	VirtualProtect_
	ret		10h 
HookedVirtualProtect ENDP

HookedVirtualProtectEx PROC hProcess:DWORD, lpAddress:DWORD, dwSize:DWORD, flNewProtect:DWORD, lpflOldProtect:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	mov		eax, DWORD PTR [flNewProtect]  
	push	eax								; flProtect
	mov		ecx, DWORD PTR [lpAddress]  
	push	ecx  							; lpAddress
	push	3								; RopCallee
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		eax, DWORD PTR [lpflOldProtect]  
	push	eax  
	mov		ecx, DWORD PTR [flNewProtect]  
	push	ecx  
	mov		edx, DWORD PTR [dwSize]  
	push	edx  
	mov		eax, DWORD PTR [lpAddress]  
	push	eax  
	mov		ecx, DWORD PTR [hProcess]  
	push	ecx
	call	VirtualProtectEx_
	ret		14h
HookedVirtualProtectEx ENDP

HookedMapViewOfFile PROC hFileMappingObject:DWORD, dwDesiredAccess:DWORD, dwFileOffsetHigh:DWORD, dwFileOffsetLow:DWORD, dwNumberOfBytesToMap:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	xor		eax, eax 
	push	eax		
	push	eax
	push	4
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		eax, DWORD PTR [dwNumberOfBytesToMap]  
	push	eax  
	mov		ecx, DWORD PTR [dwFileOffsetLow]  
	push	ecx  
	mov		edx, DWORD PTR [dwFileOffsetHigh]  
	push	edx  
	mov		eax, DWORD PTR [dwDesiredAccess]  
	push	eax  
	mov		ecx, DWORD PTR [hFileMappingObject]  
	push	ecx  
	call	MapViewOfFile_
	ret		14h
HookedMapViewOfFile ENDP

HookedMapViewOfFileEx PROC hFileMappingObject:DWORD, dwDesiredAccess:DWORD, dwFileOffsetHigh:DWORD, dwFileOffsetLow:DWORD, dwNumberOfBytesToMap:DWORD, lpBaseAddress:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	xor		eax, eax 
	push	eax
	mov		ecx, DWORD PTR [lpBaseAddress]  
	push	ecx
	push	5
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h
	mov		eax, DWORD PTR [lpBaseAddress]  
	push	eax  
	mov		ecx, DWORD PTR [dwNumberOfBytesToMap]  
	push	ecx  
	mov		edx, DWORD PTR [dwFileOffsetLow]  
	push	edx  
	mov		eax, DWORD PTR [dwFileOffsetHigh]  
	push	eax  
	mov		ecx, DWORD PTR [dwDesiredAccess]  
	push	ecx  
	mov		edx, DWORD PTR [hFileMappingObject]  
	push	edx  
	call	MapViewOfFileEx_  
	ret		18h 
HookedMapViewOfFileEx ENDP

HookedHeapCreate PROC flOptions:DWORD, dwInitialSize:DWORD, dwMaximumSize:DWORD
	push	esi
	push	ebx
	push	edx
	push	ecx
	push	eax
	xor		eax, eax 
	push	eax
	push	eax
	push	6
	lea		edx, [ebp+4]
	push	edx	; lpEspAddress
	call	_ValidateCallAgainstRop
	add		esp, 10h 
	mov		eax, DWORD PTR [dwMaximumSize]  
	push	eax  
	mov		ecx, DWORD PTR [dwInitialSize]  
	push	ecx  
	mov		edx, DWORD PTR [flOptions]  
	push	edx  
	call	HeapCreate_  
	ret		0Ch 
HookedHeapCreate ENDP

END