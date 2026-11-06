;---------------------------------------------------------------
; t386.asm -- SMART.INC con .386: las macros de turnos y MOVZX/MOVSX
; NO deben definirse (existen instrucciones nativas); FastIMul,
; flags y campos deben funcionar en DWORD.
; OJO: .386 va ANTES del include porque @Cpu se evalua al incluir.
;---------------------------------------------------------------
    .386
    .MODEL tiny
    include SMART.INC
    .CODE

start:
;--- 1: shl eax,4 debe ser UNA instruccion (C1 /4)
    mov eax, 0F00DABCDh
    shl eax, 4
    nop
;--- 2: sar/shr con inmediato (186+)
    mov ecx, 0F0000000h
    sar ecx, 4
    nop
;--- 3: movzx/movsx nativos
    movzx eax, bl
    movsx ebx, al
    nop
;--- 4: FastIMul DWORD
    mov ebx, 00123456h
    FastIMul eax, ebx, 1000
    nop
    mov ebx, 0FFFFFFF0h
    FastIMul ecx, ebx, -3
    nop
;--- 5: bits en dword
    mov eax, 0
    setflag eax, 20
    clrflag eax, 4
    flipflag eax, 31
    nop
;--- 6: campos dword
    setfield eax, 8, 12, 0ABCh
    nop
    getfield edx, eax, 8, 12
    nop
;--- 7: FastMul sigue funcionando (16 bits, igual en 386)
    mov ax, 01234h
    FastMul 0FFF0h
    nop
;--- 8: push/pop multiple con operandos de 32 bits
    mov eax, 011111111h
    mov ebx, 022222222h
    mov ecx, 033333333h
    push eax, ebx, ecx
    pop ecx, ebx, eax
    nop
    ret
END start
