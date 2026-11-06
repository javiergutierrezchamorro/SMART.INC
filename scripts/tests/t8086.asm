    include SMART.INC
;---------------------------------------------------------------
; t8086.asm -- banco de pruebas de SMART.INC en 8086 (solo registros)
; Cada bloque siembra sus registros con MOV inmediatos y termina en
; un NOP (marcador para el verificador).
;---------------------------------------------------------------
    .8086
    .MODEL tiny
    .CODE

start:
;--- A1 shl ax,4
    mov ax, 0F00Dh
    shl ax, 4
    nop
;--- A2 shr ax,2
    mov ax, 0F00Dh
    shr ax, 2
    nop
;--- A3 sar bx,3
    mov bx, 0F00Dh
    sar bx, 3
    nop
;--- A4 sal cx,2
    mov cx, 01234h
    sal cx, 2
    nop
;--- A5 rol dx,5
    mov dx, 01234h
    rol dx, 5
    nop
;--- A6 ror si,7
    mov si, 0ABCDh
    ror si, 7
    nop
;--- A7 rcl di,4 (CF=0)
    clc
    mov di, 08001h
    rcl di, 4
    nop
;--- A8 rcr bp,9 (CF=1)
    stc
    mov bp, 08765h
    rcr bp, 9
    nop
;--- A9 shl ax,cl (CL=3)
    mov cl, 3
    mov ax, 0ABCDh
    shl ax, cl
    nop
;--- A10 shl bx (un operando)
    mov bx, 055AAh
    shl bx
    nop
;--- A11 shl cx,1 (paso directo)
    mov cx, 07777h
    shl cx, 1
    nop
;--- A12 shl dx,0 (no genera nada)
    mov dx, 01234h
    shl dx, 0
    nop
;--- A13 byte: rol al,2
    mov ax, 0C3h
    rol al, 2
    nop

;--- B1 movzx ax, bl
    mov bl, 080h
    movzx ax, bl
    nop
;--- B2 movzx bx, bh (mitad alta como fuente)
    mov bh, 0FFh
    movzx bx, bh
    nop
;--- B3 movzx cx, cl
    mov cl, 07Fh
    movzx cx, cl
    nop
;--- B4 movsx ax, al
    mov al, 085h
    movsx ax, al
    nop
;--- B5 movsx bx, bl
    mov bl, 05Ah
    movsx bx, bl
    nop
;--- B6 movsx cx, cl (negativo)
    mov cl, 0E0h
    movsx cx, cl
    nop

;--- C1 push/pop multiples
    mov ax, 01111h
    mov bx, 02222h
    mov cx, 03333h
    push ax, bx, cx
    pop dx, si, di
    nop
;--- C2 push multiple (dos)
    push ax, bx
    nop
;--- C3 pop multiple
    pop cx, dx
    nop

;--- D1 setflag/clrflag/flipflag word
    mov ax, 0
    setflag ax, 3
    setflag ax, 15
    clrflag ax, 3
    flipflag ax, 15
    setflag ax, 0
    nop
;--- D2 testflag (bit puesto -> ZF=0)
    testflag ax, 0
    nop
;--- D3 testflag (bit clear -> ZF=1)
    testflag ax, 1
    nop
;--- D4 maskflag
    maskflag ax, 0
    nop
;--- D5 flags en byte
    mov bl, 0F0h
    setflag bl, 0
    clrflag bl, 7
    flipflag bl, 1
    nop
;--- D6 maskflag byte
    maskflag bl, 4
    nop

;--- E1 setfield ax (desde FFFF)
    mov ax, 0FFFFh
    setfield ax, 4, 3, 0
    nop
;--- E2 setfield ax (valor 7)
    setfield ax, 4, 3, 7
    nop
;--- E3 getfield dx, ax, 8, 4
    getfield dx, ax, 8, 4
    nop
;--- E4 getfield in situ
    getfield ax, ax, 0, 3
    nop
;--- E5 getfield cx, bx, 4, 8
    mov bx, 0ABCDh
    getfield cx, bx, 4, 8
    nop
;--- E6 setfield cx, 0, 4, 3
    setfield cx, 0, 4, 3
    nop
;--- E7 getfield si, cx, 4, 8
    getfield si, cx, 4, 8
    nop
;--- E8 campo ancho 12
    mov ax, 01234h
    setfield ax, 2, 12, 0BCDh
    nop
    getfield bx, ax, 2, 12
    nop

;--- F: bateria FastIMul (dest = (src * cte) & 0FFFFh)
    mov bx, 01234h
    FastIMul ax, bx, 0
    nop
    mov bx, 01234h
    FastIMul ax, bx, 1
    nop
    mov bx, 01234h
    FastIMul ax, bx, -1
    nop
    mov bx, 01234h
    FastIMul ax, bx, 2
    nop
    mov bx, 01234h
    FastIMul ax, bx, -2
    nop
    mov bx, 01234h
    FastIMul ax, bx, 3
    nop
    mov bx, 01234h
    FastIMul ax, bx, 7
    nop
    mov bx, 08000h
    FastIMul cx, bx, 7
    nop
    mov bx, 01234h
    FastIMul ax, bx, 8
    nop
    mov bx, 01234h
    FastIMul ax, bx, 15
    nop
    mov bx, 01234h
    FastIMul ax, bx, 16
    nop
    mov bx, 01234h
    FastIMul ax, bx, 17
    nop
    mov bx, 01234h
    FastIMul ax, bx, -15
    nop
    mov bx, 01234h
    FastIMul ax, bx, 45
    nop
    mov bx, 01234h
    FastIMul ax, bx, 48
    nop
    mov bx, 01234h
    FastIMul ax, bx, 112
    nop
    mov bx, 01234h
    FastIMul ax, bx, 255
    nop
    mov bx, 01234h
    FastIMul ax, bx, 256
    nop
    mov bx, 01234h
    FastIMul ax, bx, 1000
    nop
    mov bx, 01234h
    FastIMul ax, bx, 4097
    nop
    mov bx, 01234h
    FastIMul ax, bx, 12288
    nop
    mov bx, 01234h
    FastIMul ax, bx, 10000
    nop
    mov bx, 01234h
    FastIMul ax, bx, 32767
    nop
    mov bx, 08000h
    FastIMul dx, bx, -32768
    nop
    mov bx, 01234h
    FastIMul ax, bx, 65535
    nop
    mov bx, 0FFFFh
    FastIMul si, bx, -32768
    nop

;--- G: bateria FastMul (dx:ax = ax * cte mod 2^32)
    mov ax, 01234h
    FastMul 0
    nop
    mov ax, 01234h
    FastMul 1
    nop
    mov ax, 01234h
    FastMul 2
    nop
    mov ax, 01234h
    FastMul 3
    nop
    mov ax, 01234h
    FastMul 10
    nop
    mov ax, 01234h
    FastMul 15
    nop
    mov ax, 01234h
    FastMul 16
    nop
    mov ax, 01234h
    FastMul 17
    nop
    mov ax, 01234h
    FastMul 100
    nop
    mov ax, 01234h
    FastMul 255
    nop
    mov ax, 01234h
    FastMul 256
    nop
    mov ax, 01234h
    FastMul 1000
    nop
    mov ax, 08000h
    FastMul 2
    nop
    mov ax, 01234h
    FastMul 4097
    nop
    mov ax, 01234h
    FastMul 08000h
    nop
    mov ax, 01234h
    FastMul 05555h
    nop
    mov ax, 0FFFFh
    FastMul 0FFFFh
    nop
    mov ax, 01234h
    FastMul 0FFF0h
    nop
    mov ax, 01234h
    FastMul 0BFFFh
    nop
    mov ax, 0FFFFh
    FastMul 0EEEFh
    nop
    mov ax, 08000h
    FastMul 08000h
    nop

    ret
END start
