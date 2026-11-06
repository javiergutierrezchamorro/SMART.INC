;---------------------------------------------------------------
; t8086b.asm -- casos con memoria (revision por desensamblado) y
; doble inclusion del archivo.
;---------------------------------------------------------------
    .8086
    .MODEL tiny
    include SMART.INC
    include SMART.INC        ; la guarda debe hacer esto inofensivo

    .DATA
wvar    dw  01234h
bvar    db  0F0h
tabla   dw  8 dup (?)

    .CODE
start:
;--- turnos con memoria (8086: expande en turnos de 1 bit)
    shl wvar, 3
    shr byte ptr bvar, 2
    sar wvar, 1
    shl wvar, cl
;--- FastIMul con memoria
    mov bx, 10
    FastIMul wvar, bx, 45        ; dest memoria, src registro
    mov ax, 3
    FastIMul cx, wvar, 100       ; dest registro, src memoria
;--- FastIMul con memoria en el atajo Mersenne (conserva src)
    FastIMul dx, wvar, 15
;--- bits con memoria
    setflag  wvar, 5
    clrflag  wvar, 12
    flipflag wvar, 0
    testflag bvar, 3
    maskflag wvar, 7
;--- campos con memoria
    setfield wvar, 4, 3, 5
    getfield ax, wvar, 4, 3     ; memoria -> registro
    getfield wvar, ax, 0, 4     ; registro -> memoria
;--- push/pop con memoria y segmentos
    push wvar, ds, si
    pop  si, ds, wvar
;--- movzx con memoria
    movzx ax, bvar
    movsx bx, bvar
    ret
END start
