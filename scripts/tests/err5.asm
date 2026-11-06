    include SMART.INC
; err5.asm -- esperado: error del ensamblador: bit 9 no cabe en AL
; (setflag emite "or al, 200h" y el ensamblador rechaza el inmediato)
    .8086
    .MODEL tiny
    .CODE
start:
    setflag al, 9
    ret
END start
