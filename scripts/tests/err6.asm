    include SMART.INC
; err6.asm -- esperado: error de rango del campo (lo+width > 32)
    .386
    .MODEL tiny
    .CODE
start:
    setfield eax, 30, 4, 3
    ret
END start
