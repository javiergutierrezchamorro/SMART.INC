    include SMART.INC
; err3.asm -- esperado: error "recuento no puede ser negativo" en shl
    .8086
    .MODEL tiny
    .CODE
start:
    shl ax, -1
    ret
END start
