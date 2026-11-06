    include SMART.INC
; err1.asm -- esperado: error "dest y src deben ser operandos distintos"
    .8086
    .MODEL tiny
    .CODE
start:
    FastIMul ax, ax, 3
    ret
END start
