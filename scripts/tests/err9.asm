    include SMART.INC
; err9.asm -- esperado: error "push: faltan operandos"
    .8086
    .MODEL tiny
    .CODE
start:
    push
    ret
END start
