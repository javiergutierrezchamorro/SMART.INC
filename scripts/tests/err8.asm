    include SMART.INC
; err8.asm -- esperado: error "FastMul: factor fuera de rango"
    .8086
    .MODEL tiny
    .CODE
start:
    FastMul 70000
    ret
END start
