    include SMART.INC
; err2.asm -- esperado: error "cte fuera de rango"
    .8086
    .MODEL tiny
    .CODE
start:
    FastIMul ax, bx, 70000
    ret
END start
