    include SMART.INC
; err4.asm -- esperado: error "movzx: destino no soportado"
    .8086
    .MODEL tiny
    .CODE
start:
    movzx si, bl
    ret
END start
