    include SMART.INC
; err10.asm -- esperado: error "FastIMul: dest y src...": dest = src
; con un campo de memoria y registro mezclados no aplica; aqui el caso
; es setfield con width 0.
    .8086
    .MODEL tiny
    .CODE
start:
    setfield ax, 2, 0, 3
    ret
END start
