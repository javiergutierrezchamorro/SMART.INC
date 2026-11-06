    include SMART.INC
; err7.asm -- esperado: error "dest y src no pueden ser memoria los dos"
    .8086
    .MODEL tiny
    .DATA
v1  dw ?
v2  dw ?
    .CODE
start:
    getfield v1, v2, 2, 4
    ret
END start
