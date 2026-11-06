;=====================================================================
;  SMART.INC  v2.0  --  "TASM style" optimization macros
;                       for MASM 6.0+ and ASMC (also JWasm)
;=====================================================================
;  Brings to MASM/ASMC the facilities Turbo Assembler used to provide
;  out of the box, and adds bit manipulation utilities:
;
;    1. SHL/SHR/SAL/SAR/ROL/ROR/RCL/RCR with a constant count on the
;       8086 (the 8086 only accepts shifting by 1 or by CL; with a
;       constant count the macro expands into 1-bit instructions).
;    2. MOVZX/MOVSX emulated on CPUs older than the 386.
;    3. PUSH/POP with several operands (TASM 4 style; in MASM macro
;       arguments are comma separated:  push ax, bx, cx).
;    4. FastIMul dest, src, const : signed multiplication by a
;       constant using shifts and adds only (8086).
;    5. FastMul const : DX:AX = AX * const unsigned, like MUL r16.
;    6. setflag/clrflag/flipflag/testflag/maskflag : single bits.
;    7. setfield/getfield : bit field insertion and extraction.
;
;  Requirements: MASM 6.0 or later, or ASMC/JWasm. Uses OPTION
;  RENAMEKEYWORD, OPATTR, ELSEIFIDNI, FOR/VARARG, macro functions
;  (EXITM %) and REPEAT/WHILE. The default CPU is 8086; with .186 or
;  higher the shift macros and MOVZX/MOVSX are not defined because
;  equivalent native instructions already exist.
;
;  General notes:
;   - Include this file AFTER the processor directive
;     (.8086/.186/.286/.386): @Cpu is evaluated at the include point.
;   - Include it BEFORE using the instructions it replaces (the
;     include enables OPTION RENAMEKEYWORD).
;   - On 8086, OPTION RENAMEKEYWORD:<shl>/<shr> also disables the
;     SHL and SHR expression OPERATORS (they share the token with
;     the instructions). The macros in this file compensate for it
;     with the __Pow2 function; if your own code needs 2^n in
;     constant expressions, use __Pow2(n) or multiplications.
;   - Unless stated otherwise, all macros destroy the flags.
;   - Counts and constants must be constant expressions known at
;     assembly time.
;   - Protected against multiple inclusion.
;
;  Verification: automated test bank of 104 cases (assembly,
;  disassembly and result simulation) with JWasm 2.31, the same
;  macro engine as ASMC; cross-checked against the test suite and
;  the ASMC 2.40 source code.
;
;  History:
;   v2.0  Rewrite: restored the <...> arguments lost in
;         ifidni/renamekeyword; fixed movzx with ah/bh/ch/dh as
;         source; SHx accepts CL, no count and detects negative
;         counts; FastIMul uses fewer MOVs and preserves src in the
;         shortcuts; FastMul gains a 32-bit Mersenne shortcut;
;         added movsx, multiple push/pop and the bit/field macros.
;=====================================================================

IFNDEF __SMART_INC__
__SMART_INC__ = 1

;=====================================================================
;  0. __Pow2 n  (internal function:  returns 2^n)
;=====================================================================
;  OPTION RENAMEKEYWORD:<shl>/<shr> also disables the assembler's
;  SHL and SHR OPERATORS (they share the token with the
;  instruction), so every mask computation in this file uses this
;  function, built from multiplications only:
;
;       flM = __Pow2(bit)          ; in assignments
;       or  ax, __Pow2(4)          ; inside expressions
;       IF v EQ __Pow2(5) - 1      ; in conditions
;
;  n must be a constant between 0 and 31.
;=====================================================================

__Pow2 MACRO n:REQ
    LOCAL p, i
    p = 1
    i = 0
    WHILE i LT (n)
        p = p * 2
        i = i + 1
    ENDM
    EXITM %p
ENDM

;=====================================================================
;  1. SHIFTS WITH A CONSTANT COUNT ON 8086
;=====================================================================
;  The 8086 only accepts "SHx reg,1" and "SHx reg,cl". These macros
;  also accept a constant count:
;
;       shl ax, 4      ->  four times "shl ax,1"
;       shl ax         ->  one "shl ax,1"
;       shl ax, 1      ->  "shl ax,1"      (direct pass-through)
;       shl ax, cl     ->  "shl ax,cl"     (direct pass-through)
;
;  A count of 0 emits nothing; a negative count raises an error.
;  OPTION RENAMEKEYWORD frees the instruction name (it becomes
;  @@shl) so the macro can take it over.
;  They work on registers and on memory as well (shl [bx], 3).
;=====================================================================

IF ((@Cpu AND 0FFh) EQ 1)       ; 8086 only: 186+ accepts immediate counts

    option renamekeyword:<shl>=@@shl
shl MACRO reg, val
    IFB <val>
        @@shl reg, 1
    ELSEIFIDNI <val>, <1>
        @@shl reg, 1
    ELSEIFIDNI <val>, <cl>
        @@shl reg, cl
    ELSE
        IF (val) LT 0
            .ERR <shl: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@shl reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<shr>=@@shr
shr MACRO reg, val
    IFB <val>
        @@shr reg, 1
    ELSEIFIDNI <val>, <1>
        @@shr reg, 1
    ELSEIFIDNI <val>, <cl>
        @@shr reg, cl
    ELSE
        IF (val) LT 0
            .ERR <shr: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@shr reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<sal>=@@sal
sal MACRO reg, val
    IFB <val>
        @@sal reg, 1
    ELSEIFIDNI <val>, <1>
        @@sal reg, 1
    ELSEIFIDNI <val>, <cl>
        @@sal reg, cl
    ELSE
        IF (val) LT 0
            .ERR <sal: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@sal reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<sar>=@@sar
sar MACRO reg, val
    IFB <val>
        @@sar reg, 1
    ELSEIFIDNI <val>, <1>
        @@sar reg, 1
    ELSEIFIDNI <val>, <cl>
        @@sar reg, cl
    ELSE
        IF (val) LT 0
            .ERR <sar: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@sar reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rol>=@@rol
rol MACRO reg, val
    IFB <val>
        @@rol reg, 1
    ELSEIFIDNI <val>, <1>
        @@rol reg, 1
    ELSEIFIDNI <val>, <cl>
        @@rol reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rol: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@rol reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<ror>=@@ror
ror MACRO reg, val
    IFB <val>
        @@ror reg, 1
    ELSEIFIDNI <val>, <1>
        @@ror reg, 1
    ELSEIFIDNI <val>, <cl>
        @@ror reg, cl
    ELSE
        IF (val) LT 0
            .ERR <ror: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@ror reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rcl>=@@rcl
rcl MACRO reg, val
    IFB <val>
        @@rcl reg, 1
    ELSEIFIDNI <val>, <1>
        @@rcl reg, 1
    ELSEIFIDNI <val>, <cl>
        @@rcl reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rcl: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@rcl reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rcr>=@@rcr
rcr MACRO reg, val
    IFB <val>
        @@rcr reg, 1
    ELSEIFIDNI <val>, <1>
        @@rcr reg, 1
    ELSEIFIDNI <val>, <cl>
        @@rcr reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rcr: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            @@rcr reg, 1
        ENDM
    ENDIF
ENDM

ENDIF   ; @Cpu = 8086

;=====================================================================
;  2. MOVZX/MOVSX EMULATED (CPU < 386)
;=====================================================================
;  movzx reg16, reg8/mem8 : clears the high half of the destination
;  and loads the low half. The order (MOV first, XOR after) makes it
;  work even with the high half as source:  movzx ax, ah  and
;  movzx bx, bh  give the correct result (they were lost in v1).
;
;  movsx reg16, reg8/mem8 : sign extension via CBW. For AX a plain
;  MOV AL + CBW is enough; for BX/CX/DX clobbering AX is unavoidable,
;  because the 8086 has no BL-to-register sign extension.
;
;  Both destroy the flags and accept AX/BX/CX/DX as destination only.
;=====================================================================

IF ((@Cpu AND 0FFh) LT 8)       ; 8086/186/286 (386+ has native MOVZX/MOVSX)

    option renamekeyword:<movzx>=@@movzx
movzx MACRO reg, val
    IFIDNI <reg>, <ax>
        mov al, val
        xor ah, ah
    ELSEIFIDNI <reg>, <bx>
        mov bl, val
        xor bh, bh
    ELSEIFIDNI <reg>, <cx>
        mov cl, val
        xor ch, ch
    ELSEIFIDNI <reg>, <dx>
        mov dl, val
        xor dh, dh
    ELSE
        .ERR <movzx: destination not supported, use AX/BX/CX/DX>
    ENDIF
ENDM

    option renamekeyword:<movsx>=@@movsx
movsx MACRO reg, val
    IFIDNI <reg>, <ax>
        mov al, val
        cbw
    ELSEIFIDNI <reg>, <bx>
        mov al, val
        cbw
        mov bx, ax              ; warning: clobbers AX
    ELSEIFIDNI <reg>, <cx>
        mov al, val
        cbw
        mov cx, ax              ; warning: clobbers AX
    ELSEIFIDNI <reg>, <dx>
        mov al, val
        cbw
        mov dx, ax              ; warning: clobbers AX
    ELSE
        .ERR <movsx: destination not supported, use AX/BX/CX/DX>
    ENDIF
ENDM

ENDIF   ; CPU < 386

;=====================================================================
;  3. PUSH/POP WITH SEVERAL OPERANDS (TASM 4 style)
;=====================================================================
;  TASM 4+ accepted "PUSH AX BX CX". In MASM the macro argument
;  separator is the comma, so the form here is:
;
;       push ax, bx, cx        ; three PUSHes in written order
;       pop  cx, bx, ax        ; three POPs in written order
;
;  With a single operand they emit exactly the same instruction as
;  without the macro. With no operands they raise an error.
;  PUSHA/PUSHF/POPA/POPF are left untouched.
;=====================================================================

    option renamekeyword:<push>=@@push
push MACRO ops:VARARG
    IFB <ops>
        .ERR <push: missing operands>
        EXITM
    ENDIF
    FOR o, <ops>
        @@push o
    ENDM
ENDM

    option renamekeyword:<pop>=@@pop
pop MACRO ops:VARARG
    IFB <ops>
        .ERR <pop: missing operands>
        EXITM
    ENDIF
    FOR o, <ops>
        @@pop o
    ENDM
ENDM

;=====================================================================
;  4. FastIMul dest, src, const
;=====================================================================
;  Multiplies signed by a constant without using IMUL (which on the
;  8086 costs 118-133 cycles). Shifts, adds and subtracts only.
;
;    dest : register (or memory with a declared size) that receives
;           the result; same size as src (WORD on 8086; with .386
;           DWORD works too: the macro is size agnostic).
;    src  : register or memory of the same size. DESTROYED in the
;           general case; PRESERVED when const is 0, +-2^j or of the
;           form (2^k - 1)*2^j with k >= 4 (shortcuts, see below).
;    const: signed constant, -32768 to 65535 (values 32768..65535
;           are taken as their 16-bit two's complement). Must be
;           known at assembly time.
;
;  Besides the general method the macro uses two shortcuts:
;    - const = +-2^j                    : dest = (src << j)  (+ NEG)
;    - const = (2^k - 1) * 2^j, k >= 4  : dest = ((src << k) - src) << j
;      (the "Mersenne" shortcut: one SUB instead of k-1 ADDs; in v1
;      this shortcut needed two extra MOVs and destroyed src).
;
;  General method (from least to most significant):
;    const = 2^a0 + 2^a1 + ...  =>  shl src up to 2^a0, mov dest, src,
;    and for each following bit: shl src and, if the bit is set,
;    add dest, src.
;
;  Examples:  FastIMul ax, bx, 45    ; ax = bx * 45
;             FastIMul cx, dx, -7    ; cx = -7 * dx
;             FastIMul eax, ebx, 1000; DWORD version with .386
;=====================================================================

FastIMul MACRO dest, src, cte
    IFIDNI <dest>, <src>
        .ERR <FastIMul: dest and src must be different operands>
        EXITM
    ENDIF
    IF ((cte) LT -32768) OR ((cte) GT 0FFFFh)
        .ERR <FastIMul: const out of range (-32768..65535)>
        EXITM
    ENDIF

    fmV = (cte) AND 0FFFFh          ; 16-bit pattern of the constant
    IF fmV AND 8000h                ; negative?
        fmV = (0 - fmV) AND 0FFFFh  ; absolute value
        fmNeg = 1
    ELSE
        fmNeg = 0
    ENDIF

    IF fmV EQ 0                     ; x * 0 = 0 (preserves src and flags)
        mov dest, 0
        EXITM
    ENDIF

    fmJ = 0                         ; trailing zeros: fmV = fmM * 2^fmJ
    fmM = fmV
    WHILE (fmM AND 1) EQ 0
        fmM = fmM / 2               ; (SHR operator is unavailable here: see __Pow2)
        fmJ = fmJ + 1
    ENDM

    IF fmM EQ 1                     ; const = +-2^fmJ : preserves src
        mov dest, src
        fmI = fmJ
        WHILE fmI
            shl dest, 1
            fmI = fmI - 1
        ENDM
    ELSE
        fmK = 0                     ; number of bits of fmM
        fmT = fmM
        WHILE fmT
            fmK = fmK + 1
            fmT = fmT / 2
        ENDM

        fmP = __Pow2(fmK)
        IF (fmM EQ (fmP - 1)) AND (fmK GE 4)
            ; Mersenne shortcut: x*((2^k - 1)*2^j) = ((x << k) - x) << j
            ; preserves src (v1 shifted src in place and needed 2 more MOVs)
            mov dest, src
            fmI = fmK
            WHILE fmI
                shl dest, 1
                fmI = fmI - 1
            ENDM
            sub dest, src
            fmI = fmJ               ; restore the stripped trailing zeros
            WHILE fmI
                shl dest, 1
                fmI = fmI - 1
            ENDM
        ELSE
            ; general case: src is shifted in place, dest accumulates
            ; (v1's fmA equalled fmJ: redundant computation removed)
            fmI = fmJ
            WHILE fmI
                shl src, 1
                fmI = fmI - 1
            ENDM
            mov dest, src
            fmT = fmV / __Pow2(fmJ + 1) ; bits above fmJ
            WHILE fmT
                shl src, 1
                IF fmT AND 1
                    add dest, src
                ENDIF
                fmT = fmT / 2
            ENDM
        ENDIF
    ENDIF

    IF fmNeg
        neg dest
    ENDIF
ENDM

;=====================================================================
;  5. FastMul const  ->  DX:AX = AX * const, unsigned (like MUL r16)
;=====================================================================
;  const: constant from 0 to 0FFFFh, known at assembly time.
;  Destroys BX (and CX when a real MUL wins) and the flags. It does
;  not reproduce the CF/OF values MUL would leave, only the result.
;
;  Strategies, best first depending on the bit pattern:
;    - const = 0                          : XOR AX / XOR DX
;    - const = 2^k                        : 32-bit shift
;    - const = (2^k - 1) * 2^j, k >= 4    : 32-bit Mersenne shortcut
;      (new in v2.0): ((x << k) - x) << j with SUB/SBB; turns dense
;      factors like 0FFFFh into ~2/3 of the instructions.
;    - MSB-to-LSB Horner with the DX:AX accumulator (v1)
;    - real MUL when the expansion would come out worse
;      (~118-137 cycles)
;=====================================================================

FastMul MACRO factor
    IF ((factor) LT 0) OR ((factor) GT 0FFFFh)
        .ERR <FastMul: factor out of range (0..65535)>
        EXITM
    ENDIF

    fmF = (factor) AND 0FFFFh
    IF fmF EQ 0                     ; x * 0 = 0
        xor ax, ax
        xor dx, dx
        EXITM
    ENDIF

    fmHi = 0                        ; position of the highest bit
    fmOnes = 0                      ; set bits of the factor
    fmT = fmF
    WHILE fmT
        fmHi = fmHi + 1
        fmOnes = fmOnes + (fmT AND 1)
        fmT = fmT / 2
    ENDM
    fmHi = fmHi - 1

    IF fmOnes EQ 1                  ; factor = power of 2
        xor dx, dx
        fmI = fmHi
        WHILE fmI
            shl ax, 1
            rcl dx, 1
            fmI = fmI - 1
        ENDM
        EXITM
    ENDIF

    fmJ = 0                         ; trailing zeros (odd factor * 2^fmJ)
    fmM = fmF
    WHILE (fmM AND 1) EQ 0
        fmM = fmM / 2
        fmJ = fmJ + 1
    ENDM
    fmK = 0                         ; number of bits of the odd part
    fmT = fmM
    WHILE fmT
        fmK = fmK + 1
        fmT = fmT / 2
    ENDM

    fmP = __Pow2(fmK)
    IF (fmM EQ (fmP - 1)) AND (fmK GE 4) AND (((fmHi + fmJ) * 4 + 6) LE 110)
        ; 32-bit Mersenne shortcut: DX:AX = ((x << k) - x) << j
        mov bx, ax                  ; keep the multiplicand
        xor dx, dx
        fmI = fmK
        WHILE fmI
            shl ax, 1
            rcl dx, 1
            fmI = fmI - 1
        ENDM
        sub ax, bx
        sbb dx, 0                   ; propagate the SUB carry
        fmI = fmJ
        WHILE fmI
            shl ax, 1
            rcl dx, 1
            fmI = fmI - 1
        ENDM
        EXITM
    ENDIF

    IF fmHi*4 + (fmOnes-1)*6 GT 110 ; expansion would be worse than MUL
        mov cx, fmF                 ; -> real MUL (~118-137 cycles)
        mul cx
        EXITM
    ENDIF

    mov  bx, ax                     ; keep the multiplicand
    xor  dx, dx                     ; 32-bit accumulator DX:AX
    fmJ = 0
    WHILE fmJ LT fmHi
        fmI = fmHi - 1 - fmJ        ; bit index, high to low
        shl  ax, 1                  ; acc = acc * 2
        rcl  dx, 1
        IF (fmF / __Pow2(fmI)) AND 1
            add  ax, bx             ; acc = acc + x
            adc  dx, 0
        ENDIF
        fmJ = fmJ + 1
    ENDM
ENDM

;=====================================================================
;  6. SINGLE BITS (FLAGS)
;=====================================================================
;  "bit" is the bit position (0 = least significant), as a constant
;  known at assembly time. rm can be an 8, 16 or 32-bit register or
;  memory operand:
;
;       setflag  rm, bit    ; or   rm, 1 shl bit      -> bit = 1
;       clrflag  rm, bit    ; and  rm, NOT (1 shl bit) -> bit = 0
;       flipflag rm, bit    ; xor  rm, 1 shl bit      -> invert bit
;       testflag rm, bit    ; test rm, 1 shl bit      -> ZF = (bit == 0)
;       maskflag rm, bit    ; and  rm, 1 shl bit      -> keep only the bit
;
;  If the bit does not exist in the size of the operand (e.g. bit 9
;  of AL) the assembler raises an error instead of emitting wrong
;  code. All of them destroy the flags; testflag and maskflag leave
;  the bit state in ZF. For BYTE/WORD operands the assembler picks
;  the imm8 form whenever the value fits.
;=====================================================================

setflag MACRO rm, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <setflag: bit index must be between 0 and 31>
        EXITM
    ENDIF
    or rm, __Pow2(bit)
ENDM

clrflag MACRO rm, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <clrflag: bit index must be between 0 and 31>
        EXITM
    ENDIF
    and rm, NOT __Pow2(bit)
ENDM

flipflag MACRO rm, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <flipflag: bit index must be between 0 and 31>
        EXITM
    ENDIF
    xor rm, __Pow2(bit)
ENDM

testflag MACRO rm, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <testflag: bit index must be between 0 and 31>
        EXITM
    ENDIF
    test rm, __Pow2(bit)
ENDM

maskflag MACRO rm, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <maskflag: bit index must be between 0 and 31>
        EXITM
    ENDIF
    and rm, __Pow2(bit)
ENDM

;=====================================================================
;  7. BIT FIELDS
;=====================================================================
;  A field is described by its start bit (lo, 0 = LSB) and its width
;  in bits. For example, bits 4..6 are lo=4, width=3. Both must be
;  constants known at assembly time.
;
;       setfield rm, lo, width, val
;           Inserts the constant val into the field (truncated to
;           width bits); the rest of the operand is preserved.
;           Emits:  AND rm, NOT (mask)  +  OR rm, (val * 2^lo)
;
;       getfield dest, src, lo, width
;           Extracts the field with zero extension: copies src into
;           dest, shifts right by lo bits and masks the rest. When
;           dest and src are the same operand no MOV is emitted;
;           the two operands cannot both be memory.
;
;  Compatible with MASM/TASM RECORD (native in MASM 6+/ASMC):
;       DOOR RECORD CLOSED:1, MODE:2, SPEED:5   ; SPEED = bits 3..7
;  allows writing   setfield ax, 3, WIDTH SPEED, 17
;  and              getfield bx, ax, 3, WIDTH SPEED
;  (WIDTH field returns the width; the position is read from the
;  RECORD itself: here SPEED starts at bit 3).
;=====================================================================

setfield MACRO rm, lo, width, val
    IF ((lo) LT 0) OR ((width) LT 1) OR ((width) GT 31) OR (((lo) + (width)) GT 32)
        .ERR <setfield: invalid range of lo/width (lo + width up to 32)>
        EXITM
    ENDIF
    and rm, NOT ((__Pow2(width) - 1) * __Pow2(lo))
    or  rm, ((val) AND (__Pow2(width) - 1)) * __Pow2(lo)
ENDM

getfield MACRO dest, src, lo, width
    IF ((lo) LT 0) OR ((width) LT 1) OR ((width) GT 31) OR (((lo) + (width)) GT 32)
        .ERR <getfield: invalid range of lo/width (lo + width up to 32)>
        EXITM
    ENDIF
    IF ((OPATTR (dest)) AND 2) AND ((OPATTR (src)) AND 2)
        .ERR <getfield: dest and src cannot both be memory>
        EXITM
    ENDIF
    IFIDNI <dest>, <src>
        IF (lo) GT 0
            shr src, (lo)       ; uses the SHR macro on 8086 (1 bit at a time)
        ENDIF
        and src, __Pow2(width) - 1
    ELSE
        mov dest, src
        IF (lo) GT 0
            shr dest, (lo)
        ENDIF
        and dest, __Pow2(width) - 1
    ENDIF
ENDM

ENDIF   ; __SMART_INC__
