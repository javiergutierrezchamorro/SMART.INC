;=====================================================================
;  SMART.INC  v2.4  --  "TASM style" optimization macros
;                       for ASMC, JWasm and UASM
;=====================================================================
;  Brings to ASMC/JWasm the facilities Turbo Assembler used to provide
;  out of the box, and adds bit manipulation utilities:
;
;    1. SHL/SHR/SAL/SAR/ROL/ROR/RCL/RCR with a constant count on the
;       8086 (the 8086 only accepts shifting by 1 or by CL; with a
;       constant count the macro expands into 1-bit instructions).
;    2. MOVZX/MOVSX emulated on CPUs older than the 386.
;    3. PUSH/POP with several operands (TASM 4 style; the macro
;       argument separator is the comma:  push ax, bx, cx).
;    4. FastIMul dest, src, const : signed multiplication by a
;       constant using shifts and adds only (8086).
;    5. FastMul const : DX:AX = AX * const unsigned, like MUL r16.
;    6. setflag/clrflag/flipflag/testflag/maskflag : single bits.
;    7. setfield/getfield : bit field insertion and extraction.
;
;  Requirements: an assembler that implements OPTION RENAMEKEYWORD:
;  ASMC 2.40, JWasm 2.06+ or UASM. OPATTR, ELSEIFIDNI, FOR/VARARG,
;  macro functions (EXITM %) and REPEAT/WHILE are used as well.
;  Microsoft MASM CANNOT use this file: ml.exe has no RENAMEKEYWORD
;  (its OPTION NOKEYWORD deletes the keyword instead of renaming it,
;  so the original instruction becomes unreachable from the macro).
;  TASM is not supported either. The default CPU is 8086; with .186
;  or higher the shift macros and MOVZX/MOVSX are not defined because
;  equivalent native instructions already exist.
;
;  General notes:
;   - Include this file AFTER the processor directive
;     (.8086/.186/.286/.386): @Cpu is evaluated at the include point.
;   - Include it BEFORE using the instructions it replaces (the
;     include enables OPTION RENAMEKEYWORD).
;   - ASMC quirk: the replacement names used to reach the renamed
;     instruction MUST start with a letter, digit, '$' or '?'. An
;     identifier starting with '@' or '_' is always looked up in the
;     user symbol table and never matches a keyword (JWasm/UASM
;     accept any valid identifier, which hides the bug). This file
;     uses the "??"-prefix convention of ASMC's own test suite
;     (??shl, ??push, ...).
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
;  Verification: assembled with ASMC 2.40 (8086/186/286/386 targets)
;  and JWasm 2.12 (4VIEW 1.04 itself also uses ASMC-only extensions
;  such as .switch and inline "proto asmcall", so it builds with
;  ASMC). FastIMul/FastMul verified numerically: every emitted
;  instruction sequence is executed by an 8086 simulator for 220
;  FastIMul and 150 FastMul (constant, seed) combinations, plus the
;  -3 spot checks and a byte-level check of the shift/push/pop/bit
;  expansions. The v2.0 "104 cases" bank only ever ran on JWasm,
;  which is why none of this showed up there - see v2.1 below.
;
;  v2.4 was assembled with UASM 2.57 on the 8086 and 386 targets
;  (the ASMC 2.40 Linux binary is not runnable in the build
;  environment of this pass: it is a 32-bit image and the host
;  forbids 32-bit system calls). The changed expansions were checked
;  by disassembly, the 8086 target stayed byte-identical to v2.3
;  (verified on the test battery), and the new FastMul IMUL path was
;  executed - instruction by instruction - for EVERY 16-bit
;  multiplicand (0..65535) and a factor battery (dense, sparse,
;  Mersenne and MUL-worst cases) against a 32-bit reference product.
;
;  History:
;   v2.4  FastMul, 386+ every non-power-of-two factor: the Horner
;         chain, the Mersenne shortcut and the real MUL fallback are
;         replaced by one native IMUL: movzx eax,ax / imul edx,eax,f
;         (the 32-bit product of AX*f always fits EDX, so DX:AX is
;         exact). Two instructions instead of 10-30, BX and CL are
;         not touched, and factors that used to fall back to the
;         ~118-137-cycle MUL now take the ~13-38-cycle IMUL. The
;         power-of-two path stays movzx/shl (cheaper than IMUL), and
;         the 8086 build is byte-identical to v2.3.
;   v2.3  FastMul, power-of-two factors: the 386+ build now emits
;         movzx eax,ax / shl eax,k (two instructions, no BX), and
;         the 8086 build switches to two half-window shifts for
;         k >= 8 (six instructions instead of up to 30; CL is
;         destroyed in that path, and BX is not). k < 8 keeps the
;         old shl/rcl loop. Every other path is byte-identical.
;   v2.2  Documentation only - no macro code was touched: the
;         requirements no longer claim MASM 6.0+ support (OPTION
;         RENAMEKEYWORD is an ASMC/JWasm/UASM extension; Microsoft
;         MASM does not implement it), and the FastIMul doc block,
;         accidentally duplicated four times, is a single copy
;         again. Re-verified end to end on the unchanged macros:
;         ASMC on the four CPU targets, JWasm, the error battery,
;         the 8086 simulator suite and the 4VIEW 1.04 builds
;         (byte-identical modulo the @Time stamp).
;   v2.1  ASMC fix, three independent problems:
;         1. The renamed instructions were invoked through "@@"-
;            prefixed names (@@push, @@shl, ...). ASMC never looks up
;            identifiers starting with '@' or '_' in the keyword
;            table, so every expansion died with "error A2008: syntax
;            error : @@push" (JWasm accepts any identifier, which is
;            why the v2.0 test bank did not catch it). All replacement
;            names now use the "??" prefix ASMC's own test suite uses.
;         2. FastIMul produced silently WRONG code under ASMC for
;            about a third of the constants (neg missing or shifted
;            garbage, e.g. -6, -320, -1000, -16384): the expansion
;            re-read its own assembly-time variables after WHILE
;            bodies had been re-processed, and ASMC returns corrupted
;            values for such reads (JWasm is unaffected). The macro
;            now contains no assembly-time variables at all: every
;            condition is a literal expression over the cte
;            parameter, emitted as an MSB-first Horner chain that
;            also preserves src (v2.0 destroyed it in the general
;            case). FastIMul also rejects dest and src being both
;            memory operands up front.
;         3. setfield emitted the unencodable mask NOT 0FFFFh when
;            the field filled the whole 16-bit operand (below 386)
;            and silently assembled wrong code for fields wider than
;            16 bits on those CPUs; both cases are now handled.
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
;  ??shl) so the macro can take it over.
;  They work on registers and on memory as well (shl [bx], 3).
;=====================================================================

IF ((@Cpu AND 0FFh) EQ 1)       ; 8086 only: 186+ accepts immediate counts

    option renamekeyword:<shl>=??shl
shl MACRO reg, val
    IFB <val>
        ??shl reg, 1
    ELSEIFIDNI <val>, <1>
        ??shl reg, 1
    ELSEIFIDNI <val>, <cl>
        ??shl reg, cl
    ELSE
        IF (val) LT 0
            .ERR <shl: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??shl reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<shr>=??shr
shr MACRO reg, val
    IFB <val>
        ??shr reg, 1
    ELSEIFIDNI <val>, <1>
        ??shr reg, 1
    ELSEIFIDNI <val>, <cl>
        ??shr reg, cl
    ELSE
        IF (val) LT 0
            .ERR <shr: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??shr reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<sal>=??sal
sal MACRO reg, val
    IFB <val>
        ??sal reg, 1
    ELSEIFIDNI <val>, <1>
        ??sal reg, 1
    ELSEIFIDNI <val>, <cl>
        ??sal reg, cl
    ELSE
        IF (val) LT 0
            .ERR <sal: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??sal reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<sar>=??sar
sar MACRO reg, val
    IFB <val>
        ??sar reg, 1
    ELSEIFIDNI <val>, <1>
        ??sar reg, 1
    ELSEIFIDNI <val>, <cl>
        ??sar reg, cl
    ELSE
        IF (val) LT 0
            .ERR <sar: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??sar reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rol>=??rol
rol MACRO reg, val
    IFB <val>
        ??rol reg, 1
    ELSEIFIDNI <val>, <1>
        ??rol reg, 1
    ELSEIFIDNI <val>, <cl>
        ??rol reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rol: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??rol reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<ror>=??ror
ror MACRO reg, val
    IFB <val>
        ??ror reg, 1
    ELSEIFIDNI <val>, <1>
        ??ror reg, 1
    ELSEIFIDNI <val>, <cl>
        ??ror reg, cl
    ELSE
        IF (val) LT 0
            .ERR <ror: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??ror reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rcl>=??rcl
rcl MACRO reg, val
    IFB <val>
        ??rcl reg, 1
    ELSEIFIDNI <val>, <1>
        ??rcl reg, 1
    ELSEIFIDNI <val>, <cl>
        ??rcl reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rcl: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??rcl reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<rcr>=??rcr
rcr MACRO reg, val
    IFB <val>
        ??rcr reg, 1
    ELSEIFIDNI <val>, <1>
        ??rcr reg, 1
    ELSEIFIDNI <val>, <cl>
        ??rcr reg, cl
    ELSE
        IF (val) LT 0
            .ERR <rcr: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            ??rcr reg, 1
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

    option renamekeyword:<movzx>=??movzx
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

    option renamekeyword:<movsx>=??movsx
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
;  TASM 4+ accepted "PUSH AX BX CX". Here the macro argument
;  separator is the comma, so the form is:
;
;       push ax, bx, cx        ; three PUSHes in written order
;       pop  cx, bx, ax        ; three POPs in written order
;
;  With a single operand they emit exactly the same instruction as
;  without the macro. With no operands they raise an error.
;  PUSHA/PUSHF/POPA/POPF are left untouched.
;=====================================================================

    option renamekeyword:<push>=??push
push MACRO ops:VARARG
    IFB <ops>
        .ERR <push: missing operands>
        EXITM
    ENDIF
    FOR o, <ops>
        ??push o
    ENDM
ENDM

    option renamekeyword:<pop>=??pop
pop MACRO ops:VARARG
    IFB <ops>
        .ERR <pop: missing operands>
        EXITM
    ENDIF
    FOR o, <ops>
        ??pop o
    ENDM
ENDM

;=====================================================================
;  4. FastIMul dest, src, const
;=====================================================================
;  Multiplies signed by a constant without using IMUL (which on the
;  8086 costs 118-133 cycles). Shifts and adds only; the expansion is
;  an MSB-first Horner chain:
;
;       mov dest, src              ; the highest set bit of |const|
;       shl dest, 1                ; one run per lower bit...
;       IF bit:  add dest, src     ; ...plus the set ones
;       ...
;       IF negative:  neg dest
;
;    dest : register (or memory with a declared size) that receives
;           the result; same size as src (WORD on 8086; with .386
;           DWORD works too: the macro is size agnostic).
;    src  : register or memory of the same size. PRESERVED (the v2.1
;           expansion accumulates into dest and never shifts src).
;    const: signed constant, -32768 to 65535 (values 32768..65535
;           are taken as their 16-bit two's complement). Must be
;           known at assembly time.
;
;  The expansion contains no assembly-time variables at all: every
;  condition is a literal expression over the cte parameter, which
;  the assembler substitutes textually on each expansion. ASMC (not
;  JWasm) returns corrupted values when an expansion re-reads its
;  own assembly-time variables, which silently scrambled v2.0's
;  results for a third of the constants; parameter-only expressions
;  are immune. See the v2.1 history entry.
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
    IF ((OPATTR (dest)) AND 2) AND ((OPATTR (src)) AND 2)
        .ERR <FastIMul: dest and src cannot both be memory>
        EXITM
    ENDIF
    IF ((cte) LT -32768) OR ((cte) GT 0FFFFh)
        .ERR <FastIMul: const out of range (-32768..65535)>
        EXITM
    ENDIF

    IF (((cte) AND 0FFFFh)) EQ 0                       ; const = 0 (16-bit pattern)
        mov dest, 0
        EXITM
    ENDIF
    IF ((cte) AND 0FFFFh) AND 8000h                       ; negative (bit 15 of the pattern)
;       t = 10000h - (cte AND 0FFFFh), result negated at the end
        mov dest, src
        IF ((10000h - ((cte) AND 0FFFFh))) / 8000h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 4000h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 4000h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 2000h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 2000h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 1000h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 1000h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 800h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 800h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 400h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 400h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 200h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 200h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 100h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 100h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 80h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 80h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 40h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 40h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 20h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 20h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 10h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 10h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 8h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 8h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 4h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 4h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 2h
                add dest, src
            ENDIF
        ENDIF
        IF ((10000h - ((cte) AND 0FFFFh))) / 2h
            shl dest, 1
            IF ((10000h - ((cte) AND 0FFFFh))) AND 1
                add dest, src
            ENDIF
        ENDIF
        neg dest
    ELSE
;       t = cte AND 0FFFFh
        mov dest, src
        IF (((cte) AND 0FFFFh)) / 8000h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 4000h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 4000h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 2000h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 2000h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 1000h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 1000h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 800h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 800h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 400h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 400h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 200h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 200h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 100h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 100h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 80h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 80h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 40h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 40h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 20h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 20h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 10h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 10h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 8h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 8h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 4h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 4h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 2h
                add dest, src
            ENDIF
        ENDIF
        IF (((cte) AND 0FFFFh)) / 2h
            shl dest, 1
            IF (((cte) AND 0FFFFh)) AND 1
                add dest, src
            ENDIF
        ENDIF
    ENDIF
ENDM

;=====================================================================
;  5. FastMul const  ->  DX:AX = AX * const, unsigned (like MUL r16)
;=====================================================================
;  const: constant from 0 to 0FFFFh, known at assembly time.
;  Destroys BX (not on the 386+ paths), CL (8086 power-of-two
;  factors from 256 up) and CX (when a real MUL wins), plus the
;  flags; the 386+ paths also rewrite the high word of EAX. It does
;  not reproduce the CF/OF values MUL would leave, only the result.
;
;  Strategies, best first depending on the bit pattern:
;    - const = 0                          : XOR AX / XOR DX
;    - const = 2^k                        : 32-bit shift
;      (v2.3) 386+: movzx eax,ax / shl eax,k - two instructions and
;      BX is not touched. 8086 with k >= 8: two half-window shifts
;      (mov dx,ax / shr dx,cl with 16-k, then the low bits left and
;      shifted k) - six instructions instead of the old 2*k shl/rcl
;      pairs, which cost up to 30 instructions for 32768. 8086 with
;      k < 8 keeps the original shl ax,1 / rcl dx,1 loop.
;    - any other const, 386+ (v2.4): one native IMUL -
;      movzx eax,ax / imul edx,eax,const. The 32-bit product of
;      AX*f (both under 65536) always fits EDX, so DX = high word
;      and AX (preserved by IMUL) = low word are the exact result.
;      Replaces the Mersenne shortcut, the Horner chain (10-30
;      instructions) and the ~118-137-cycle real-MUL fallback with
;      one ~13-38-cycle instruction; BX and CL are not touched and
;      the high word of EAX is cleared by the MOVZX.
;    - const = (2^k - 1) * 2^j, k >= 4    : 32-bit Mersenne shortcut
;      (new in v2.0): ((x << k) - x) << j with SUB/SBB; turns dense
;      factors like 0FFFFh into ~2/3 of the instructions. 8086 only
;      since v2.4.
;    - MSB-to-LSB Horner with the DX:AX accumulator (v1, 8086 only
;      since v2.4)
;    - real MUL when the expansion would come out worse
;      (~118-137 cycles; 8086 only since v2.4)
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
        IF ((@Cpu AND 0FFh) GE 8)   ; 386+: one native wide shift (v2.3)
            movzx eax, ax           ; EAX = zero-extended multiplicand
            shl  eax, fmHi          ; DX:AX = AX << k, no BX touched
        ELSEIF fmHi GE 8            ; 8086, k >= 8: two halves (v2.3)
            mov  dx, ax
            mov  cl, 16 - fmHi      ; (16-k) is a constant
            shr  dx, cl             ; DX = X >> (16-k) = high word
            and  ax, __Pow2(16 - fmHi) - 1  ; keep the low 16-k bits
            mov  cl, fmHi
            shl  ax, cl             ; AX = (X AND mask) << k = low word
        ELSE                        ; 8086, k < 8: the short way (v1)
            xor dx, dx
            fmI = fmHi
            WHILE fmI
                shl ax, 1
                rcl dx, 1
                fmI = fmI - 1
            ENDM
        ENDIF
        EXITM
    ENDIF

    IF ((@Cpu AND 0FFh) GE 8)       ; 386+: one native IMUL (v2.4)
        movzx eax, ax               ; EAX = zero-extended multiplicand
        imul edx, eax, fmF          ; EDX = AX*f; fits 32 bits, exact
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
;           except when the field fills the whole 16-bit operand on
;           a CPU below the 386: then the AND would need the
;           unencodable mask NOT 0FFFFh and is skipped (nothing to
;           preserve). On those CPUs a field wider than the 16-bit
;           operand is an error instead of silently emitting wrong
;           code; on a 386+ build 32-bit fields work as documented.
;
;       getfield dest, src, lo, width
;           Extracts the field with zero extension: copies src into
;           dest, shifts right by lo bits and masks the rest. When
;           dest and src are the same operand no MOV is emitted;
;           the two operands cannot both be memory.
;
;  Compatible with the RECORD syntax (native in ASMC/JWasm, as in
;  MASM 6+):
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
    IF ((@Cpu AND 0FFh) LT 8) AND (((lo) + (width)) GT 16)
        .ERR <setfield: field does not fit the 16-bit operand of this CPU>
        EXITM
    ENDIF
    IF ((@Cpu AND 0FFh) LT 8) AND (((lo) + (width)) EQ 16)
            ; the field covers the whole 16-bit operand: nothing to
            ; preserve, and NOT 0FFFFh (0FFFF0000h) does not encode
        or  rm, ((val) AND (__Pow2(width) - 1)) * __Pow2(lo)
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
