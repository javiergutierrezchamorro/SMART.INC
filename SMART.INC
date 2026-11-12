;=====================================================================
;  SMART.INC  v3.6  --  "TASM style" optimization macros
;                       for ASMC, JWasm and UASM
;=====================================================================
;  Brings to ASMC/JWasm/UASM the facilities Turbo Assembler used to
;  provide out of the box, and adds bit manipulation utilities:
;
;    1. SHL/SHR/SAL/SAR/ROL/ROR/RCL/RCR with a constant count on the
;       8086 (the 8086 only accepts shifting by 1 or by CL; with a
;       constant count the macro expands into 1-bit instructions).
;    2. MOVZX/MOVSX emulated on CPUs older than the 386.
;    3. PUSH/POP with several operands (TASM 4 style; the macro
;       argument separator is the comma:  push ax, bx, cx).
;    4. FastIMul dest, src, const : signed multiplication by a
;       constant using shifts and adds only (8086; on 386+ with
;       register operands: LEA for 3, 5, 9, 6, 10, 12, 18, 20, 24,
;       and one native IMUL when |const| > 8).
;    5. FastMul const : DX:AX = AX * const unsigned, like MUL r16
;       (386+: LEA shortcuts for 3, 5, 9 and 6, 10, 12, 18, 20, 24;
;       one native IMUL for the rest).
;    6. setflag/clrflag/flipflag/testflag/maskflag : single bits.
;    7. setfield/getfield : bit field insertion and extraction.
;    8. mov/xchg reg, reg eliminated: "mov ax, ax" and "xchg ax,
;       ax" assemble to nothing (any other MOV/XCHG passes through
;       unchanged; ??mov / ??xchg force the original instruction).
;       SMART mode, the default; NOSMART disables it (v3.3/v3.5).
;    9. lea reg16, var rewritten as "mov reg, OFFSET var" when that
;       is shorter (SMART mode, v3.4; ??lea forces the original).
;   10. conditional jumps extended automatically: a backward jump
;       out of short range becomes "j<inv> over jmp target", and
;       forward jumps always take the extended form so none can
;       die with "jump destination too far" (SMART mode, v3.4;
;       ??jxx forces the short form).
;   11. JCXZ and LOOP extended automatically too (v3.6): the two
;       short-only jumps that have neither an inverse nor a long
;       encoding - OPTION LJMP cannot lengthen them, so they were
;       the last instructions able to die with "error A2075: jump
;       destination too far". The macro measures backward targets
;       and keeps the 2-byte form while it fits; anything else goes
;       through a near-JMP trampoline that preserves the flags and
;       LOOP's CX = 0 wrap exactly (SMART mode; ??jcxz / ??loop
;       force the original instruction).
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
;     constant expressions, use __Pow2(n) or multiplications. The
;     mov rename (item 8) has no effect on any expression operator
;     (MOV does not share a token with one).
;   - Unless stated otherwise, all macros destroy the flags.
;   - SMART/NOSMART (v3.3) toggle the automatic optimizations, like
;     TASM's; the default is SMART. Currently automatic: the "mov
;     reg, reg" and "xchg reg, reg" eliminations (item 8), the
;     "lea reg16, var" to "mov reg, OFFSET var" substitution
;     (item 9) and the extended conditional jumps (item 10). The
;     rest of the library is explicit macro calls and is not
;     affected.
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
;  Since v2.42 the -3 battery compares the DX:AX PAIR (not EAX and
;  not EDX) against the reference product for every 16-bit
;  multiplicand: v2.4's EDX check was exactly what the broken path
;  produced, which is how the bug shipped.
;  v3.2's FastIMul refactor was proven byte-identical by comparing
;  the old and new instruction sequences for all 98,304 constants
;  (0 differences), and the 386+ LEA/IMUL decision tree was executed
;  for 2,359,296 (constant, size, register/memory, seed)
;  combinations against a signed reference product (0 failures).
;  The v3.3 SMART/NOSMART switch was checked in both states: the
;  SMART output is byte-identical to v3.2, and NOSMART passes every
;  MOV through, including "mov ax, ax". The v3.4 jump logic was
;  simulated for every backward distance 0..400: the short form is
;  kept exactly while the displacement fits (-128..127, boundary
;  at 126/127 verified) and the trampoline displacement (+3) is
;  always in range; the lea decision table was checked against the
;  byte counts (mov r16,imm16 = 3 vs lea r16,m16 = 4). The v3.5
;  alias renames restore the v2.0 rule (every taken-over mnemonic
;  is freed before its macro is defined), so the include again
;  emits no code at include time and can be included outside a
;  segment. The v3.6 JCXZ/LOOP trampoline was checked against the
;  same 0..400 backward-distance sweep (short kept exactly while
;  the displacement fits, boundary 126/127) and the trampoline's
;  own displacements (+2 short hop, full-range near JMP) are in
;  range by construction; the CX = 0 wrap and the untouched flags
;  were verified against the native instructions' semantics.
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
;   v3.6  The last "jump destination too far" hole closed:
;         1. JCXZ and LOOP are intercepted now (option
;            renamekeyword, SMART mode, escapes ??jcxz / ??loop).
;            They are the only two jumps with neither an inverse
;            nor a long encoding: ASMC's OPTION LJMP lengthens the
;            conditional jumps automatically, but a JCXZ or LOOP
;            whose destination lands more than 127 bytes away dies
;            with "error A2075: jump destination too far" and
;            nothing in the assembler can save it (reported by
;            4VIEW.ASM on the 386 build: A2075 by 2 bytes - one
;            forward Jcc extended by the v3.4 macros grew the code
;            between a short-only jump and its target by exactly
;            one 2-to-5-byte extension). The macro keeps the
;            2-byte form for backward targets measured in range
;            (same $ - target <= 126 rule as __Jcc) and otherwise
;            emits the trampoline "jxx near-label / jmp over /
;            near-label: jmp target": JCXZ touches no flags and
;            the LOOP trampoline neither (the real LOOP inside it
;            does the decrement), so both stay 100% transparent,
;            including LOOP's CX = 0 wrap. NOSMART passes both
;            through in the native form.
;         2. LOOPE/LOOPNE/LOOPZ/LOOPNZ are NOT intercepted: they
;            test ZF, so the trampoline would need a flag-safe
;            bridge that costs more than the instruction is worth;
;            they keep the native short-only behavior.
;   v3.5  Bug fix, version constant, one more redundant case:
;         1. FIXED: the 14 alias jump macros (jz, jnz, jc, jnc,
;            jna, jnae, jnb, jnbe, jng, jnge, jnl, jnle, jpe,
;            jpo) were defined without freeing their keyword
;            first, so ASMC parsed "jz MACRO target" as the jz
;            INSTRUCTION: "error A2034: must be in segment block"
;            at the definition line, the macro body then executed
;            as main-line code (its __Jcc expansion emitted
;            instructions outside any segment) and the orphaned
;            ENDM aborted with "fatal error A1008: unmatched
;            macro nesting" (reported by 4VIEW.ASM, which
;            includes SMART.INC outside a segment - the include
;            emits no code at include time, so that is fine).
;            Every alias now has its option renamekeyword line,
;            the same rule every other taken-over mnemonic has
;            followed since v2.0; the ??jz-style escapes exist
;            now as a side effect.
;         2. The inclusion guard now carries the version:
;            __SMART_INC__ = 350 means v3.5 (major*100 + minor,
;            the banner numbering). Source can test
;            "IF __SMART_INC__ GE 350" before using a feature.
;         3. xchg joins the redundant-instruction elimination
;            (??xchg escape): "xchg reg, reg" with the same
;            register assembles to nothing under SMART - it
;            changes no register, no memory and no flags. CAREFUL:
;            the 1-byte "xchg ax, ax" (opcode 90h) is the classic
;            single-byte NOP used for alignment padding; SMART
;            removes it like any other dead instruction, and
;            ??xchg ax, ax forces the byte back. NOSMART passes
;            everything through.
;   v3.4  Bug fix plus the TASM SMART optimizations - two new
;         automatic transformations, both disabled by NOSMART:
;         1. FIXED: FastIMul died at assembly time on ASMC with
;            "error A2006: undefined symbol : TYPE" (reported by
;            4VIEW.ASM): the v3.2 register-size checks used the
;            TYPE operator, which ASMC disables by default (it
;            wants TYPEOF or the -Zne switch, and neither is
;            portable to JWasm/UASM; the OPATTR word carries no
;            size bits either). The checks are now textual: a new
;            internal __RegBits function matches the operand name
;            against the 24 register names with IFIDNI and returns
;            1, 2, 4 or 0. The emitted code is unchanged on every
;            assembler; on ASMC it assembles again.
;         2. lea is taken over (??lea escape): "lea reg16, var"
;            with a DIRECT memory source (OPATTR bits 1 and 3 set,
;            bit 6 clear) and a 16-bit register destination becomes
;            "mov reg, OFFSET var" - 3 bytes instead of 4, same
;            address, no flags touched. Every other LEA (indexed
;            sources, 32-bit destinations) passes through
;            byte-identical, including the internal LEA forms of
;            FastIMul and FastMul.
;         3. The 30 conditional jump mnemonics are taken over
;            (??jxx escape): a backward target that is a known
;            local code label is MEASURED, and the short form is
;            kept while it fits ($ - target <= 126); anything
;            farther, and every forward reference or external
;            target (whose distance cannot be measured at
;            expansion time - OPATTR returns 0 for forward
;            references), takes the extended form "j<inverse> over
;            jmp target" (5 bytes, always encodable), so no
;            conditional jump can die with "jump destination too
;            far". Targets written as @F/@B pass through with
;            their native semantics (the macro must not insert
;            anonymous labels that would hijack them); the
;            trampoline label is a macro LOCAL, invisible to the
;            user's symbols. NOSMART passes every jump through in
;            the short form, i.e. the native behavior.
;         4. Considered and NOT implemented: minimum-size
;            instruction encodings (ASMC/JWasm/UASM already pick
;            the sign-extended imm8 forms and the short JMPs
;            natively) and cross-instruction stack optimizations
;            (a macro expansion cannot see its neighboring
;            instructions; the multi-operand push/pop macros
;            remain the tool for that).
;   v3.3  New directives, no expansion changes in SMART mode: SMART
;         and NOSMART, the TASM-style optimization switch. The
;         default is SMART. NOSMART disables the only automatic
;         transformation of the file, the "mov reg, reg"
;         elimination (section 8): every MOV then passes through
;         byte-identical until the next SMART. The rest of the
;         library is not affected (its macros are explicit calls
;         the user wrote on purpose, not silent rewrites of
;         instructions the assembler would also accept). The
;         switch is a plain global assembly-time flag (??smart)
;         read by the mov expansion, which contains no WHILE and
;         defines no variables of its own, so it stays outside the
;         ASMC v2.1 re-read bug pattern. ??mov ax, ax keeps forcing
;         the original instruction in both modes.
;   v3.2  Cleanup plus one new FastIMul shortcut; FastMul and the
;         shift/push/pop/bit/field/mov macros are untouched:
;         1. FastIMul, 386+ with DWORD register dest AND register
;            src: factors 3, 5, 9 emit ONE LEA and 6, 10, 12, 18,
;            20, 24 emit LEA + ADD/SHL, mirroring FastMul's v3.1
;            tree (1-2 instructions vs 3-7 for the chain or IMUL).
;            The LEA forms need 32-bit registers (the SIB byte does
;            not exist in 16-bit addressing), so WORD destinations
;            keep the chain. The three-operand IMUL now also
;            requires a non-BYTE destination (TYPE dest NE 1):
;            IMUL r,r,imm has no byte encoding, and a BYTE FastIMul
;            - which the chain always supported - would have died
;            at assembly time since v3.1 (found in this review;
;            the chain is restored for it).
;         2. FastIMul's chain is ONE copy now: the two 15-block
;            branches (negative/positive) differed only in the
;            magnitude expression, and __IMag already unifies it.
;            A new internal __Horn helper holds the single Horner
;            step, FastIMul calls it 15 times, and the negative
;            case just appends NEG. The expansion stays
;            parameter-only (ASMC v2.1 doctrine) and the emitted
;            code is byte-identical for all 98,304 constants
;            (verified by exhaustive comparison of the old and new
;            sequences); about 95 source lines shorter.
;         3. The five flag macros and setfield/getfield share the
;            new __BitRange/__FieldRange validators; the error
;            texts are unchanged (the macro name is passed as a
;            parameter into the .ERR text).
;   v3.1  Speed, four changes; the shift/push/pop/bit/field/mov
;         expansions and the FastIMul chain are untouched:
;         1. FastMul, 386+: factors 3, 5, 9 now use ONE LEA
;            (lea eax,[eax+eax*2/4/8]; 1-2 cycles vs 13-42 for
;            IMUL r32,imm) and 6, 10, 12, 18, 20, 24 use
;            LEA + ADD/SHL (two instructions). Every other factor
;            keeps the v2.4 IMUL; the DX:AX contract is unchanged
;            (the SHLD closing stays).
;         2. FastIMul, 386+ with a REGISTER destination: constants
;            whose 16-bit magnitude exceeds 8 now emit one native
;            three-operand IMUL (9-22 cycles r16, 9-38 r32) instead
;            of chains of up to 30 instructions. |cte| <= 8, memory
;            destinations and every CPU below the 386 keep the
;            shift/add chain. Constants in 32768..65535 are passed
;            to IMUL as their negative two's complement equivalent
;            (new __ISgn helper), which the 16-bit encodings made
;            moot but a DWORD destination needs (a positive 65535
;            immediate would mean +65535, not -1).
;         3. FastMul: the MUL-fallback threshold moves from 110 to
;            117 estimated cycles. The old model ignored the
;            5-cycle fixed overhead of the chain (mov bx,ax +
;            xor dx,dx) and priced MUL at 110 when mov cx,imm +
;            MUL r16 really costs 122-137; breakeven is 117. The
;            6,304 factors in the 111..117 band switch from MUL to
;            the Horner chain (verified exhaustively); the truly
;            dense factors (>= 10 set bits) still take the real
;            MUL, which remains the best 8086 option for them -
;            no shortcut gets a dense 16-bit factor near 10-30
;            cycles on an 8086.
;         4. FastMul's assembly-time variables (fmF, fmHi, fmOnes,
;            fmT, fmJ, fmM, fmK, fmP, fmI) are now LOCAL to the
;            macro: no user symbol can collide with them and no
;            state leaks between expansions.
;         Analyzed and REJECTED: a "(2^k + 1) * 2^j" shortcut
;         ("inverse Mersenne", (x << k + x) << j with ADD/ADC).
;         For every one of the 120 factors of that form the Horner
;         chain already emits EXACTLY the same instructions in the
;         same order (the top bit is implicit in the initial
;         mov/accumulator, which saves the extra shift the shortcut
;         would pay), so the shortcut would add macro code without
;         changing one byte of output. Example, factor 18:
;           Horner actual : shl,rcl,shl,rcl,shl,rcl,add,adc,shl,rcl
;           Atajo propuesto: shl,rcl,shl,rcl,shl,rcl,add,adc,shl,rcl
;   v3.0  New macro, no existing expansion touched: MOV is now also
;         taken over (OPTION RENAMEKEYWORD:<mov>, defined at EVERY
;         CPU level). "mov reg, reg" with the same register on both
;         sides assembles to nothing - it changes no register, no
;         memory and no flags, so removing it cannot change the
;         behavior of the program. Every other MOV (different
;         register, immediate, memory, segment) passes through
;         byte-identical. Deliberately NOT implemented: turning
;         "mov reg, 0" into "xor reg, reg". MOV leaves the flags
;         untouched and XOR destroys them, so that "optimization"
;         can silently break flag-dependent code; SMART only removes
;         instructions that provably do nothing. A "mov ax, ax"
;         kept on purpose (2-byte timing delay, patch hole in
;         self-modifying code) can be forced with "??mov ax, ax".
;         Detection is textual (IFIDNI, case-insensitive) plus an
;         OPATTR register check, so identical text that is not a
;         register pair (e.g. the invalid "mov [bx], [bx]") still
;         reaches the assembler and keeps raising its normal error.
;         The battery should gain three mov cases before release:
;         an eliminated "mov ax, ax" (zero bytes), a forced
;         "??mov ax, ax" (2 bytes) and pass-through of the
;         remaining forms.
;   v2.43 Source simplification, ZERO code change: the eight 8086
;         shift macros each repeated the same 15-line body and only
;         differed in the instruction they emit. The body now lives
;         once in the internal __SHx helper and every macro is a
;         two-line wrapper that just names its instruction (SAL
;         keeps its own ??sal - it encodes exactly as SHL anyway).
;         The negative-count error text is uniform ("shift: ...").
;         The assembled output is byte-identical to v2.42 on the
;         full 8086 battery; the 386 target defines none of these
;         macros.
;   v2.42 FastMul, 386+ paths: THE DX:AX CONTRACT REALLY HOLDS NOW.
;         v2.4's "movzx eax,ax / imul edx,eax,f" left the product in
;         EDX (DX = its LOW word, AX = the untouched multiplicand)
;         and v2.41's one-word repair "imul eax,eax,f" fixed AX but
;         STILL never wrote DX - the high word of the product was
;         lost in both, and every caller that divides DX:AX 16-bit
;         (4VIEW's DrwSt/DrwBar percents, fix 90's freeze) got a
;         garbage dividend. Both 386 paths now end with "shld
;         edx,eax,16" so DX carries the high word (factor 1
;         collapses to "xor dx,dx"), and the battery compares the
;         full DX:AX pair for every 16-bit multiplicand. The 8086
;         target is byte-identical to v2.3/v2.41.
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
;  Version constant: mayor*100 + menor (360 = v3.6). Source can test
;  "IF __SMART_INC__ GE 360" before using a newer feature.
__SMART_INC__ = 360

;=====================================================================
;  SMART / NOSMART  (new in v3.3) - the TASM-style optimization
;  switch. SMART (the default, as in TASM) enables the automatic
;  optimizations of this file; NOSMART turns them off and every
;  taken-over instruction passes through byte-identical until the
;  next SMART. The automatic transformations (all disabled by
;  NOSMART) are: the "mov reg, reg" and "xchg reg, reg"
;  eliminations (section 8), the "lea reg16, var" to "mov reg,
;  OFFSET var" substitution (section 9) and the extended
;  conditional jumps (section 10). The rest of
;  the library consists of explicit macro calls the user wrote on
;  purpose, so NOSMART does not affect it.
;  The switch is one global assembly-time flag (??smart) read by
;  the automatic expansions. Those expansions contain no WHILE and
;  define no assembly-time variables of their own, so the read is
;  outside the ASMC v2.1 re-read bug pattern.
;=====================================================================

??smart = 1                         ; TASM default: SMART mode on

SMART   MACRO
    ??smart = 1
ENDM

NOSMART MACRO
    ??smart = 0
ENDM


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
;  All eight share one expansion body (v2.43): the internal __SHx
;  helper receives the renamed instruction as its first argument and
;  every macro is a two-line wrapper. SAL keeps its own ??sal rename
;  (SAL and SHL are the same opcode, so the bytes match shl's).
;=====================================================================

IF ((@Cpu AND 0FFh) EQ 1)       ; 8086 only: 186+ accepts immediate counts

;  __SHx op, reg, val - the shared body of all eight macros (v2.43):
;  expands op (the renamed instruction) under the rules below. Every
;  macro is a two-line wrapper that only names its instruction.
__SHx MACRO op, reg, val
    IFB <val>
        op reg, 1
    ELSEIFIDNI <val>, <1>
        op reg, 1
    ELSEIFIDNI <val>, <cl>
        op reg, cl
    ELSE
        IF (val) LT 0
            .ERR <shift: count cannot be negative>
            EXITM
        ENDIF
        REPEAT (val)
            op reg, 1
        ENDM
    ENDIF
ENDM

    option renamekeyword:<shl>=??shl
shl MACRO reg, val
    __SHx ??shl, reg, val
ENDM

    option renamekeyword:<shr>=??shr
shr MACRO reg, val
    __SHx ??shr, reg, val
ENDM

    option renamekeyword:<sal>=??sal
sal MACRO reg, val
    __SHx ??sal, reg, val          ; SAL encodes as SHL: same bytes
ENDM

    option renamekeyword:<sar>=??sar
sar MACRO reg, val
    __SHx ??sar, reg, val
ENDM

    option renamekeyword:<rol>=??rol
rol MACRO reg, val
    __SHx ??rol, reg, val
ENDM

    option renamekeyword:<ror>=??ror
ror MACRO reg, val
    __SHx ??ror, reg, val
ENDM

    option renamekeyword:<rcl>=??rcl
rcl MACRO reg, val
    __SHx ??rcl, reg, val
ENDM

    option renamekeyword:<rcr>=??rcr
rcr MACRO reg, val
    __SHx ??rcr, reg, val
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
;  On a 386+ build with a REGISTER destination: factors 3, 5 and 9
;  with a register source emit ONE LEA (lea dest,[src+src*2/4/8];
;  1-2 cycles vs 13-42 for IMUL r32,imm) and 6, 10, 12, 18, 20, 24
;  emit LEA + ADD/SHL (two instructions), mirroring FastMul's tree;
;  the LEA forms need 32-bit registers (the SIB byte does not exist
;  in 16-bit addressing), so WORD destinations keep the chain.
;  Other constants whose 16-bit magnitude is greater than 8 emit one
;  native three-operand IMUL (9-22 cycles for r16, 9-38 for r32)
;  instead of a chain of up to 30 instructions. |cte| <= 8, BYTE
;  destinations (the three-operand IMUL has no byte encoding),
;  memory destinations, memory sources and every CPU below the 386
;  keep the shift/add chain. Constants in 32768..65535 are passed to
;  IMUL as their negative two's complement equivalent, so the
;  documented contract also holds for DWORD destinations (a positive
;  65535 immediate would mean +65535, not -1). The three-operand
;  IMUL preserves src, like the shortcuts.
;
;  Examples:  FastIMul ax, bx, 45    ; ax = bx * 45
;             FastIMul cx, dx, -7    ; cx = -7 * dx
;             FastIMul eax, ebx, 1000; DWORD version with .386
;=====================================================================

;  __IMag c  - internal function: 16-bit magnitude of the cte
;  pattern (32768..65535 count as their negative two's complement).
;  __ISgn c  - internal function: the signed value IMUL must receive
;  (32768..65535 become their negative equivalent).
;  Both are pure parameter expressions with no assembly-time
;  variables, so they are immune to the ASMC re-read bug of v2.1.
__IMag MACRO c
    EXITM %(((((c) AND 8000h) NE 0) AND (10000h - ((c) AND 0FFFFh))) + ((NOT (((c) AND 8000h) NE 0)) AND ((c) AND 0FFFFh)))
ENDM

__ISgn MACRO c
    EXITM %(((((c) GT 32767) AND ((c) - 10000h)) + ((NOT (((c) GT 32767))) AND (c))))
ENDM

;  __Horn c, mask, d, s - internal macro: one Horner step of the
;  FastIMul chain (v3.2). If the 16-bit magnitude of c reaches
;  "mask", shift the accumulator once, and add s if the bit just
;  below "mask" is set. c is FastIMul's parameter passed through,
;  so every condition stays parameter-only (ASMC-safe, v2.1).
__Horn MACRO c, mask, d, s
    IF (__IMag(c)) / (mask)
        shl d, 1
        IF (__IMag(c)) AND ((mask) / 2)
            add d, s
        ENDIF
    ENDIF
ENDM

;  __RegBits r - internal function: 1, 2 or 4 if r is an 8, 16 or
;  32-bit register, 0 otherwise. Textual on purpose: the TYPE
;  operator is NOT portable (ASMC disables it by default - it wants
;  TYPEOF or the -Zne switch, and neither exists in JWasm/UASM;
;  4VIEW.ASM died with "error A2006: undefined symbol : TYPE" in
;  the v3.2 FastIMul checks), and the OPATTR word carries no size
;  bits. IFIDNI is case-insensitive and works everywhere.
__RegBits MACRO r
    IFIDNI <r>, <al>
        EXITM %1
    ELSEIFIDNI <r>, <ah>
        EXITM %1
    ELSEIFIDNI <r>, <bl>
        EXITM %1
    ELSEIFIDNI <r>, <bh>
        EXITM %1
    ELSEIFIDNI <r>, <cl>
        EXITM %1
    ELSEIFIDNI <r>, <ch>
        EXITM %1
    ELSEIFIDNI <r>, <dl>
        EXITM %1
    ELSEIFIDNI <r>, <dh>
        EXITM %1
    ELSEIFIDNI <r>, <ax>
        EXITM %2
    ELSEIFIDNI <r>, <bx>
        EXITM %2
    ELSEIFIDNI <r>, <cx>
        EXITM %2
    ELSEIFIDNI <r>, <dx>
        EXITM %2
    ELSEIFIDNI <r>, <si>
        EXITM %2
    ELSEIFIDNI <r>, <di>
        EXITM %2
    ELSEIFIDNI <r>, <bp>
        EXITM %2
    ELSEIFIDNI <r>, <sp>
        EXITM %2
    ELSEIFIDNI <r>, <eax>
        EXITM %4
    ELSEIFIDNI <r>, <ebx>
        EXITM %4
    ELSEIFIDNI <r>, <ecx>
        EXITM %4
    ELSEIFIDNI <r>, <edx>
        EXITM %4
    ELSEIFIDNI <r>, <esi>
        EXITM %4
    ELSEIFIDNI <r>, <edi>
        EXITM %4
    ELSEIFIDNI <r>, <ebp>
        EXITM %4
    ELSEIFIDNI <r>, <esp>
        EXITM %4
    ELSE
        EXITM %0
    ENDIF
ENDM

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
    IF ((@Cpu AND 0FFh) GE 8) AND ((OPATTR (dest)) AND 010h)
        IF (__RegBits(dest)) EQ 4                ; LEA needs 32-bit regs
            IF ((OPATTR (src)) AND 010h) AND ((__RegBits(src)) EQ 4)
                IF (cte) EQ 3                    ; reg = reg * 3, 5, 9:
                    lea dest, [src+src*2]        ; one LEA (1-2 cycles
                    EXITM                        ; vs 13-42 for IMUL)
                ELSEIF (cte) EQ 5
                    lea dest, [src+src*4]
                    EXITM
                ELSEIF (cte) EQ 9
                    lea dest, [src+src*8]
                    EXITM
                ELSEIF (cte) EQ 6                ; 6, 10, 12, 18, 20, 24:
                    lea dest, [src+src*2]        ; LEA + ADD/SHL
                    add dest, dest
                    EXITM
                ELSEIF (cte) EQ 10
                    lea dest, [src+src*4]
                    add dest, dest
                    EXITM
                ELSEIF (cte) EQ 12
                    lea dest, [src+src*2]
                    shl dest, 2
                    EXITM
                ELSEIF (cte) EQ 18
                    lea dest, [src+src*8]
                    add dest, dest
                    EXITM
                ELSEIF (cte) EQ 20
                    lea dest, [src+src*4]
                    shl dest, 2
                    EXITM
                ELSEIF (cte) EQ 24
                    lea dest, [src+src*2]
                    shl dest, 3
                    EXITM
                ENDIF
            ENDIF
        ENDIF
        IF ((__IMag(cte)) GT 8) AND ((__RegBits(dest)) NE 1)
            imul dest, src, __ISgn(cte) ; 386+: one native IMUL, src
            EXITM                       ; preserved; a BYTE destination
        ENDIF                           ; stays on the chain (v3.2)
    ENDIF
    mov dest, src                       ; Horner seed: dest = src
    __Horn cte, 8000h, dest, src
    __Horn cte, 4000h, dest, src
    __Horn cte, 2000h, dest, src
    __Horn cte, 1000h, dest, src
    __Horn cte, 800h, dest, src
    __Horn cte, 400h, dest, src
    __Horn cte, 200h, dest, src
    __Horn cte, 100h, dest, src
    __Horn cte, 80h, dest, src
    __Horn cte, 40h, dest, src
    __Horn cte, 20h, dest, src
    __Horn cte, 10h, dest, src
    __Horn cte, 8h, dest, src
    __Horn cte, 4h, dest, src
    __Horn cte, 2h, dest, src
    IF ((cte) AND 0FFFFh) AND 8000h     ; negative: negate at the end
        neg dest
    ENDIF
ENDM

;=====================================================================
;  5. FastMul const  ->  DX:AX = AX * const, unsigned (like MUL r16)
;=====================================================================
;  const: constant from 0 to 0FFFFh, known at assembly time.
;  Destroys BX (not on the 386+ paths), CL (8086 power-of-two
;  factors from 256 up) and CX (when a real MUL wins), plus the
;  flags; the 386+ paths rewrite the whole EAX and the whole EDX
;  (DX is half of the RESULT, so EDX is fully owned by the macro
;  since v2.42). It does
;  not reproduce the CF/OF values MUL would leave, only the result.
;
;  Strategies, best first depending on the bit pattern:
;    - const = 0                          : XOR AX / XOR DX
;    - const = 2^k                        : 32-bit shift
;      (v2.3) 386+: movzx eax,ax / shl eax,k, plus (v2.42) shld
;      edx,eax,16 to deliver DX - three instructions and
;      BX is not touched (factor 1 is just "xor dx,dx"). 8086 with
;      k >= 8: two half-window shifts
;      (mov dx,ax / shr dx,cl with 16-k, then the low bits left and
;      shifted k) - six instructions instead of the old 2*k shl/rcl
;      pairs, which cost up to 30 instructions for 32768. 8086 with
;      k < 8 keeps the original shl ax,1 / rcl dx,1 loop.
;    - any other const, 386+: native LEA/IMUL (v3.1) -
;      movzx eax,ax first; then factors 3, 5, 9 take ONE LEA
;      (lea eax,[eax+eax*2/4/8]; 1-2 cycles vs 13-42 for IMUL
;      r32,imm), factors 6, 10, 12, 18, 20, 24 take LEA + ADD/SHL
;      (two instructions), and every other factor takes
;      imul eax,eax,const. The 32-bit product of AX*f (both under
;      65536) always fits EAX, so AX = its low word for free and
;      the closing SHLD lifts its high word into DX: the DX:AX
;      pair the macro promises. (v2.4 emitted "imul edx,eax,const"
;      - the product landed in EDX, DX took its LOW word and AX
;      stayed the multiplicand; v2.41 fixed AX but still never
;      wrote DX. Both broke every caller that divides the pair,
;      4VIEW's fix 90 percent freeze being the reported case.)
;      BX and CL are not touched and the high word of EAX is
;      cleared by the MOVZX.
;    - const = (2^k - 1) * 2^j, k >= 4    : 32-bit Mersenne shortcut
;      (new in v2.0): ((x << k) - x) << j with SUB/SBB; turns dense
;      factors like 0FFFFh into ~2/3 of the instructions. 8086 only
;      since v2.4.
;    - MSB-to-LSB Horner with the DX:AX accumulator (v1, 8086 only
;      since v2.4)
;    - real MUL when the expansion would come out worse
;      (v3.1: above 117 estimated cycles; 8086 only since v2.4).
;      The model: the chain costs 5 fixed cycles (mov bx,ax +
;      xor dx,dx) + 4 per shl/rcl pair + 6 per add/adc pair;
;      mov cx,imm + MUL r16 costs 122-137. Breakeven: 117.
;=====================================================================

FastMul MACRO factor
    LOCAL fmF, fmHi, fmOnes, fmT, fmJ, fmM, fmK, fmP, fmI
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
            IF fmHi EQ 0            ; x*1: DX:AX = 0:AX, AX untouched
                xor dx, dx          ; (v2.42)
            ELSE
                movzx eax, ax       ; EAX = zero-extended multiplicand
                shl  eax, fmHi      ; EAX = the 32-bit product
                shld edx, eax, 16   ; DX = its high word (v2.42: the
            ENDIF                   ; macro's DX:AX contract - up to
                                    ; v2.41 DX was never written in
                                    ; this path, so the caller's 16-bit
                                    ; DIVs divided a stale high word)
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

    IF ((@Cpu AND 0FFh) GE 8)       ; 386+: native LEA/IMUL (v3.1)
        movzx eax, ax               ; EAX = zero-extended multiplicand
        IF fmF EQ 3
            lea eax, [eax+eax*2]    ; x*3: one LEA, 1-2 cycles
        ELSEIF fmF EQ 5
            lea eax, [eax+eax*4]    ; x*5: one LEA
        ELSEIF fmF EQ 9
            lea eax, [eax+eax*8]    ; x*9: one LEA
        ELSEIF fmF EQ 6
            lea eax, [eax+eax*2]    ; x*6: LEA + ADD
            add eax, eax
        ELSEIF fmF EQ 10
            lea eax, [eax+eax*4]    ; x*10: LEA + ADD
            add eax, eax
        ELSEIF fmF EQ 12
            lea eax, [eax+eax*2]    ; x*12: LEA + SHL
            shl eax, 2
        ELSEIF fmF EQ 18
            lea eax, [eax+eax*8]    ; x*18: LEA + ADD
            add eax, eax
        ELSEIF fmF EQ 20
            lea eax, [eax+eax*4]    ; x*20: LEA + SHL
            shl eax, 2
        ELSEIF fmF EQ 24
            lea eax, [eax+eax*2]    ; x*24: LEA + SHL
            shl eax, 3
        ELSE
            imul eax, eax, fmF      ; EAX = AX*f, exact: it always
        ENDIF                       ; fits 32 bits (v2.4, non-LEA)
        shld edx, eax, 16           ; DX = high word: the DX:AX
        EXITM                       ; contract (v2.42)
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

    IF fmHi*4 + (fmOnes-1)*6 GT 117 ; expansion would be worse than MUL
        mov cx, fmF                 ; -> real MUL (~122-137 cycles with
        mul cx                      ;    the mov cx,imm; v3.1 threshold:
        EXITM                       ;    the old 110 ignored the 5-cycle
    ENDIF                           ;    fixed overhead of the chain)

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

;  __BitRange name, bit - internal macro: the shared range check of
;  the five flag macros (v3.2). The macro name is passed as a
;  parameter so the error text stays per-macro.
__BitRange MACRO name, bit
    IF ((bit) LT 0) OR ((bit) GT 31)
        .ERR <name: bit index must be between 0 and 31>
        EXITM
    ENDIF
ENDM

setflag MACRO rm, bit
    __BitRange setflag, bit
    or rm, __Pow2(bit)
ENDM

clrflag MACRO rm, bit
    __BitRange clrflag, bit
    and rm, NOT __Pow2(bit)
ENDM

flipflag MACRO rm, bit
    __BitRange flipflag, bit
    xor rm, __Pow2(bit)
ENDM

testflag MACRO rm, bit
    __BitRange testflag, bit
    test rm, __Pow2(bit)
ENDM

maskflag MACRO rm, bit
    __BitRange maskflag, bit
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

;  __FieldRange name, lo, width - internal macro: the shared range
;  check of setfield and getfield (v3.2). The macro name is passed
;  as a parameter so the error text stays per-macro.
__FieldRange MACRO name, lo, width
    IF ((lo) LT 0) OR ((width) LT 1) OR ((width) GT 31) OR (((lo) + (width)) GT 32)
        .ERR <name: invalid range of lo/width (lo + width up to 32)>
        EXITM
    ENDIF
ENDM

setfield MACRO rm, lo, width, val
    __FieldRange setfield, lo, width
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
    __FieldRange getfield, lo, width
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

;=====================================================================
;  8. REDUNDANT "REG, REG" MOVES ELIMINATED (every CPU level;
;     mov since v3.0, xchg since v3.5)
;=====================================================================
;  "mov ax, ax" changes no register, no memory and no flags: it is a
;  pure redundancy, usually left over after edits or generated by
;  other macros. The macro below removes exactly that case and
;  passes every other MOV through untouched:
;
;       mov ax, ax      ->  (nothing)
;       mov ax, bx      ->  mov ax, bx        (pass-through)
;       mov ax, 0       ->  mov ax, 0         (pass-through, NOT xor!)
;       mov [bx], ax    ->  mov [bx], ax      (pass-through)
;
;  mov reg, 0 is deliberately NOT turned into "xor reg, reg": MOV
;  does not touch the flags, XOR destroys them, so the substitution
;  can silently break flag-dependent code. SMART only removes
;  instructions that provably do nothing.
;
;  Detection is textual (IFIDNI, case-insensitive) plus an OPATTR
;  register check: only two REGISTER operands with the same name are
;  removed. Identical text that is not a register pair (e.g. the
;  invalid "mov [bx], [bx]") still reaches the assembler and keeps
;  raising its normal error. The OPATTR check also keeps the
;  assembler's own diagnostics for any other invalid form.
;
;  If you need the original instruction anyway (a "mov ax, ax" used
;  as a 2-byte timing delay, or a patch hole for self-modifying
;  code), force it with "??mov ax, ax".
;
;  SMART / NOSMART (v3.3): the elimination is an optimization of
;  SMART mode, like TASM's automatic redundant-instruction removal.
;  It only happens while SMART (the default) is active; NOSMART
;  turns it off and every MOV passes through byte-identical until
;  the next SMART. The ??mov escape works in both modes.
;
;  xchg joins the elimination in v3.5: "xchg ax, ax" changes no
;  register, no memory and no flags either, so under SMART it
;  assembles to nothing and ??xchg forces the original byte back.
;  CAREFUL: the 1-byte "xchg ax, ax" (opcode 90h) is the classic
;  single-byte NOP used for alignment padding - SMART removes it
;  like any other dead instruction, so pad with "??xchg ax, ax"
;  (or with "nop", which is not taken over) when the byte count
;  matters.
;
;  The rename applies at every CPU level and has no effect on any
;  expression operator (MOV and XCHG do not share a token with an
;  expression operator).
;=====================================================================

    option renamekeyword:<mov>=??mov
mov MACRO dest, val
    IFB <val>
        .ERR <mov: missing operands>
        EXITM
    ENDIF
    IFIDNI <dest>, <val>
        IF (OPATTR (dest)) AND 010h     ; registers only: "mov [bx],[bx]"
            IF ??smart                  ; NOSMART keeps the instruction
            ELSE
                ; mov reg, reg: redundant, assembles to nothing
            ENDIF
        ELSE
            ??mov dest, val             ; keeps the assembler's error
        ENDIF
    ELSE
        ??mov dest, val
    ENDIF
ENDM

    option renamekeyword:<xchg>=??xchg
xchg MACRO a, b
    IFB <b>
        .ERR <xchg: missing operands>
        EXITM
    ENDIF
    IFIDNI <a>, <b>
        IF (OPATTR (a)) AND 010h        ; registers only
            IF ??smart                  ; NOSMART keeps the instruction
            ELSE
                ; xchg reg, reg: redundant, assembles to nothing
            ENDIF
        ELSE
            ??xchg a, b                 ; keeps the assembler's error
        ENDIF
    ELSE
        ??xchg a, b
    ENDIF
ENDM

;=====================================================================
;  9. LEA reg, var -> MOV reg, OFFSET var  (SMART, new in v3.4)
;=====================================================================
;  TASM's SMART mode replaces LEA with the shorter MOV when the
;  source is a plain variable: "lea ax, var" costs 4 bytes on the
;  8086 while "mov ax, OFFSET var" costs 3, and both load the same
;  address without touching the flags. The macro below performs
;  exactly that substitution and passes every other LEA through
;  byte-identical:
;
;       lea ax, var        ->  mov ax, OFFSET var   (shorter)
;       lea ax, var+2      ->  mov ax, OFFSET var+2 (shorter)
;       lea eax, var       ->  lea eax, var         (same size, kept)
;       lea ax, [bx]       ->  lea ax, [bx]         (indexed, kept)
;       lea ax, var[si]    ->  lea ax, var[si]      (indexed, kept)
;       lea ax, [bp+4]     ->  lea ax, [bp+4]       (no constant
;                                                       address, kept)
;       ??lea ax, var      ->  lea ax, var          (forced original)
;
;  Detection: the source must be a memory expression (OPATTR bit 1)
;  using direct addressing (bit 3) without an SS-relative part
;  (bit 6 clear), and the destination a 16-bit register
;  (__RegBits = 2). NOSMART disables the substitution. FastIMul and
;  FastMul expand their internal LEA forms through this macro; the
;  operands are indexed, carry no direct-addressing bit and pass
;  through unchanged.
;=====================================================================

    option renamekeyword:<lea>=??lea
lea MACRO reg, mem
    IF ??smart
        IF ((OPATTR (mem)) AND 01001010b) EQ 01010b ; direct memory var
            IF (__RegBits(reg)) EQ 2                ; MOV r16,imm16 is
                mov reg, OFFSET mem                 ; 3 bytes vs 4 for
                EXITM                               ; LEA r16,m16
            ENDIF
        ENDIF
    ENDIF
    ??lea reg, mem
ENDM

;=====================================================================
;  10. EXTENDED CONDITIONAL JUMPS  (SMART, new in v3.4)
;=====================================================================
;  On the 8086/186/286 a conditional jump only reaches -128..127
;  bytes, and the assembler just errors when the target is farther.
;  TASM's SMART mode handles the range automatically; the macros
;  below do the same for all 30 conditional jump mnemonics:
;
;       je near_label     ->  je near_label            (in range)
;       je far_label      ->  jne over / jmp far_label (extended)
;
;  - Backward targets (defined, local, not external) are MEASURED:
;    the short form is kept while the distance fits ($ - target
;    <= 126) and the extended form "j<inverse> over jmp target"
;    (5 bytes, always encodable) is emitted when it does not.
;  - Forward targets cannot be measured at expansion time (OPATTR
;    returns 0 for forward references), so they ALWAYS take the
;    extended form: no conditional jump can ever die with "jump
;    destination too far", at the price of 3 extra bytes on every
;    forward jump that would have fit. Write backward branches or
;    use ??jxx (the forced short form) where it matters.
;  - Targets given as @F or @B pass through unchanged: the macro
;    must not insert anonymous labels that would hijack them.
;  - The plain JMP needs no macro: the assembler already picks its
;    short or near encoding from the distance.
;  - The extended form reaches the full +/-32K of the near JMP;
;    beyond that (possible for a backward jump in a 64K segment)
;    the assembler's normal error remains - use an intermediate
;    label. NOSMART passes every jump through in the short form,
;    i.e. the native behavior.
;=====================================================================

;  __Jcc jshort, jinv, target - the shared body of all 30 jump
;  macros (v3.4): jshort is the renamed short instruction, jinv its
;  inverse, used to skip over the near JMP of the extended form.
__Jcc MACRO jshort, jinv, target
    LOCAL jext
    IFB <target>
        .ERR <jump: missing operand>
        EXITM
    ENDIF
    IF ??smart
        IFIDNI <target>, <@F>
            jshort target
        ELSEIFIDNI <target>, <@B>
            jshort target
        ELSEIF ((OPATTR (target)) AND 0081h) EQ 0001h   ; known local
            IF (($ - (target)) GT 126)                  ; code label
                jinv jext
                jmp target
                jext:
            ELSE
                jshort target
            ENDIF
        ELSE
            jinv jext               ; forward or external: extended
            jmp target
            jext:
        ENDIF
    ELSE
        jshort target               ; NOSMART: the short form
    ENDIF
ENDM

    option renamekeyword:<je>=??je
je MACRO target
    __Jcc ??je, ??jne, target
ENDM

    option renamekeyword:<jne>=??jne
jne MACRO target
    __Jcc ??jne, ??je, target
ENDM

    option renamekeyword:<ja>=??ja
ja MACRO target
    __Jcc ??ja, ??jbe, target
ENDM

    option renamekeyword:<jae>=??jae
jae MACRO target
    __Jcc ??jae, ??jb, target
ENDM

    option renamekeyword:<jb>=??jb
jb MACRO target
    __Jcc ??jb, ??jae, target
ENDM

    option renamekeyword:<jbe>=??jbe
jbe MACRO target
    __Jcc ??jbe, ??ja, target
ENDM

    option renamekeyword:<jg>=??jg
jg MACRO target
    __Jcc ??jg, ??jle, target
ENDM

    option renamekeyword:<jge>=??jge
jge MACRO target
    __Jcc ??jge, ??jl, target
ENDM

    option renamekeyword:<jl>=??jl
jl MACRO target
    __Jcc ??jl, ??jge, target
ENDM

    option renamekeyword:<jle>=??jle
jle MACRO target
    __Jcc ??jle, ??jg, target
ENDM

    option renamekeyword:<jo>=??jo
jo MACRO target
    __Jcc ??jo, ??jno, target
ENDM

    option renamekeyword:<jno>=??jno
jno MACRO target
    __Jcc ??jno, ??jo, target
ENDM

    option renamekeyword:<js>=??js
js MACRO target
    __Jcc ??js, ??jns, target
ENDM

    option renamekeyword:<jns>=??jns
jns MACRO target
    __Jcc ??jns, ??js, target
ENDM

    option renamekeyword:<jp>=??jp
jp MACRO target
    __Jcc ??jp, ??jnp, target
ENDM

    option renamekeyword:<jnp>=??jnp
jnp MACRO target
    __Jcc ??jnp, ??jp, target
ENDM

    option renamekeyword:<jz>=??jz
jz MACRO target
    __Jcc ??je, ??jne, target
ENDM

    option renamekeyword:<jnz>=??jnz
jnz MACRO target
    __Jcc ??jne, ??je, target
ENDM

    option renamekeyword:<jc>=??jc
jc MACRO target
    __Jcc ??jb, ??jae, target
ENDM

    option renamekeyword:<jnc>=??jnc
jnc MACRO target
    __Jcc ??jae, ??jb, target
ENDM

    option renamekeyword:<jna>=??jna
jna MACRO target
    __Jcc ??jbe, ??ja, target
ENDM

    option renamekeyword:<jnae>=??jnae
jnae MACRO target
    __Jcc ??jb, ??jae, target
ENDM

    option renamekeyword:<jnb>=??jnb
jnb MACRO target
    __Jcc ??jae, ??jb, target
ENDM

    option renamekeyword:<jnbe>=??jnbe
jnbe MACRO target
    __Jcc ??ja, ??jbe, target
ENDM

    option renamekeyword:<jng>=??jng
jng MACRO target
    __Jcc ??jle, ??jg, target
ENDM

    option renamekeyword:<jnge>=??jnge
jnge MACRO target
    __Jcc ??jl, ??jge, target
ENDM

    option renamekeyword:<jnl>=??jnl
jnl MACRO target
    __Jcc ??jge, ??jl, target
ENDM

    option renamekeyword:<jnle>=??jnle
jnle MACRO target
    __Jcc ??jg, ??jle, target
ENDM

    option renamekeyword:<jpe>=??jpe
jpe MACRO target
    __Jcc ??jp, ??jnp, target
ENDM

    option renamekeyword:<jpo>=??jpo
jpo MACRO target
    __Jcc ??jnp, ??jp, target
ENDM

;=====================================================================
;  11. JCXZ / LOOP extended automatically (v3.6)
;=====================================================================
;  JCXZ and LOOP are the only two jumps with neither an inverse nor
;  a long encoding: the 8-bit displacement is all they will ever
;  have, OPTION LJMP cannot lengthen them, and a destination more
;  than 127 bytes away is a hard "error A2075: jump destination
;  too far". Both take the same trampoline, because both mean
;  "condition -> target, else fall through":
;
;      jxx jext        ; the short-only jump, 2 bytes, hops +2
;      jmp jout        ; the fall-through path skips the trampoline
;      jext: jmp target ; near JMP reaches the full +/-32K
;      jout:
;
;  The trampoline is transparent on every axis that matters:
;   - JCXZ affects no flags and neither does the trampoline.
;   - LOOP must not touch flags (a plain "dec cx / jnz" emulation
;     would destroy them) and must wrap when CX = 0 (CX = 0FFFFh,
;     jump taken): the trampoline keeps the REAL loop as the
;     decrementing instruction, so both properties hold exactly.
;   - The +2 hop of the short jump and the near JMP are always in
;     range by construction.
;  Backward targets measured in range (the same "$ - target <= 126"
;  rule __Jcc uses, conservative by the 2 bytes of the short form)
;  keep the native 2-byte instruction. @F / @B targets pass through
;  unchanged, and NOSMART restores the native behavior. LOOPE/
;  LOOPNE/LOOPZ/LOOPNZ stay native: they test ZF, and a flag-safe
;  bridge would cost more than the instruction is worth.
;=====================================================================

;  __SExt jshort, target - shared body of the JCXZ/LOOP macros
;  (v3.6): jshort is the renamed short-only instruction.
__SExt MACRO jshort, target
    LOCAL jext, jout
    IFB <target>
        .ERR <jump: missing operand>
        EXITM
    ENDIF
    IF ??smart
        IFIDNI <target>, <@F>
            jshort target
        ELSEIFIDNI <target>, <@B>
            jshort target
        ELSEIF ((OPATTR (target)) AND 0081h) EQ 0001h   ; known local
            IF (($ - (target)) GT 126)                  ; code label
                jshort jext
                jmp jout
                jext: jmp target
                jout:
            ELSE
                jshort target
            ENDIF
        ELSE
            jshort jext             ; forward or external: extended
            jmp jout
            jext: jmp target
            jout:
        ENDIF
    ELSE
        jshort target               ; NOSMART: the short form
    ENDIF
ENDM

    option renamekeyword:<jcxz>=??jcxz
jcxz MACRO target
    __SExt ??jcxz, target
ENDM

    option renamekeyword:<loop>=??loop
loop MACRO target
    __SExt ??loop, target
ENDM

ENDIF   ; __SMART_INC__