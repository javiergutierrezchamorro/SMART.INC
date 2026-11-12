;=====================================================================
;  SMART.INC  v4.02  --  "TASM style" optimization macros
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
;       constant using shifts and adds only (8086; since .186 a
;       power-of-two |const| is mov + shl + neg for register AND
;       memory destinations - on a 386 with
;       32-bit registers, one single LEA for |const| = 2..8 - and
;       every constant whose chain would outgrow the native
;       three-operand IMUL, which exists since the .186, takes that
;       IMUL; on 386+ with register operands the odd part of |const|
;       is looked up in a LEA tree - one or two LEAs for the odd
;       factors 3..21 and 25, 27, 37, 41, 45, 73, 81 - and the power
;       of two becomes one SHL). dest and src may be the SAME
;       register for the constants that never re-read the source
;       (v4.01); v4.02: the power-of-two constants also work with
;       dest = src as a MEMORY operand, in place and with no seed
;       MOV at all.
;    5. FastMul const : DX:AX = AX * const unsigned, like MUL r16
;       (386+: movzx + the same odd-part LEA tree on EAX, with EDX
;       as scratch, + SHL, or one native IMUL; .186+: power-of-two
;       factors in four instructions, and the chain/MUL decision
;       follows the much faster MUL of the 186/286).
;    6. setflag/clrflag/flipflag/testflag/maskflag : single bits.
;    7. setfield/getfield : bit field insertion and extraction
;       (v3.9: on registers the AND masks fit the operand size and
;       a field that covers the whole register skips the AND;
;       v4.0: fields that do not fit a register are errors instead
;       of silent no-ops, a full 32-bit field is one MOV, and
;       getfield uses one MOVZX on a 386+ register source - with
;       the low word for width 16, and also when the source is the
;       smaller register).
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
;       ??jxx forces the short form). On a 386+ build the macros
;       just pass through (v3.9): the native near conditional jumps
;       reach every distance and the assembler picks the short or
;       near encoding by itself.
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
;  macro functions (EXITM %), REPEAT/WHILE and the .ERRNZ/.ERRB
;  directives are used as well (v4.01). NOTE: the :REQ parameter
;  attribute was tried and WITHDRAWN in v4.01 - ASMC 2.41 rejects it
;  ("error A2008: syntax error : :REQ") although JWasm/UASM accept
;  it; the file stays at the common subset.
;  Microsoft MASM CANNOT use this file: ml.exe has no RENAMEKEYWORD
;  (its OPTION NOKEYWORD deletes the keyword instead of renaming it,
;  so the original instruction becomes unreachable from the macro).
;  TASM is not supported either. The default CPU is 8086; with .186
;  or higher the shift macros and MOVZX/MOVSX are not defined because
;  equivalent native instructions already exist.
;
;  General notes:
;   - Include this file AFTER the processor directive
;     (.8086/.186/.286/.386/.486/.586): @Cpu is evaluated at the
;     include point.
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
;  Verification of v4.02: the FastIMul dest = src rewrite was swept
;  over the full documented constant range (-32768..65535) x four
;  register classes + a memory destination x the 8086/186/386 CPU
;  levels: 1,474,560 cases; the 590,256 that emit code were executed
;  against the reference signed product truncated to the operand
;  size (0 failures) and the 884,304 that raise the documented error
;  are exactly the cases with no in-place form. Diffed against the
;  v4.01 routes: 1,474,419 identical; the only changes are the 141
;  memory power-of-two cases (47 constant patterns x three CPUs)
;  that died in the invalid "mov mem, mem" and now emit the correct
;  in-place SHL/NEG tail. The REPEAT conversions emit the same
;  shl/rcl streams as the WHILE loops they replace (fmK, fmJ and
;  fmHi are loop-invariant, REPEAT 0 = no iterations, the same
;  proven __SHx pattern), and the folded fmP test evaluates the
;  same expression. The source has NOT been re-assembled with
;  ASMC/JWasm/UASM in this pass - re-run the assembly battery before
;  relying on this version in production.
;
;  Verification of v4.01: the changed macros were re-verified with
;  the same simulation method. FastIMul dest = src: the full
;  (register class, CPU, constant) space - four register classes
;  (byte, word, dword, dword-ESP) x three CPU levels x all 98,304
;  constants of the documented range - was routed and executed
;  against the reference signed product truncated to the operand
;  size: 1,179,648 cases; the 590,112 that emit code are all exact
;  and the 589,536 that raise the documented error are exactly the
;  cases with no in-place encoding (byte destinations at every CPU,
;  16-bit non-power-of-two constants on the 8086); 0 unexpected
;  results. The d = s shapes of the eight __IsLeaOddD factors were
;  executed factor by factor against the reference product (0
;  failures) and the nine t-forms were confirmed excluded from the
;  predicate. FastMul: the new (fmK + fmJ) Mersenne budget was
;  diffed against the old (fmHi + fmJ) test over all 65,536 factors
;  on the 8086, 186 and 286 - exactly three route changes (61440,
;  63, 15), each re-executed against the reference DX:AX product, 0
;  failures; the 386+ paths and every power-of-two path are
;  untouched. The .ERRNZ/.ERRB conversions emit nothing on the
;  passing path and only reword the error on the failing one. The
;  :REQ attributes were withdrawn after the 4VIEW 2.14 build
;  rejected them (ASMC 2.41, "error A2008: syntax error : :REQ");
;  every parameter list is back to the v4.0 form. The
;  getfield widening collapse is the same two calls in both CPU
;  branches by construction. The macro source has NOT been
;  re-assembled with ASMC/JWasm/UASM in this pass - the simulator
;  models the intended expansions, not the assemblers' macro
;  engines; re-run the assembly battery before relying on this
;  version in production.
;
;  Verification of v4.0: the changed macros were re-verified with
;  the same simulation method. getfield: 295,893 (dest, src, lo,
;  width, CPU) combinations - 24 register names plus three memory
;  sizes, CPUs 8086 and 386+ (below the 386 restricted to operands
;  of 16 bits or less), every lo/width pair - each executed with
;  three source values against the reference (src SHR lo) AND
;  (2^width - 1), with an encodability check on every emitted
;  immediate: 0 failures. The diff census against v3.9 counted
;  151,151 route changes, all of them the intended ones (the
;  width-16 MOVZX fix, the memory-destination AND fix, the new
;  mixed-size widening paths and the four same-operand extensions
;  "movzx eax, si" and friends); 0 unexpected. setfield: 127,170
;  combinations (nine val values per case) against the reference
;  field insert: 0 failures - of which 5,155 memory cases where an
;  emitted immediate does not encode are the documented assembler
;  error, not wrong code. clrflag: 1,440 combinations, 0 failures.
;  The SMART/NOSMART contract of the mov/xchg macros was checked in
;  both states (NOSMART now really passes "mov reg, reg" through).
;  The macro source has NOT been re-assembled with
;  ASMC/JWasm/UASM in this pass - the simulator models the intended
;  expansions, not the assemblers' macro engines; re-run the
;  assembly battery before relying on this version in production.
;
;  Verification of v3.9: the changed macros were re-verified with
;  the same simulation method. FastIMul (memory destinations on the
;  power-of-two path, ESP-destination guard): 7,021,800 cases - the
;  full 16-bit constant range on the 8086 and 386+ over eight
;  operand shapes (byte/word/dword register and memory destinations,
;  register/memory/ESP sources, ESP destination), sampled on the
;  186/286/386 - against the reference product truncated to the
;  destination size: 0 failures, and the 8086 expansions stayed
;  byte-identical to v3.8 (the 31 power-of-two constants, the only
;  ones that change route, diffed instruction by instruction against
;  the v3.8 Horner streams). clrflag: the fitted masks were checked
;  for encodability and semantics at 8/16 bits for every bit index
;  (the v3.8 plain NOT was unencodable exactly for the top bit:
;  "clrflag ax, 15", "clrflag al, 7"). setfield/getfield: every
;  (size, lo, width, val, old-value) combination was executed
;  against a reference field insert/extract with an encodability
;  check on every emitted immediate: 0 failures. The sweep caught
;  TWO bugs before they reached the source: the first getfield
;  draft fired its MOVZX path for every width below the operand
;  size (only 8 and 16 zero-extend into exactly the field), and the
;  first v3.9 setfield draft - like the v3.2 code it replaced -
;  wrote a full-operand field with the OR alone, which cannot clear
;  the field bits val has at 0 ("setfield ax, 12, 4, 5" kept the
;  old bits 13 and 15; silent wrong code since v3.2). The 386+ Jcc
;  pass-through was checked by construction (the native near
;  conditional jump reaches every distance the trampoline did).
;  The macro source has NOT been re-assembled with
;  ASMC/JWasm/UASM in this pass - the simulator models the intended
;  expansions, not the assemblers' macro engines; re-run the
;  assembly battery before relying on this version in production.
;
;  Verification of v3.8: same method, wider sweep. FastIMul: the
;  full v3.8 decision tree (five CPU levels, byte/word/dword
;  register and memory destinations, register/memory/ESP sources,
;  every 16-bit constant pattern and its negative twins) was
;  executed instruction by instruction against a signed reference
;  product: 23,592,600 cases, 0 failures. FastMul: every factor
;  0..65535 on the 8086, 186, 286 and 386 targets, ten multiplicand
;  seeds each, the DX:AX PAIR checked against the reference product:
;  2,621,440 cases, 0 failures. Route census from the same sweep -
;  8086: 59,936 Horner chains, 90 Mersenne shortcuts, 5,493 MULs;
;  186: 19 chains, 4 Mersenne (15/30/31/63), 65,496 MULs; 286:
;  7 chains, 1 Mersenne (15), 65,511 MULs; 386+: 208 factors on the
;  LEA tree, the other 65,327 on one native IMUL, no MUL and no
;  chain anywhere. The macro source has NOT been re-assembled with
;  ASMC/JWasm/UASM in this pass - the simulator models the intended
;  expansions, not the assemblers' macro engines; re-run the
;  assembly battery before relying on this version in production.
;
;  Verification of v3.7: the new decision logic was verified by an
;  exhaustive simulation of the intended expansions outside the
;  assembler: 712,140 FastIMul cases (every 16-bit constant pattern
;  and its negative-range twins, five CPU levels, byte/word/dword
;  register destinations, register and memory sources) and 566,886
;  FastMul cases (every factor on the 8086, 186 and 386 targets,
;  with denser sampling on 4,096 pseudo-random factors) were executed
;  instruction by instruction against a reference product, checking
;  the source operand for preservation: 0 failures. The LEA trees
;  were verified factor by factor for both the dest = src and the
;  dest <> src shapes, and the IMUL path arithmetically.
;
;  Verification of v3.6 and earlier: assembled with ASMC 2.40
;  (8086/186/286/386 targets) and JWasm 2.12 (4VIEW 1.04 itself also
;  uses ASMC-only extensions such as .switch and inline "proto
;  asmcall", so it builds with ASMC). FastIMul/FastMul verified
;  numerically: every emitted instruction sequence is executed by an
;  8086 simulator for 220 FastIMul and 150 FastMul (constant, seed)
;  combinations, plus the -3 spot checks and a byte-level check of
;  the shift/push/pop/bit expansions. The v2.0 "104 cases" bank only
;  ever ran on JWasm, which is why none of this showed up there -
;  see v2.1 below. Since v2.42 the -3 battery compares the DX:AX
;  PAIR (not EAX and not EDX) against the reference product for
;  every 16-bit multiplicand: v2.4's EDX check was exactly what the
;  broken path produced, which is how the bug shipped. v3.2's
;  FastIMul refactor was proven byte-identical by comparing the old
;  and new instruction sequences for all 98,304 constants
;  (0 differences), and the 386+ LEA/IMUL decision tree was executed
;  for 2,359,296 (constant, size, register/memory, seed) combinations
;  against a signed reference product (0 failures). The v3.3
;  SMART/NOSMART switch was checked in both states: the SMART output
;  is byte-identical to v3.2, and NOSMART passes every MOV through,
;  including "mov ax, ax". The v3.4 jump logic was simulated for
;  every backward distance 0..400: the short form is kept exactly
;  while the displacement fits (-128..127, boundary at 126/127
;  verified) and the trampoline displacement (+3) is always in
;  range; the lea decision table was checked against the byte counts
;  (mov r16,imm16 = 3 vs lea r16,m16 = 4). The v3.5 alias renames
;  restore the v2.0 rule (every taken-over mnemonic is freed before
;  its macro is defined), so the include again emits no code at
;  include time and can be included outside a segment. The v3.6
;  JCXZ/LOOP trampoline was checked against the same 0..400
;  backward-distance sweep (short kept exactly while the
;  displacement fits, boundary 126/127) and the trampoline's own
;  displacements (+2 short hop, full-range near JMP) are in range by
;  construction; the CX = 0 wrap and the untouched flags were
;  verified against the native instructions' semantics.
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
;   v4.02  Sixth review pass: one fix, three simplifications. Every
;          SMART-mode register expansion is byte-identical to v4.01:
;          1. FIXED (FastIMul, dest = src): the power-of-two path
;             emitted the seed "mov dest, src" before the SHL/NEG
;             tail. For a REGISTER the self-MOV was deleted by SMART
;             (and was dead weight under NOSMART); for a MEMORY
;             operand it was the invalid "mov mem, mem" - an obscure
;             assembler error for a case that has a perfectly good
;             in-place form. The seed is gone: the tail runs alone,
;             so "FastIMul var, var, 4" now expands to the in-place
;             shift and "FastIMul var, var, 1" to nothing. Verified
;             over the full constant range (see the v4.02 note).
;          2. SIMPLIFIED (zero code change): FastMul's three
;             fixed-body counting loops (the two Mersenne shifts and
;             the 8086 power-of-two shl/rcl loop) are REPEAT now -
;             the same proven pattern as __SHx, no counter seeds or
;             decrements. The bottom Horner loop keeps its WHILE:
;             it tests a different bit of fmF on every pass.
;          3. SIMPLIFIED (zero code change): FastMul's fmP variable
;             is folded into the Mersenne test as __Pow2(fmK) - one
;             LOCAL and one assignment less.
;          4. SIMPLIFIED (zero code change): getfield's inverted
;             same-operand guard (IFIDNI with an empty body and the
;             memory check in the ELSE) is one IFDIFI.
;   v4.01  Fifth review pass: the assembler's high-level constructs
;          adopted where they cannot change one byte of output, one
;          cost-model fix, one new capability, three source
;          simplifications:
;          1. High-level directives: __BitRange and __FieldRange are
;             one-line .ERRNZ tests now (the assembler's own
;             conditional error, same test and text) and push/pop
;             check their operand list with .ERRB. Runtime HLL flow
;             (.IF/.WHILE/.REPEAT) stays deliberately unused: every
;             macro emits a fixed instruction sequence and the
;             expansions' contract (which registers and flags die)
;             would blur. The emitted expansions are unchanged.
;             TRIED AND WITHDRAWN: :REQ parameters on the user-facing
;             macros - ASMC 2.41 rejects the attribute ("error A2008:
;             syntax error : :REQ", reported by the 4VIEW 2.14
;             build), so the file keeps the plain parameter lists of
;             v4.0; JWasm/UASM accept :REQ, but ASMC is the reference
;             assembler of this file.
;          2. FIXED (cost-model deviation, FastMul): the Mersenne
;             budget test measured (fmHi + fmJ) = (fmK + 2*fmJ - 1)
;             where the v3.8 model says (fmK + fmJ). On a 286 the
;             factor 15 fired the shortcut the model says can never
;             win there (24 vs the 23-cycle MUL), on a 186 the
;             factor 63 kept it past the documented budget, and on
;             the 8086 the factor 61440 (= 15 * 4096) was denied the
;             shortcut the model grants it. Route census over all
;             65536 factors x the three CPU levels: exactly THREE
;             routes change (61440 on the 8086, 63 on the 186, 15 on
;             the 286), each toward the route the documented model
;             prices cheaper; every changed route was re-executed
;             against the reference product, 0 failures.
;          3. NEW: FastIMul accepts dest = src for the constants
;             whose expansion never re-reads the source after the
;             destination is written: const 0; the powers of two
;             (the seed "mov dest, src" becomes a self-MOV that
;             SMART mode deletes); on a 386+ with 32-bit registers
;             the d-only LEA-tree factors 3, 5, 9, 15, 25, 27, 45
;             and 81 (new __IsLeaOddD - the t-forms 7, 11, 13, 17,
;             19, 21, 37, 41, 73 read the source again after the
;             first LEA and keep requiring dest <> src); and on a
;             .186+ with a non-byte register destination every
;             remaining constant takes one native IMUL. Everything
;             else raises a clear error instead of silently
;             computing the wrong product (the Horner chain adds the
;             shifted accumulator to the source; the 8086 has no
;             in-place form and the macro will not clobber a scratch
;             register the caller was not told about).
;          4. SIMPLIFIED (zero code change): FastMul computes
;             fmHi/fmOnes/fmJ/fmM/fmK with the section-0 functions
;             __Hibit/__Ones/__TZ instead of three inline counting
;             loops (~18 lines); FastIMul's fifteen __Horn calls are
;             one FOR over the mask list (same calls, same order);
;             getfield's mixed-size widening is ONE movzx call - the
;             386+ native form and the section-2 macro share it, and
;             below the 386 the movzx macro raises its own clear
;             error for the destinations it cannot widen, so
;             getfield's duplicated four-way dispatch is gone; the
;             __Pow2 note documents the deliberate 2^32 wrap the
;             mask expressions use.
;   v4.0  Fourth full review; seven fixes, all in the bit/field and
;         mov/xchg macros. FastIMul/FastMul, the jump macros and
;         every 8086 expansion are untouched:
;         1. FIXED (silent wrong code, v3.9 regression): getfield's
;            MOVZX path mapped every covered source to its low BYTE
;            even for width = 16 - "getfield eax, ebx, 0, 16"
;            emitted "movzx eax, bl" and dropped the high byte.
;            Width 16 now takes the low WORD (eax->ax, ebx->bx,
;            ecx->cx, edx->dx, esi->si, edi->di, ebp->bp, esp->sp,
;            all legal "movzx r32, r16" forms); the width-8 list
;            keeps the byte-half registers only.
;         2. FIXED (silent wrong code, v3.9 regression): getfield's
;            identity-AND skip tested the DESTINATION size, which is
;            0 for memory, so the final AND was skipped on every
;            memory destination ("getfield var, ax, 4, 4" kept the
;            source bits above the field). The closing AND/SHR now
;            lives in the shared __GFTail macro, which knows whether
;            the operand is a register (skip only on identity) or
;            memory (always AND, except a full 32-bit field).
;         3. FIXED (contract bug since v3.3): NOSMART did not restore
;            "mov reg, reg" / "xchg reg, reg" - the ELSE branches of
;            the ??smart test held only a comment, so the
;            elimination happened in both modes and a deliberate
;            patch hole or timing delay silently vanished. Both now
;            emit the original instruction under NOSMART.
;         4. FIXED (v3.9 regression): clrflag on a REGISTER with a
;            bit beyond the operand size assembled to the fitted
;            mask's silent no-op ("clrflag al, 15" = "and al, 0FFh")
;            instead of the documented error; now a clear .ERR.
;         5. FIXED (v3.9 regression): setfield on a REGISTER with
;            lo + width above the operand size silently truncated or
;            no-op'd the same way ("setfield al, 8, 8, 5h" = "and
;            al, 0FFh / or al, 0"); now a clear .ERR (the <386
;            16-bit check and the full-operand MOV are unchanged).
;         6. FIXED: __FieldRange rejected the legitimate width = 32
;            with lo = 0 ("setfield eax, 0, 32, val"), which the
;            documented "lo + width up to 32" limit allows; accepted
;            now, and a full 32-bit field on MEMORY (386+ build)
;            takes one MOV like every full-operand field.
;         7. FIXED (assembler-error class): getfield with register
;            operands of DIFFERENT sizes died on the invalid seed
;            "mov dest, src" ("getfield eax, bx, 4, 8"). A larger
;            destination is now seeded with ONE MOVZX (native on a
;            386+; below the 386 through the section-2 movzx macro,
;            which only widens into AX/BX/CX/DX), the identity of
;            the final AND is measured against the SOURCE size
;            (MOVZX has already zeroed everything above it), and a
;            destination smaller than the source raises a clear
;            error instead of the invalid MOV.
;   v3.9  Full review of every macro; three fixes and four new
;         CPU-dependent paths. The 8086 FastIMul/FastMul expansions
;         stay byte-identical to v3.8:
;         1. FIXED: FastIMul, 386+, the __LeaOddX tree path only
;            guarded its SOURCE against ESP - as a DESTINATION,
;            ESP breaks every two-step form ("lea esp,[eax+esp*2]"
;            and the d-only forms use ESP as a scaled index, which
;            has no encoding). FastIMul esp, eax, 7 now keeps the
;            mov + chain expansion.
;         2. FIXED: clrflag and setfield computed their AND masks
;            as 32-bit NOTs: any mask that sets the top bit of the
;            operand without covering it all produced an
;            unencodable immediate - "clrflag ax, 15" emitted
;            "and ax, 0FFFF7FFFh" (-32769, out of the 16-bit
;            signed/unsigned range), "clrflag al, 7" and
;            "setfield al, 4, 4" died the same way on every CPU,
;            and on a 386+ build so did every 16-bit setfield whose
;            field reaches bit 15 (the v3.2 full-16-bit special
;            case only covered CPUs below the 386). On REGISTER
;            operands the masks are now fitted to the operand size
;            with __RegBits ("and ax, 7FFFh", "and al, 0Fh");
;            memory operands keep the plain NOT (their size is not
;            visible to the macro).
;         3. FIXED: getfield var, var, ... (the same memory
;            operand as dest and src) raised the "cannot both be
;            memory" error although no MOV is emitted in that
;            case; the check now only applies to two DIFFERENT
;            memory operands.
;         4. FastIMul: the power-of-two path (mov + SHL + NEG) no
;            longer requires a register destination - on the .186
;            and above a MEMORY destination now takes one native
;            "shl mem,imm" instead of k one-bit read-modify-writes
;            (SHL mem,1 = 16 cycles on a 286), and on the 8086 the
;            expansion is byte-identical to the old Horner chain,
;            which for a power of two is the same mov + k shifts +
;            neg with no add steps.
;         5. Conditional jumps, 386+: __Jcc passes through - the
;            386 added near conditional jumps (0F 8x rel), so the
;            assembler picks the short or near encoding by itself
;            and the 5-byte "j<inv> over jmp" trampoline is never
;            needed (a forward jump that fits saves 3 bytes, an
;            out-of-range one saves the trampoline). SMART and
;            NOSMART are equivalent for Jcc on a 386+ build.
;            JCXZ/LOOP keep the trampoline at every CPU level:
;            they never got a long encoding.
;         6. getfield: the final AND is skipped when it is an
;            identity operation - after "shr dest,lo" the bits
;            above width are already zero whenever
;            lo + width covers the destination register
;            (getfield ax,bx,12,4 is now mov + shr; on memory
;            destinations the size is unknown and the AND stays).
;         7. getfield, 386+, register source and destination with
;            lo = 0 and a width of exactly 8 or 16 below the
;            destination size: ONE
;            MOVZX from the low byte/word register replaces
;            mov + shr + and (getfield eax,ebx,0,8 is "movzx
;            eax,bl"; other widths would keep bits beyond the
;            field). SI/DI/BP/SP have no byte halves and keep
;            the old path.
;         8. setfield: FIXED silent wrong code from v3.2 - a field
;            covering the whole operand was written with the OR
;            alone, which cannot clear the field bits val has at 0
;            ("setfield ax, 12, 4, 5" kept the old bits 13 and 15;
;            the <386 full-16-bit special case had the same bug).
;            lo = 0 with width >= size now emits one MOV (which
;            also preserves the flags); every other case keeps
;            AND + OR with the immediates fitted to the operand.
;   v3.8  Second pass over FastIMul/FastMul with per-CPU decision
;         data; every 8086 expansion stays byte-identical to
;         v3.6/v3.7:
;         1. FastIMul: the native three-operand IMUL exists since
;            the .186, not since the 386 - below the 386 it now
;            replaces the Horner chain whenever the chain would
;            outgrow it. Every chain step costs 2-3 cycles on a
;            186/286 while IMUL r16,imm costs 21 on a 286 (and on a
;            186 it is several times faster than the 8086's
;            118-133); new __Hibit/__Ones measure the chain as
;            (highest bit + set bits) of |const| and the IMUL wins
;            above 10: FastIMul ax,bx,1000 on a .286 is ONE imul
;            instead of the 15-instruction chain of v3.6. The 386+
;            paths adopt the same rule instead of v3.7's
;            "|cte| > 8" (on a 486/Pentium the short 9..15 chains
;            win and the long ones lose; on a 386 both rules sit
;            inside the IMUL's own 9-22/9-38-cycle spread). An
;            immediate source (outside the documented contract)
;            stays on the chain instead of dying in the IMUL.
;         2. FastIMul, 386+, 32-bit register source: |const| = 4
;            and 8 now collapse to ONE "lea dest,[src*4]"/
;            "[src*8]" next to the v3.7 "[src+src]" for 2 (2 cycles
;            on a 386, 1 on a 486/Pentium, vs 5 for mov + shl; the
;            no-base SIB form costs 7 bytes instead of 5). ESP
;            cannot be a scaled index, so a register-ESP source
;            keeps mov + shl - FIXED: v3.7 handed it the invalid
;            "[esp+esp]" (|cte| = 2) or tree forms, an assembler
;            error the v3.6 chain/IMUL paths never produced.
;         3. FastIMul, 386+, MEMORY destination with a register
;            source: |const| > 8 takes the "IMUL r/m, reg, imm"
;            form the 386 added; the chain on memory is a sequence
;            of read-modify-writes (SHL mem,1 = 7 cycles on a 386,
;            16 on a 286 - where no such IMUL exists and the chain
;            stays).
;         4. FastMul, 386+: the odd-part tree now covers ALL 17
;            __LeaOddX factors (7, 11, 13, 17, 19, 21, 37, 41, 73
;            join 3, 5, 9, 15, 25, 27, 45, 81). The two-step forms
;            run their intermediate through EDX, which the 386+
;            paths already own (v2.42), and the final LEA writes
;            EAX: "lea edx,[eax+eax*2] / lea eax,[eax+edx*2]" is
;            x*7 in two 1-cycle LEAs on a 486/Pentium, against the
;            13-42/10-11-cycle IMUL those factors took in v3.7.
;            __LeaOdd and __IsLeaOdd are gone: one unified
;            __LeaOddX d,s,t,o serves both macros (FastIMul passes
;            its own dest as the scratch t, which reproduces its
;            v3.7 forms exactly).
;         5. FastMul, .186/.286: the MUL-fallback and Mersenne
;            budgets follow the CPU (v3.6 used the 8086 model at
;            every level). 8086: unchanged (add/adc pair 6 cycles,
;            MUL budget 117, Mersenne (k+j) LE 26). 186: same pair
;            costs, but its MUL is several times faster than the
;            8086's (budget 27, Mersenne (k+j) LE 5). 286: every
;            register op runs in 2 cycles and MUL r16 in 21
;            (add/adc pair 4, budget 19, and the Mersenne form can
;            never win: its fixed k >= 4 cost is already 24
;            cycles). v3.6 emitted 8086-calibrated 20-40
;            instruction chains there instead of one MUL.
;         6. FIXED (latent, pre-v3.7): getfield accepted fields
;            beyond 16 bits on CPUs below the 386 where setfield
;            errors - the bits beyond 15 silently shifted out to 0;
;            it now raises the same error as setfield.
;         7. Source shape: section 0 gained __Hibit/__Ones, the
;            shared __MulTail closing (SHL for the trailing 2^k +
;            NEG) lives in section 0b next to the single unified
;            LEA tree, and FastIMul's duplicated SHL/NEG closers
;            are gone.
;   v3.7  486/Pentium LEA exploitation. Only the 386+ paths of
;         FastIMul/FastMul and the .186+ power-of-two paths change;
;         every 8086 expansion is byte-identical to v3.6:
;         1. FastIMul, |const| = 2^k with a register destination:
;            MOV + SHL dest,k + optional NEG since the .186 (SHL
;            r/m,imm is a native instruction there; the barrel
;            shifter makes it 2-3 cycles on a 486 and 1 on a
;            Pentium). v3.6 ran 1-bit chains for |const| <= 8 and
;            sent powers of two above 8 to the native IMUL on the
;            386+ (13-42 cycles for what is now 2-3 instructions;
;            -32768 was a 17-instruction chain on the 8086 and an
;            IMUL on the 386+, it is now 3 instructions at every
;            CPU from the .186 up). On the 386 with a 32-bit
;            register source, |const| = 2 collapses to one
;            "lea dest,[src+src]".
;         2. FastIMul/FastMul, 386+: the constant is split into
;            odd part x 2^k (new internal functions __TZ/__TZm/
;            __MOdd). The odd part is looked up in a LEA tree:
;            __LeaOddX (FastIMul, dest <> src) covers the odd
;            factors 3..21 plus 25, 27, 37, 41, 45, 73 and 81 with
;            one or two LEAs; __LeaOdd (FastMul, dest = src = EAX)
;            covers 3, 5, 9, 15, 25, 27, 45 and 81 (the forms whose
;            second LEA reads the multiplicand again need a
;            separate destination register, so FastMul keeps the
;            native IMUL for 7, 11, 13, 17, 19, 21, 37, 41 and 73).
;            The trailing 2^k becomes one SHL. This replaces the
;            v3.1 fixed list 3, 5, 9, 6, 10, 12, 18, 20, 24 (6 =
;            3x2, 10 = 5x2, 12 = 3x4, 18 = 9x2, 20 = 5x4, 24 = 3x8
;            are all odd part x power of two) and adds hundreds of
;            factors (every 3..21 odd times any power of two: 14,
;            22, 28, 30, 40, 48, 56, 96, ...). Two dependent LEAs
;            cost 4 cycles on a 386, 2-3 on a 486 and 2-3 on a
;            Pentium (LEA is 1 cycle there vs 2 on the 386, and the
;            second LEA pays one AGI cycle because it reads the
;            register the first one wrote), against 9-38 cycles for
;            IMUL r32,imm on the 386, 13-42 on the 486 and 10-11 on
;            the Pentium: the tree wins for every factor it covers,
;            which is why the |cte| > 8 IMUL threshold of v3.1 is
;            gone for 32-bit register pairs. On a Pentium a 16-bit
;            LEA costs 3 cycles - one more reason the trees only
;            use 32-bit registers. The expansions stay
;            parameter-only (__TZ/__MOdd are macro FUNCTIONS whose
;            LOCALS never escape, the same proven pattern as
;            __Pow2), so the ASMC v2.1 re-read bug does not apply.
;            Negative constants append NEG to the tree result:
;            -3 drops from 6 instructions to 2, -48 from 9 to 3.
;         3. FastMul, .186/.286 power-of-two factors: immediate
;            shifts remove the CL setup - mov dx,ax / and ax,mask /
;            shl ax,k / shr dx,16-k, four instructions at every
;            k >= 2 (the 8086 form costs six for k >= 8 and 1+2k
;            for k < 8); k = 1 keeps xor dx,dx / shl ax,1 /
;            rcl dx,1. The 8086 paths are untouched.
;         4. FIXED (latent): the "lea reg16, var -> mov reg, OFFSET
;            var" substitution now requires @WordSize EQ 2. In a
;            use32 segment OFFSET is a 32-bit value and "mov ax,
;            OFFSET var" truncates it or fails to encode; such a
;            LEA now passes through unchanged. Every use16 build
;            (all 8086..386 real-mode code) behaves exactly as
;            before.
;         5. The internal assembly-time functions are consolidated
;            in section 0 (__Pow2, __IMag, __ISgn move there; new
;            __TZ/__TZm/__MOdd/__IsLeaOdd/__IsLeaOddX) and the two
;            internal LEA-tree macros in section 0b. No user-visible
;            name changed.
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
;  Version constant: mayor*100 + menor (402 = v4.02; 3.10 would have
;  collided with 3.1, which is why the fourth review pass bumped the
;  major digit). Source can test
;  "IF __SMART_INC__ GE 402" before using a newer feature.
__SMART_INC__ = 402

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
;  0. INTERNAL ASSEMBLY-TIME FUNCTIONS
;=====================================================================
;  All pure functions of this file live here since v3.7 (__Pow2 was
;  alone before; __IMag/__ISgn moved from section 4 in v3.7, and
;  __TZ/__TZm/__MOdd/__Hibit/__Ones/__IsLeaOddX joined them in
;  v3.7/v3.8). None of them emits code
;  and none touches the caller's assembly-time variables: every
;  LOCAL is set and read inside the function itself, before EXITM,
;  so they are immune to the ASMC v2.1 re-read bug pattern and safe
;  to call inside any expression.
;=====================================================================

;  __Pow2 n  -  returns 2^n
;
;  OPTION RENAMEKEYWORD:<shl>/<shr> also disables the assembler's
;  SHL and SHR OPERATORS on the 8086 (they share the token with
;  the instruction), so every mask computation in this file uses
;  this function, built from multiplications only:
;
;       flM = __Pow2(bit)          ; in assignments
;       or  ax, __Pow2(4)          ; inside expressions
;       IF v EQ __Pow2(5) - 1      ; in conditions
;
;  n must be a constant between 0 and 31. 32 wraps to 0 in the
;  assembler's 32-bit arithmetic; the mask expressions below use
;  that on purpose (2^32 - 1 = 0FFFFFFFFh, the full-operand mask).
__Pow2 MACRO n
    LOCAL p, i
    p = 1
    i = 0
    WHILE i LT (n)
        p = p * 2
        i = i + 1
    ENDM
    EXITM %p
ENDM

;  __IMag c  -  16-bit magnitude of the cte pattern (32768..65535
;  count as their negative two's complement).
;  __ISgn c  -  the signed value IMUL must receive (32768..65535
;  become their negative equivalent).
;  Both are pure parameter expressions with no assembly-time
;  variables, so they are immune to the ASMC re-read bug of v2.1.
__IMag MACRO c
    EXITM %(((((c) AND 8000h) NE 0) AND (10000h - ((c) AND 0FFFFh))) + ((NOT (((c) AND 8000h) NE 0)) AND ((c) AND 0FFFFh)))
ENDM

__ISgn MACRO c
    EXITM %(((((c) GT 32767) AND ((c) - 10000h)) + ((NOT (((c) GT 32767))) AND (c))))
ENDM

;  __TZ m  -  trailing zeros of m (1..32768): returns 0..15.
;  __TZm c -  __TZ of the 16-bit magnitude of the cte pattern.
;  __MOdd c -  odd part of that magnitude: |cte| = __MOdd * 2^__TZm.
;  New in v3.7: the 386+ paths of FastIMul/FastMul decompose the
;  constant into odd part x power of two and evaluate the odd part
;  with one or two LEA reg,[base+index*scale] forms; the trailing
;  2^k becomes one SHL. LEA costs 2 cycles on the 386 and 1 cycle on
;  the 486 and Pentium (plus one AGI cycle on the 486/Pentium when
;  the base or index register was written by the immediately
;  preceding instruction, which is the case for the second LEA of
;  every pair), while IMUL r,imm costs 9-38 cycles on the 386,
;  13-42 on the 486 and 10-11 on the Pentium. The scaled forms need
;  32-bit registers (the SIB byte does not exist in 16-bit
;  addressing; on a Pentium a 16-bit LEA would also cost 3 cycles).
__TZ MACRO m
    LOCAL t, n
    t = (m)
    n = 0
    WHILE ((t) AND 1) EQ 0
        t = (t) / 2
        n = n + 1
    ENDM
    EXITM %n
ENDM

__TZm MACRO c
    EXITM %(__TZ(__IMag(c)))
ENDM

__MOdd MACRO c
    EXITM %((__IMag(c)) / __Pow2(__TZ(__IMag(c))))
ENDM

;  __Hibit m  -  position of the most significant bit of m (m >= 1
;  gives 0..15; the callers never pass 0).
;  __Ones m   -  number of set bits of m.
;  New in v3.8: their sum estimates the length of a Horner chain -
;  one shift per bit above the seed plus one add per set bit - and
;  decides between the chain and the native IMUL in FastIMul (see
;  section 4). Same LOCAL discipline as __TZ.
__Hibit MACRO m
    LOCAL t, n
    t = (m)
    n = 0
    WHILE t GT 1
        t = (t) / 2
        n = n + 1
    ENDM
    EXITM %n
ENDM

__Ones MACRO m
    LOCAL t, n
    t = (m)
    n = 0
    WHILE t
        n = n + ((t) AND 1)
        t = (t) / 2
    ENDM
    EXITM %n
ENDM

;  __IsLeaOddX o - 1 (all bits set) if the odd part o is covered by
;  the __LeaOddX tree (section 0b): every odd value 3..21 plus 25,
;  27, 37, 41, 45, 73 and 81. One tree and one predicate serve
;  FastIMul and FastMul since v3.8 (v3.7 had a second, smaller tree
;  for FastMul).
__IsLeaOddX MACRO o
    EXITM %((((o) GE 3) AND ((o) LE 21)) OR ((o) EQ 25) OR ((o) EQ 27) OR ((o) EQ 37) OR ((o) EQ 41) OR ((o) EQ 45) OR ((o) EQ 73) OR ((o) EQ 81))
ENDM

;  __IsLeaOddD o - 1 (all bits set) if the odd part o is computable
;  by __LeaOddX with d = s = t, i.e. without a scratch register
;  distinct from the source: the single-step forms (3, 5, 9) and the
;  d-only two-step forms (15, 25, 27, 45, 81) - exactly the old v3.7
;  FastMul tree. The t-forms (7, 11, 13, 17, 19, 21, 37, 41, 73) run
;  their intermediate through t and read s again after it, so they
;  need dest <> src. New in v4.01 for FastIMul's dest = src case.
__IsLeaOddD MACRO o
    EXITM %((((o) GE 3) AND ((o) LE 15) AND ((o) NE 7) AND ((o) NE 11) AND ((o) NE 13)) OR ((o) EQ 25) OR ((o) EQ 27) OR ((o) EQ 45) OR ((o) EQ 81))
ENDM

;=====================================================================
;  0b. INTERNAL LEA TREE AND EXPANSION TAIL  (v3.7, unified in v3.8)
;=====================================================================
;  __LeaOddX d, s, t, o - one or two LEA forms per covered odd
;  factor o; the caller closes with __MulTail (the SHL for the
;  trailing 2^k of the constant and the NEG for a negative one).
;  t is the scratch register the two-step forms run their
;  intermediate k*s through: FastIMul passes its own dest (free at
;  that point), FastMul passes EDX (which its 386+ paths already
;  own since v2.42) - so ONE tree serves both macros since v3.8
;  (v3.7 had a smaller dest-only tree for FastMul). The single-step
;  forms (3, 5, 9) and the d-only two-step forms (15, 25, 27, 45,
;  81) never read s or t again after the first LEA, so they also
;  work with d = s. Covered: every odd value 3..21 plus 25, 27, 37,
;  41, 45, 73, 81 (__IsLeaOddX); three dependent LEAs buy no more
;  odd factor below 100 that still beats the IMUL. 32-bit registers
;  required (the SIB byte does not exist in 16-bit addressing) and
;  s/t must not be ESP (no scaled index). Verified factor by factor
;  for the d <> s and the d = s shapes (verification note).
;=====================================================================
__LeaOddX MACRO d, s, t, o
    IF (o) EQ 3
        lea d, [s+s*2]              ; 3s
    ELSEIF (o) EQ 5
        lea d, [s+s*4]              ; 5s
    ELSEIF (o) EQ 7
        lea t, [s+s*2]              ; 3s
        lea d, [s+t*2]              ; s + 2 * 3s
    ELSEIF (o) EQ 9
        lea d, [s+s*8]              ; 9s
    ELSEIF (o) EQ 11
        lea t, [s+s*4]              ; 5s
        lea d, [s+t*2]              ; s + 2 * 5s
    ELSEIF (o) EQ 13
        lea t, [s+s*2]              ; 3s
        lea d, [s+t*4]              ; s + 4 * 3s
    ELSEIF (o) EQ 15
        lea d, [s+s*2]              ; 3s
        lea d, [d+d*4]              ; 5 * 3s
    ELSEIF (o) EQ 17
        lea t, [s+s]                ; 2s
        lea d, [s+t*8]              ; s + 8 * 2s
    ELSEIF (o) EQ 19
        lea t, [s+s*8]              ; 9s
        lea d, [s+t*2]              ; s + 2 * 9s
    ELSEIF (o) EQ 21
        lea t, [s+s*4]              ; 5s
        lea d, [s+t*4]              ; s + 4 * 5s
    ELSEIF (o) EQ 25
        lea d, [s+s*4]              ; 5s
        lea d, [d+d*4]              ; 5 * 5s
    ELSEIF (o) EQ 27
        lea d, [s+s*2]              ; 3s
        lea d, [d+d*8]              ; 9 * 3s
    ELSEIF (o) EQ 37
        lea t, [s+s*8]              ; 9s
        lea d, [s+t*4]              ; s + 4 * 9s
    ELSEIF (o) EQ 41
        lea t, [s+s*4]              ; 5s
        lea d, [s+t*8]              ; s + 8 * 5s
    ELSEIF (o) EQ 45
        lea d, [s+s*4]              ; 5s
        lea d, [d+d*8]              ; 9 * 5s
    ELSEIF (o) EQ 73
        lea t, [s+s*8]              ; 9s
        lea d, [s+t*8]              ; s + 8 * 9s
    ELSEIF (o) EQ 81
        lea d, [s+s*8]              ; 9s
        lea d, [d+d*8]              ; 9 * 9s
    ENDIF
ENDM

;  __MulTail d, c - internal macro (v3.8): the shared closing of the
;  FastIMul shortcuts: one SHL for the trailing 2^k of |c| and one
;  NEG for a negative c. Parameter-only (the conditions are literal
;  expressions over c), so it is ASMC-safe like the v2.1 doctrine.
__MulTail MACRO d, c
    IF (__TZm(c)) GT 0
        shl d, (__TZm(c))
    ENDIF
    IF ((c) AND 0FFFFh) AND 8000h
        neg d
    ENDIF
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
;  With .186 or higher these macros are NOT defined: the native
;  "shl reg,imm" (barrel shifter) already exists.
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
    .ERRB <ops>, <push: missing operands>
    FOR o, <ops>
        ??push o
    ENDM
ENDM

    option renamekeyword:<pop>=??pop
pop MACRO ops:VARARG
    .ERRB <ops>, <pop: missing operands>
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
;  the assembler substitutes textually on each expansion (the new
;  __TZ/__TZm/__MOdd helpers are macro FUNCTIONS whose LOCALS never
;  escape, the same proven pattern as __Pow2). ASMC (not JWasm)
;  returns corrupted values when an expansion re-reads its own
;  assembly-time variables, which silently scrambled v2.0's results
;  for a third of the constants; parameter-only expressions are
;  immune. See the v2.1 history entry.
;
;  Since the .186, a power-of-two |const| (1, 2, 4, ..., 32768, and
;  their negatives) is mov + shl + neg (v3.7; v3.9 for ANY
;  destination, memory included: one barrel shift instead of a 1-bit
;  chain (v3.6) or a native IMUL (v3.6 on 386+ for |const| > 8); on
;  the 8086 the expansion is byte-identical to the old chain). On the
;  386 with a
;  32-bit register source, |const| = 2, 4 or 8 collapses to ONE LEA
;  (v3.8): "lea dest,[src+src]" / "lea dest,[src*4]" /
;  "lea dest,[src*8]" - 2 cycles on a 386 and 1 on a 486/Pentium,
;  against 5 for mov + shl. The no-base SIB forms of x4/x8 cost
;  7 bytes instead of 5, and ESP cannot be a scaled index, so a
;  register-ESP source keeps mov + shl (the tree below too, which
;  v3.7 wrongly handed to the assembler as an invalid [esp*...]).
;
;  On a 386+ build with 32-bit register dest AND register source
;  (v3.7): |const| is split into odd part x 2^k (__MOdd/__TZm); the
;  odd part is looked up in the __LeaOddX tree - odd factors 3..21
;  and 25, 27, 37, 41, 45, 73, 81 take ONE or TWO LEAs - the power
;  of two becomes one SHL and a negative constant appends a NEG.
;  Every other constant emits one native three-operand IMUL
;  (9-38 cycles on a 386, 13-42 on a 486, 10-11 on a Pentium), which
;  also preserves src. Two dependent LEAs cost 4 cycles on the 386,
;  2-3 on the 486 and Pentium (LEA is 1 cycle there and the second
;  LEA pays one AGI cycle), which is why the tree beats the IMUL for
;  every factor it covers - the v3.1 "|cte| > 8" threshold is gone
;  for this operand shape.
;
;  The native three-operand IMUL exists since the .186, not since
;  the 386 (v3.8): on a 186/286 it now replaces the Horner chain
;  whenever the chain would outgrow it. Every chain step (mov, shl,
;  add, neg) costs 2-3 cycles on a 186/286, so the chain costs
;  roughly 2 x (highest bit + set bits) of |const| cycles, while
;  IMUL r16,imm costs 21 on a 286 and several times less than the
;  8086's 118-133 on a 186: the IMUL wins once that sum passes 10
;  (FastIMul ax,bx,1000 on a .286 is ONE imul instead of the
;  15-instruction chain of v3.6). The 386+ paths adopt the same
;  rule instead of v3.7's "|cte| > 8": on a 486/Pentium the short
;  chains for 9..15 win and the long ones lose, and on a 386 both
;  rules sit at the IMUL's own 9-22/9-38-cycle spread. A memory
;  source follows the same rule; a BYTE destination always keeps
;  the chain (the three-operand IMUL has no byte encoding, v3.2).
;  A MEMORY destination on the 386+ with a register source takes
;  the IMUL for |const| > 8 (v3.8): the 386 added the
;  "IMUL r/m, reg, imm" form, and a chain on memory is a sequence
;  of read-modify-writes (SHL mem,1 alone is 7 cycles on a 386 and
;  16 on a 286 - where no such IMUL exists and the chain stays).
;  Constants in 32768..65535 are passed to IMUL as their negative
;  two's complement equivalent (__ISgn), so the documented contract
;  also holds for DWORD destinations.
;
;  dest and src may be the SAME operand since v4.01 for every
;  constant whose expansion never re-reads the source after the
;  destination is written: const 0; the powers of two - pure SHL/NEG
;  in place, no seed MOV at all (v4.02: the v4.01 seed "mov dest,
;  src" was a self-MOV under SMART, dead weight under NOSMART and an
;  invalid "mov mem, mem" for a memory destination); on
;  a 386+ with 32-bit registers the d-only LEA-tree factors 3, 5,
;  9, 15, 25, 27, 45 and 81 (the t-forms 7, 11, 13, 17, 19, 21, 37,
;  41 and 73 read the source again after the first LEA and keep
;  requiring dest <> src); and on a .186+ with a non-byte register
;  destination every remaining constant takes one native IMUL.
;  Everything else raises a clear error instead of silently
;  computing the wrong product (the Horner chain adds the source
;  after shifting it; the 8086 has no in-place form and the macro
;  will not clobber a scratch register the caller was not told
;  about).
;
;  Examples:  FastIMul ax, bx, 45    ; ax = bx * 45
;             FastIMul cx, dx, -7    ; cx = -7 * dx
;             FastIMul eax, ebx, 1000; DWORD version with .386
;             FastIMul eax, eax, 48  ; v4.01: in-place, one LEA + SHL
;=====================================================================

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
    IF ((OPATTR (dest)) AND 2) AND ((OPATTR (src)) AND 2)
        .ERR <FastIMul: dest and src cannot both be memory>
        EXITM
    ENDIF
    IF ((cte) LT -32768) OR ((cte) GT 0FFFFh)
        .ERR <FastIMul: const out of range (-32768..65535)>
        EXITM
    ENDIF

    IFDIFI <dest>, <src>
    ; normal case: dest and src are different operands, every path
    ; below may re-read src after dest has been written

    IF (((cte) AND 0FFFFh)) EQ 0                       ; const = 0 (16-bit pattern)
        mov dest, 0
        EXITM
    ENDIF

;  v3.7: |cte| = 2^k: MOV + SHL + NEG (v3.9 at every CPU level and
;  for memory destinations too - on the 8086 the SHL is the macro's
;  1-bit expansion, byte-identical to the old Horner chain, which
;  for a power of two has no add steps; on the .186+ a memory
;  destination takes one native "shl mem,imm" instead of k
;  read-modify-writes). v3.8: on
;  the 386 with a 32-bit register source, k = 1..3 is ONE LEA; ESP
;  is no valid scaled index, so it keeps MOV + SHL.
    IF (((__IMag(cte)) AND ((__IMag(cte)) - 1)) EQ 0)  ; |cte| = 2^k
        IF ((@Cpu AND 0FFh) GE 8) AND ((__RegBits(dest)) EQ 4)
            IFDIFI <src>, <esp>
                IF ((OPATTR (src)) AND 010h) AND ((__RegBits(src)) EQ 4) AND ((__TZm(cte)) GE 1) AND ((__TZm(cte)) LE 3)
                    IF (__TZm(cte)) EQ 1
                        lea dest, [src+src]        ; x*2: 3 bytes
                    ELSEIF (__TZm(cte)) EQ 2
                        lea dest, [src*4]          ; x*4: one LEA
                    ELSEIF (__TZm(cte)) EQ 3
                        lea dest, [src*8]          ; x*8: one LEA
                    ENDIF
                    IF ((cte) AND 0FFFFh) AND 8000h
                        neg dest
                    ENDIF
                    EXITM
                ENDIF
            ENDIF
        ENDIF
        mov dest, src
        __MulTail dest, cte
        EXITM
    ENDIF

;  Non-power-of-two constants on a .186+ with a REGISTER
;  destination (v3.9: the power-of-two path above now serves every
;  destination and CPU level, so the .186+/register gate moves down
;  here).
    IF ((@Cpu AND 0FFh) GE 2) AND ((OPATTR (dest)) AND 010h)

;  v3.7: 386+ with 32-bit register dest and source: LEA tree over
;  the odd part (__LeaOddX; dest doubles as the scratch the
;  two-step forms need) + the shared SHL/NEG tail. v3.9: ESP is
;  guarded as DESTINATION too - the two-step and d-only forms use
;  it as a scaled index, which has no encoding.
        IF ((@Cpu AND 0FFh) GE 8) AND ((__RegBits(dest)) EQ 4)
            IFDIFI <dest>, <esp>
                IFDIFI <src>, <esp>
                    IF ((OPATTR (src)) AND 010h) AND ((__RegBits(src)) EQ 4)
                        IF __IsLeaOddX(__MOdd(cte))
                            __LeaOddX dest, src, dest, __MOdd(cte)
                            __MulTail dest, cte
                            EXITM
                        ENDIF
                    ENDIF
                ENDIF
            ENDIF
        ENDIF

;  v3.8: the native three-operand IMUL exists since the .186 (v3.6
;  only used it on the 386+). Every chain step costs 2-3 cycles on
;  a 186/286 and 1-3 on a 386+, while the IMUL costs 21-34 (286:
;  21) and 9-42 on the 386/486: the chain only wins while it stays
;  short, which the highest-bit + set-bits sum of |cte| measures.
;  The OPATTR check keeps an immediate source (outside the
;  documented register/memory contract) on the chain, which accepts
;  it. A BYTE destination always keeps the chain: the
;  three-operand IMUL has no byte encoding (v3.2).
        IF ((__RegBits(dest)) NE 1) AND ((OPATTR (src)) AND 0012h) AND (((__Hibit(__IMag(cte))) + (__Ones(__IMag(cte)))) GT 10)
            imul dest, src, __ISgn(cte)
            EXITM
        ENDIF
    ENDIF

;  v3.8: 386+ with a MEMORY destination and a register source: the
;  386 added "IMUL r/m, reg, imm"; a chain on memory is a sequence
;  of read-modify-writes (SHL mem,1 = 7 cycles on a 386, 16 on a
;  286 - where no such IMUL exists and the chain stays).
    IF ((@Cpu AND 0FFh) GE 8) AND (((OPATTR (dest)) AND 010h) EQ 0) AND ((OPATTR (src)) AND 010h)
        IF ((__IMag(cte)) GT 8)
            imul dest, src, __ISgn(cte)
            EXITM
        ENDIF
    ENDIF
    mov dest, src                       ; Horner seed: dest = src
;  v4.01: the fifteen __Horn steps are one FOR over the mask list
;  (same calls in the same order; the conditions inside __Horn stay
;  parameter-only, so the ASMC v2.1 re-read pattern is not entered).
    FOR m, <8000h, 4000h, 2000h, 1000h, 800h, 400h, 200h, 100h, 80h, 40h, 20h, 10h, 8h, 4h, 2h>
        __Horn cte, m, dest, src
    ENDM
    IF ((cte) AND 0FFFFh) AND 8000h     ; negative: negate at the end
        neg dest
    ENDIF

    ELSE
;  v4.01: dest = src. Only the paths that never re-read src after
;  dest has been written are safe here: the Horner chain adds the
;  shifted accumulator to src (wrong as soon as dest = src) and the
;  t-form LEA trees run their intermediate through dest, so both are
;  excluded. v4.02: the remaining paths emit no seed at all - dest
;  already holds the source; the old seed "mov dest, src" was a
;  self-MOV that SMART deleted, dead weight under NOSMART, and an
;  invalid "mov mem, mem" for a memory operand. Everything else is a
;  clear error instead of silently computing the wrong product.
    IF (((cte) AND 0FFFFh)) EQ 0                       ; const = 0
        mov dest, 0
    ELSEIF (((__IMag(cte)) AND ((__IMag(cte)) - 1)) EQ 0)  ; |cte| = 2^k
        IF ((@Cpu AND 0FFh) GE 8) AND ((__RegBits(dest)) EQ 4)
            IFDIFI <src>, <esp>
                IF ((OPATTR (src)) AND 010h) AND ((__TZm(cte)) GE 1) AND ((__TZm(cte)) LE 3)
                    IF (__TZm(cte)) EQ 1
                        lea dest, [src+src]
                    ELSEIF (__TZm(cte)) EQ 2
                        lea dest, [src*4]
                    ELSEIF (__TZm(cte)) EQ 3
                        lea dest, [src*8]
                    ENDIF
                    IF ((cte) AND 0FFFFh) AND 8000h
                        neg dest
                    ENDIF
                    EXITM
                ENDIF
            ENDIF
        ENDIF
        __MulTail dest, cte                 ; in place: dest already holds
                                            ; src (v4.02: no seed MOV)
    ELSEIF ((@Cpu AND 0FFh) GE 8) AND ((__RegBits(dest)) EQ 4) AND __IsLeaOddD(__MOdd(cte))
        IFDIFI <dest>, <esp>
            __LeaOddX dest, src, dest, __MOdd(cte)
            __MulTail dest, cte
            EXITM
        ENDIF
        imul dest, src, __ISgn(cte)         ; ESP: no scaled index
    ELSEIF ((@Cpu AND 0FFh) GE 2) AND ((OPATTR (dest)) AND 010h) AND ((__RegBits(dest)) NE 1)
        imul dest, src, __ISgn(cte)         ; .186+: the only in-place form
    ELSE
        .ERR <FastIMul: dest must differ from src for this constant>
    ENDIF
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
;      BX is not touched (factor 1 is just "xor dx,dx").  (v3.7)
;      .186/.286: mov dx,ax / and ax,mask / shl ax,k / shr dx,16-k
;      - four instructions at every k >= 2 (immediate shifts, no CL
;      setup; k = 1 keeps xor dx,dx / shl ax,1 / rcl dx,1). 8086
;      with k >= 8: two half-window shifts
;      (mov dx,ax / shr dx,cl with 16-k, then the low bits left and
;      shifted k) - six instructions instead of the old 2*k shl/rcl
;      pairs, which cost up to 30 instructions for 32768. 8086 with
;      k < 8 keeps the original shl ax,1 / rcl dx,1 loop.
;    - any other const, 386+: native LEA/IMUL (v3.7/v3.8) -
;      movzx eax,ax first; the odd part of the factor is looked up
;      in the __LeaOddX tree with EDX as the scratch of the
;      two-step forms (v3.8: ALL 17 covered factors - 3..21 odd
;      plus 25, 27, 37, 41, 45, 73, 81 - take one or two LEAs; the
;      intermediate runs through EDX, which the 386+ paths already
;      own since v2.42, and the final LEA writes EAX:
;      "lea edx,[eax+eax*2] / lea eax,[eax+edx*2]" is x*7) - and
;      the trailing power of two becomes one SHL; every other
;      factor takes imul eax,eax,const. The 32-bit product of AX*f
;      (both under 65536) always fits EAX, so AX = its low word for
;      free and the closing SHLD lifts its high word into DX: the
;      DX:AX pair the macro promises. (v2.4 emitted
;      "imul edx,eax,const" - the product landed in EDX, DX took
;      its LOW word and AX stayed the multiplicand; v2.41 fixed AX
;      but still never wrote DX. Both broke every caller that
;      divides the pair, 4VIEW's fix 90 percent freeze being the
;      reported case.) BX and CL are not touched and the high word
;      of EAX is cleared by the MOVZX.
;    - const = (2^k - 1) * 2^j, k >= 4    : 32-bit Mersenne shortcut
;      (new in v2.0): ((x << k) - x) << j with SUB/SBB; turns dense
;      factors like 0FFFFh into ~2/3 of the instructions. 8086 only
;      since v2.4 - and since v3.8 with a CPU-dependent budget: on
;      a 286 its fixed k >= 4 cost (24+ cycles) can never beat the
;      21-cycle MUL, so it only fires there for k + j <= 3, i.e.
;      never; on a 186 for k + j <= 5.
;    - MSB-to-LSB Horner with the DX:AX accumulator (v1, 8086 only
;      since v2.4)
;    - real MUL when the expansion would come out worse. v3.8 makes
;      the budget CPU-dependent: the 8086 keeps the v3.1 model
;      (chain = 5 fixed + 4 per shl/rcl pair + 6 per add/adc pair,
;      mov cx,imm + MUL r16 = 122-137, breakeven 117); the 186 kept
;      the 8086 pair costs but multiplies several times faster
;      (budget 27); the 286 runs every register op in 2 cycles and
;      MUL r16 in 21 (budget 19), so there only the tiny factors
;      keep a chain.
;=====================================================================

FastMul MACRO factor
    LOCAL fmF, fmHi, fmOnes, fmJ, fmM, fmK, fmI, fmAd, fmMul, fmMeK
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

;  v4.01: the three inline counting loops are the section-0
;  functions now (same values, ~18 lines shorter; the functions are
;  pure parameter expressions, immune to the ASMC re-read pattern).
    fmHi = __Hibit(fmF)             ; position of the highest bit
    fmOnes = __Ones(fmF)            ; set bits of the factor
    fmJ = __TZ(fmF)                 ; trailing zeros: fmF = fmM * 2^fmJ
    fmM = fmF / __Pow2(fmJ)         ; (the 386+ tree uses the odd part)
    fmK = __Hibit(fmM) + 1          ; number of bits of the odd part

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
        ELSEIF ((@Cpu AND 0FFh) GE 2)   ; NEW v3.7: .186/.286 immediate
            IF fmHi EQ 0            ; shifts: four instructions at
                xor dx, dx          ; every k >= 2, no CL setup
            ELSEIF fmHi EQ 1
                xor dx, dx
                shl ax, 1
                rcl dx, 1
            ELSE
                mov  dx, ax
                and  ax, __Pow2(16 - fmHi) - 1  ; keep the low 16-k bits
                shl  ax, fmHi                   ; AX = low word
                shr  dx, 16 - fmHi              ; DX = X >> (16-k) = high
            ENDIF
        ELSEIF fmHi GE 8            ; 8086, k >= 8: two halves (v2.3)
            mov  dx, ax
            mov  cl, 16 - fmHi      ; (16-k) is a constant
            shr  dx, cl             ; DX = X >> (16-k) = high word
            and  ax, __Pow2(16 - fmHi) - 1  ; keep the low 16-k bits
            mov  cl, fmHi
            shl  ax, cl             ; AX = (X AND mask) << k = low word
        ELSE                        ; 8086, k < 8: the short way (v1)
            xor dx, dx
            REPEAT fmHi             ; one shl/rcl pair per bit (v4.02)
                shl ax, 1
                rcl dx, 1
            ENDM
        ENDIF
        EXITM
    ENDIF

    IF ((@Cpu AND 0FFh) GE 8)       ; 386+: native LEA/IMUL (v3.1)
        movzx eax, ax               ; EAX = zero-extended multiplicand
        IF __IsLeaOddX(fmM)         ; odd part in the tree (v3.8: the
            __LeaOddX eax, eax, edx, fmM   ; full 17-factor tree; EDX
            IF fmJ GT 0             ; is scratch the 386+ paths own)
                shl eax, fmJ       ; times the trailing 2^fmJ
            ENDIF
        ELSE
            imul eax, eax, fmF      ; EAX = AX*f, exact: it always
        ENDIF                       ; fits 32 bits (v2.4, non-LEA)
        shld edx, eax, 16           ; DX = high word: the DX:AX
        EXITM                       ; contract (v2.42)
    ENDIF

;  v3.8: CPU-dependent cost model for the Mersenne shortcut and the
;  MUL fallback (v3.6 used the 8086 model at every CPU level). The
;  8086 numbers are the classic ones: shl/rcl pair 4 cycles, add/adc
;  pair 6, mov cx,imm + MUL r16 122-137. The 186 kept the 8086 pair
;  costs but multiplies several times faster; the 286 runs every
;  register op in 2 cycles and MUL r16 in 21 (+2 for the mov cx,imm).
    IF ((@Cpu AND 0FFh) EQ 1)
        fmAd = 6                        ; add/adc pair
        fmMul = 117                     ; chain budget vs MUL
        fmMeK = 26                      ; (k + j) budget: 4*(k+j)+6 LE 110
    ELSEIF ((@Cpu AND 0FFh) AND 4)      ; .286
        fmAd = 4
        fmMul = 19                      ; MUL 21 + mov 2 - fixed 4
        fmMeK = 3                       ; 4*(k+j)+8 LE 23: never (k GE 4)
    ELSE                                ; .186
        fmAd = 6
        fmMul = 27                      ; MUL ~30 + mov - fixed 5
        fmMeK = 5                       ; 4*(k+j)+12 LE 32
    ENDIF
;  v4.01: the budget test measures (fmK + fmJ), as the v3.8 model
;  documents - it measured (fmHi + fmJ) = (fmK + 2*fmJ - 1), which
;  let the factor 15 fire on a 286 (24 cycles vs the 23-cycle MUL
;  the model assigns it) and denied the shortcut to 8086 factors
;  with a large trailing power of two (61440 = 15 * 4096 and
;  friends). See the v4.01 verification note for the route census.
    IF (fmM EQ ((__Pow2(fmK)) - 1)) AND (fmK GE 4) AND ((fmK + fmJ) LE fmMeK)
        ; 32-bit Mersenne shortcut: DX:AX = ((x << k) - x) << j
        mov bx, ax                  ; keep the multiplicand
        xor dx, dx
        REPEAT fmK                  ; DX:AX = x << k (v4.02: REPEAT, the
            shl ax, 1               ; __SHx pattern - no counter to
            rcl dx, 1               ; maintain)
        ENDM
        sub ax, bx
        sbb dx, 0                   ; propagate the SUB carry
        REPEAT fmJ                  ; << j: times the trailing 2^j
            shl ax, 1
            rcl dx, 1
        ENDM
        EXITM
    ENDIF

    IF fmHi*4 + (fmOnes-1)*fmAd GT fmMul ; expansion would be worse
        mov cx, fmF                 ; than MUL (v3.8: the budget
        mul cx                      ; follows the CPU - see above;
        EXITM                       ; 8086: ~122-137 with the mov cx,
    ENDIF                           ; v3.1 threshold was a flat 117)

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
;  the imm8 form whenever the value fits; on registers clrflag fits
;  its AND mask to the operand size (v3.9 - the 32-bit NOT of the
;  top bit did not encode: "clrflag ax, 15" was "and ax, 0FFFF7FFFh")
;  and rejects a bit beyond the operand with a clear error instead
;  of the silent no-op the fitted mask produced (v4.0).
;=====================================================================

;  __BitRange name, bit - internal macro: the shared range check of
;  the five flag macros (v3.2). The macro name is passed as a
;  parameter so the error text stays per-macro. v4.01: .ERRNZ, the
;  assembler's own high-level conditional error, replaces the
;  IF/.ERR/EXITM/ENDIF block (same test, one line).
__BitRange MACRO name, bit
    .ERRNZ ((bit) LT 0) OR ((bit) GT 31), <name: bit index must be between 0 and 31>
ENDM

setflag MACRO rm, bit
    __BitRange setflag, bit
    or rm, __Pow2(bit)
ENDM

clrflag MACRO rm, bit
    __BitRange clrflag, bit
;  v3.9: on a REGISTER the mask is fitted to the operand size. The
;  plain "NOT __Pow2(bit)" is a 32-bit complement: when the bit is
;  the top bit of a smaller operand the immediate does not encode
;  ("clrflag ax, 15" emitted "and ax, 0FFFF7FFFh" = -32769; byte
;  registers died the same way from clrflag al, 7 on).
;  v4.0: a bit beyond the operand is an ERROR - the fitted mask
;  turned "clrflag al, 15" into the silent no-op "and al, 0FFh"
;  where the documentation promises the assembler's "bit does not
;  exist" error (setflag/flipflag/testflag/maskflag still raise it
;  through the unencodable immediate). Memory operands keep the
;  assembler's own check.
    IF (OPATTR (rm)) AND 010h
        IF (bit) GE (8 * (__RegBits(rm)))
            .ERR <clrflag: bit does not exist in the operand>
            EXITM
        ENDIF
        and rm, (NOT __Pow2(bit)) AND (__Pow2(8 * (__RegBits(rm))) - 1)
    ELSE
        and rm, NOT __Pow2(bit)     ; memory: only the assembler
    ENDIF                           ; knows its size
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
;           except when the field IS the whole operand (lo = 0,
;           width >= size): one MOV writes it (v3.9 - an OR alone
;           cannot clear the field bits val has at 0, and the
;           v3.2 full-16-bit case below the 386 emitted exactly
;           that OR, silently keeping old field bits; v3.9 also
;           fits the AND mask to the operand size of every
;           REGISTER: the plain 32-bit NOT of a field that reaches
;           the top bit without covering it, e.g. "setfield al,
;           4, 4", did not encode). On those CPUs below the 386 a
;           field wider than the 16-bit operand is an error instead
;           of silently emitting wrong code; on a 386+ build 32-bit
;           fields work as documented. For MEMORY operands the size
;           is not visible to the macro: below the 386 the
;           full-16-bit field uses the fitted mask (2^lo - 1, or a
;           MOV when lo = 0); on a 386+ build a field that reaches
;           the top bit of a 16-bit memory operand without covering
;           it keeps the plain NOT mask and needs a manual "and"
;           with the right 16-bit mask. v4.0: on a REGISTER a field
;           that does not fit (lo + width above the operand size)
;           is an error, like the <386 16-bit check - the fitted
;           masks had turned the overflow into a silent no-op or a
;           partial insert that dropped the high val bits - and
;           lo = 0 with width = 32 is accepted (one MOV, memory
;           included on a 386+ build).
;
;       getfield dest, src, lo, width
;           Extracts the field with zero extension: copies src into
;           dest, shifts right by lo bits and masks the rest. When
;           dest and src are the same operand no MOV is emitted
;           (v3.9: the same MEMORY operand is allowed too - no MOV
;           is needed there either); two DIFFERENT memory operands
;           are an error. The final AND is skipped when it is an
;           identity (v3.9: after the SHR the bits above the field
;           are already zero whenever lo + width covers a REGISTER
;           destination; v4.0 fixes the condition, which skipped
;           the AND on every MEMORY destination too, where it is
;           never an identity). On a 386+ build with same-size
;           register operands, lo = 0 and a width of exactly 8 or
;           16 below the destination size, ONE MOVZX replaces the
;           whole expansion (getfield eax, ebx, 0, 8 is "movzx
;           eax,bl"); v4.0: width 16 takes the low WORD - v3.9
;           wrongly took the low byte ("getfield eax, ebx, 0, 16"
;           emitted "movzx eax, bl") - and every 32-bit register
;           qualifies there ("movzx eax, si"); the width-8 byte
;           forms stay limited to ax/eax/bx/ebx/cx/ecx/dx/edx
;           (SI/DI/BP/SP have no byte halves and keep the old
;           path). v4.0: a register source SMALLER than the
;           destination is seeded with one MOVZX instead of the
;           unencodable "mov dest, src" ("getfield eax, bx, 4, 8"
;           died with an assembler error; below the 386 the
;           widening goes through the movzx macro into AX/BX/CX/DX,
;           the only destinations it can widen), and a destination
;           smaller than the source raises a clear error. Since
;           v3.8 a field that does not fit the 16-bit operand
;           raises the same error as setfield on CPUs below the
;           386 (before, the bits beyond 15 silently shifted out
;           to 0).
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
;  v4.0: width = 32 is accepted for lo = 0 - a field that covers a
;  whole 32-bit operand ("setfield eax, 0, 32, val") satisfies the
;  documented "lo + width up to 32" limit and was wrongly rejected
;  by the separate width cap. v4.01: .ERRNZ instead of the
;  IF/.ERR/EXITM/ENDIF block (same test, one line).
    .ERRNZ ((lo) LT 0) OR ((width) LT 1) OR (((lo) + (width)) GT 32) OR (((width) GT 31) AND ((lo) GT 0)), <name: invalid range of lo/width (lo + width up to 32)>
ENDM

setfield MACRO rm, lo, width, val
    __FieldRange setfield, lo, width
    IF ((@Cpu AND 0FFh) LT 8) AND (((lo) + (width)) GT 16)
        .ERR <setfield: field does not fit the 16-bit operand of this CPU>
        EXITM
    ENDIF
;  v3.9: on a REGISTER the size is known (__RegBits), so the AND
;  masks are fitted to the operand (the plain 32-bit NOT of a field
;  that reaches the top bit without covering it does not encode:
;  "setfield al, 4, 4" emitted "and al, 0FFFFFF0Fh" on every CPU and
;  "setfield ax, 12, 4" died the same way on a 386+ build). A field
;  that IS the whole register (lo = 0, width >= size) becomes one
;  MOV - an OR alone could never clear the field bits val has at 0
;  (FIXED, silent wrong code since v3.2: the <386 full-16-bit case
;  emitted only the OR, so "setfield ax, 12, 4, 5" kept the old
;  bits 13 and 15). This MOV preserves the flags; every other
;  setfield destroys them.
    IF (OPATTR (rm)) AND 010h
;  v4.0: a field that does not fit the register is an ERROR, not a
;  silent truncation: v3.9's fitted masks turned the overflow into a
;  no-op ("setfield al, 8, 8, 5h" assembled to "and al, 0FFh / or
;  al, 0") or dropped the high val bits of a straddling field, while
;  the <386 check above already rejects the same overflow on 16-bit
;  operands. The full-operand MOV below (lo = 0, width = size) is
;  not affected.
        IF ((lo) + (width)) GT (8 * (__RegBits(rm)))
            .ERR <setfield: field does not fit the operand>
            EXITM
        ENDIF
        IF ((lo) EQ 0) AND ((width) GE (8 * (__RegBits(rm))))
            mov rm, ((val) AND (__Pow2(width) - 1)) AND (__Pow2(8 * (__RegBits(rm))) - 1)
            EXITM
        ENDIF
        and rm, (NOT ((__Pow2(width) - 1) * __Pow2(lo))) AND (__Pow2(8 * (__RegBits(rm))) - 1)
        or  rm, (((val) AND (__Pow2(width) - 1)) * __Pow2(lo)) AND (__Pow2(8 * (__RegBits(rm))) - 1)
        EXITM
    ENDIF
    IF ((@Cpu AND 0FFh) LT 8) AND (((lo) + (width)) EQ 16)
            ; memory below the 386: the field covers the whole 16-bit
            ; operand. lo = 0: one MOV. lo > 0: the fitted mask
            ; (2^lo - 1) encodes where the plain 32-bit NOT did not;
            ; v3.2 emitted only the OR here and silently kept the
            ; old bits of the field (same bug as above)
        IF (lo) EQ 0
            mov rm, (val) AND 0FFFFh
        ELSE
            and rm, __Pow2(lo) - 1
            or  rm, ((val) AND (__Pow2(width) - 1)) * __Pow2(lo)
        ENDIF
        EXITM
    ENDIF
;  v4.0: a full 32-bit field on memory (only a 386+ build reaches
;  this: below the 386 the check above already rejected
;  lo + width > 16, and the register case took its MOV above) - one
;  MOV, like every full-operand field.
    IF ((lo) EQ 0) AND ((width) GE 32)
        mov rm, (val) AND 0FFFFFFFFh
        EXITM
    ENDIF
    and rm, NOT ((__Pow2(width) - 1) * __Pow2(lo))
    or  rm, ((val) AND (__Pow2(width) - 1)) * __Pow2(lo)
ENDM

;  __GFTail d, lo, width, bits - internal macro (v4.0): the shared
;  closing of every getfield path - the right shift (skipped for
;  lo = 0) and the final AND. bits is the visible operand size in
;  bytes (8 * __RegBits of the register the tail runs on, 0 for a
;  memory operand whose size is not visible). On a REGISTER the AND
;  is skipped when it is an identity - after the SHR the bits above
;  the field are already zero whenever lo + width covers the
;  register - while a MEMORY operand always takes it (FIXED v4.0:
;  the v3.9 condition tested 8 * 0 for memory and skipped the AND
;  there, keeping source bits above the field). A full 32-bit field
;  (width = 32) covers any operand and always skips it. Parameter
;  only, like the rest of the file's expansions (ASMC-safe, v2.1).
__GFTail MACRO d, lo, width, bits
    IF (lo) GT 0
        shr d, (lo)             ; uses the SHR macro on 8086 (1 bit at a time)
    ENDIF
    IF (((lo) + (width)) LT (8 * (bits))) OR (((bits) EQ 0) AND ((width) LT 32))
        and d, __Pow2(width) - 1
    ENDIF
ENDM

getfield MACRO dest, src, lo, width
    __FieldRange getfield, lo, width
    IF ((@Cpu AND 0FFh) LT 8) AND (((lo) + (width)) GT 16)
        .ERR <getfield: field does not fit the 16-bit operand of this CPU>
        EXITM
    ENDIF
;  v3.9: the "cannot both be memory" check only applies to two
;  DIFFERENT memory operands - dest = src is one operand and needs
;  no MOV, so "getfield var, var, 4, 4" is legal now.
    IFDIFI <dest>, <src>            ; v4.02: one test, no empty branch
        IF ((OPATTR (dest)) AND 2) AND ((OPATTR (src)) AND 2)
            .ERR <getfield: dest and src cannot both be memory>
            EXITM
        ENDIF
    ENDIF
;  v4.0: register operands of DIFFERENT sizes. The old seed
;  "mov dest, src" has no mixed-size encoding, so every mixed
;  getfield ("getfield eax, bx, 4, 8", "getfield ax, al, 0, 8")
;  died with an assembler error on the MOV. A LARGER destination is
;  now seeded with ONE MOVZX and the identity of the final AND is
;  measured against the SOURCE size (MOVZX has already zeroed every
;  bit above it). v4.01: one call serves both CPU classes - on a
;  386+ movzx is the native instruction and widens into any
;  register; below the 386 it is the section-2 macro, which widens
;  into AX/BX/CX/DX only and raises its own clear error for every
;  other destination (getfield's duplicated four-way dispatch is
;  gone). A SMALLER destination has no encoding at all (the macro
;  cannot name the subregisters of si/di/bp/sp) and keeps the clear
;  error instead of the invalid MOV.
    IF ((__RegBits(dest)) GT 0) AND ((__RegBits(src)) GT 0) AND ((__RegBits(dest)) LT (__RegBits(src)))
        .ERR <getfield: dest is smaller than src>
        EXITM
    ENDIF
    IF ((__RegBits(dest)) GT (__RegBits(src))) AND ((__RegBits(src)) GT 0)
        movzx dest, src
        __GFTail dest, lo, width, __RegBits(src)
        EXITM
    ENDIF
;  v3.9, 386+: register source and destination of the SAME size with
;  lo = 0 and a width of exactly 8 or 16 below the destination size:
;  ONE MOVZX does the whole extraction (other widths would keep bits
;  beyond the field - MOVZX has no 4-bit form). v4.0: width 16 takes
;  the low WORD - v3.9 wrongly took the low byte ("getfield eax,
;  ebx, 0, 16" emitted "movzx eax, bl") - and every 32-bit register
;  qualifies there ("movzx eax, si" is a legal form). The width-8
;  byte forms stay limited to the registers that have byte halves;
;  SI/DI/BP/SP keep the old path.
    IF ((@Cpu AND 0FFh) GE 8) AND ((lo) EQ 0) AND (((width) EQ 8) OR ((width) EQ 16)) AND ((width) LT (8 * (__RegBits(dest)))) AND ((__RegBits(src)) EQ (__RegBits(dest)))
        IF (width) EQ 8
            IFIDNI <src>, <ax>
                movzx dest, al
                EXITM
            ELSEIFIDNI <src>, <eax>
                movzx dest, al
                EXITM
            ELSEIFIDNI <src>, <bx>
                movzx dest, bl
                EXITM
            ELSEIFIDNI <src>, <ebx>
                movzx dest, bl
                EXITM
            ELSEIFIDNI <src>, <cx>
                movzx dest, cl
                EXITM
            ELSEIFIDNI <src>, <ecx>
                movzx dest, cl
                EXITM
            ELSEIFIDNI <src>, <dx>
                movzx dest, dl
                EXITM
            ELSEIFIDNI <src>, <edx>
                movzx dest, dl
                EXITM
            ENDIF
        ELSE                            ; width = 16: only 32-bit pairs
            IFIDNI <src>, <eax>         ; reach the gate (16 LT 8 * 4)
                movzx dest, ax
                EXITM
            ELSEIFIDNI <src>, <ebx>
                movzx dest, bx
                EXITM
            ELSEIFIDNI <src>, <ecx>
                movzx dest, cx
                EXITM
            ELSEIFIDNI <src>, <edx>
                movzx dest, dx
                EXITM
            ELSEIFIDNI <src>, <esi>
                movzx dest, si
                EXITM
            ELSEIFIDNI <src>, <edi>
                movzx dest, di
                EXITM
            ELSEIFIDNI <src>, <ebp>
                movzx dest, bp
                EXITM
            ELSEIFIDNI <src>, <esp>
                movzx dest, sp
                EXITM
            ENDIF
        ENDIF
    ENDIF
    IFIDNI <dest>, <src>
        __GFTail src, lo, width, __RegBits(src)
    ELSE
        mov dest, src
        __GFTail dest, lo, width, __RegBits(dest)
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
;  (FIXED in v4.0: the NOSMART branch of both expansions held only
;  a comment, so "mov reg, reg" and "xchg reg, reg" were eliminated
;  in NOSMART too - the documented pass-through is real now.)
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
            IF ??smart                  ; SMART: assembles to nothing
            ELSE
                ??mov dest, val         ; NOSMART: the original
            ENDIF                       ; instruction (FIXED v4.0:
        ELSE                            ; the ELSE held only a comment,
                                        ; so NOSMART eliminated the
                                        ; "reg, reg" forms too instead
                                        ; of passing them through)
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
            IF ??smart                  ; SMART: assembles to nothing
            ELSE
                ??xchg a, b             ; NOSMART: the original
            ENDIF                       ; instruction (FIXED v4.0,
        ELSE                            ; same mov bug above)
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
;  (__RegBits = 2). Since v3.7 the substitution also requires a
;  16-bit segment (@WordSize EQ 2): in a use32 segment OFFSET is a
;  32-bit value and "mov reg16, OFFSET var" truncates it or fails
;  to encode, so such a LEA passes through unchanged there.
;  NOSMART disables the substitution. FastIMul and FastMul expand
;  their internal LEA forms through this macro; the operands are
;  indexed, carry no direct-addressing bit and pass through
;  unchanged.
;=====================================================================

    option renamekeyword:<lea>=??lea
lea MACRO reg, mem
    IF ??smart
        IF @WordSize EQ 2                   ; use16 only (v3.7): OFFSET
            IF ((OPATTR (mem)) AND 01001010b) EQ 01010b ; direct memory var
                IF (__RegBits(reg)) EQ 2                ; MOV r16,imm16 is
                    mov reg, OFFSET mem                 ; 3 bytes vs 4 for
                    EXITM                               ; LEA r16,m16
                ENDIF
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
;  - v3.9, 386+ builds: none of this machinery is needed - the 386
;    added near conditional jumps (0F 8x rel), so every macro just
;    passes through and the assembler picks the short or near
;    encoding from the real distance. A forward jump that fits
;    saves the 3 bytes the extended form used to add, and an
;    out-of-range one saves the whole trampoline. SMART and
;    NOSMART are equivalent for Jcc on a 386+ build.
;=====================================================================

;  __Jcc jshort, jinv, target - the shared body of all 30 jump
;  macros (v3.4): jshort is the renamed short instruction, jinv its
;  inverse, used to skip over the near JMP of the extended form.
;  v3.9: on a 386+ build the macro just passes through - the 386
;  added near conditional jumps (0F 8x rel), so the assembler picks
;  the short or near encoding from the real distance and no
;  trampoline is ever needed (SMART and NOSMART are equivalent for
;  Jcc there). JCXZ/LOOP never got a long encoding and keep
;  __SExt at every CPU level.
__Jcc MACRO jshort, jinv, target
    LOCAL jext
    IFB <target>
        .ERR <jump: missing operand>
        EXITM
    ENDIF
    IF ??smart
        IF ((@Cpu AND 0FFh) GE 8)                       ; 386+: native
            jshort target                               ; near Jcc
        ELSEIFIDNI <target>, <@F>
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