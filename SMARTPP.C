/*=====================================================================
*  SMARTPP  --  a conservative peephole pre-processor for
*  8086..x86-64 assembly source (MASM / JWasm / UASM / ASMC syntax,
*  the SMART.INC family).  One file, standard C.
*
*  Copyright (c) Javier Gutiérrez Chamorro (Guti)
*=====================================================================
*  SMART.INC can only optimize inside a macro expansion: a macro
*  sees its own arguments, never the surrounding instruction flow
*  (SMART.INC v3.4, "considered and NOT implemented").  SMARTPP is
*  the external pass that closes that gap.  It reads an .ASM source,
*  applies a small set of provably-safe rewrites and writes the
*  result; the assembler then re-assembles it and recomputes every
*  displacement, so removing bytes can never corrupt a jump.
*
*  THE REWRITE RULES (all enabled by default)
*  ------------------------------------------------
*    P1   "mov R, R" / "xchg R, R" (the same register)  ->  deleted.
*         Changes no register, no memory, no flags.
*
*    P2   Dead register store: "mov R, reg/imm/mem", "lea R, mem" or
*         "movzx/movsx R, reg" (flag-neutral) immediately followed by
*         an instruction that fully overwrites R without reading it
*         ("mov", "lea", "pop", "xor R, R", "movzx/movsx")  ->  the
*         first is deleted.  Partial overwrites ("mov ax, 1 /
*         mov al, bl") never fire; the second instruction's source is
*         checked for hidden reads of R ("movzx eax, al" reads al)
*         and blocks it.  Loads whose source is memory are included
*         by default (v1.10; they were opt-in -mm before).
*
*    P3   "push X" / "pop X" with the same register operand  ->
*         both deleted (stack and X end exactly where they started,
*         flags untouched).  Also "pushf/popf" (any CPU) and
*         "pusha/popa" (186+).  Memory operands are never touched.
*
*    P4   (CPU 186+, default since v1.10) two consecutive
*         shifts/rotates with the same mnemonic ("shl" and "sal"
*         count as the same, v1.60), the same REGISTER
*         destination and constant counts  ->  merged into one
*         ("shl ax,1 / shl ax,1" becomes "shl ax,2").  CF and the
*         result are identical; OF becomes undefined exactly as it
*         is for any multi-bit shift.
*
*    P5   Jump threading: "jmp L" / "j<cc> L" where L is followed
*         only by further labels and then an unconditional "jmp L2"
*         ->  retargeted to L2.  (v1.50) a conditional jump is also
*         threaded through a following j<same cc> L2 (same canonical
*         condition, so jz/je alias): taken paths reach L2 exactly
*         as before and not-taken paths fall into the unchanged
*         intermediate jcc, which takes the same branch.  Every
*         path that reached the intermediate JMP reaches the same
*         target.  Only labels defined exactly once are followed;
*         @F/@B, indirect and short/near/far-qualified targets are
*         never touched.
*
*    P6   (v1.10) a "jmp L" / "j<cc> L" whose target label already
*         introduces the very next code line  ->  deleted: taken or
*         not, execution reaches the same instruction.  Flags are
*         untouched by jmp/jcc, so this is exact.
*
*    P7   (v1.10) branch inversion over a bridge jump:
*         "j<cc> L1 / jmp L2 / L1:"  ->  "j<not cc> L2", and the
*         bridge jmp is deleted.  The cc paths fall into L1's code
*         exactly as before; the not-cc paths reach L2 exactly as
*         the bridge did.  Flags are untouched.  The bridge must
*         carry no label (nothing else may jump to it) and L1's
*         code must start right after it.  All 30 supported
*         conditions have an exact inverse.
*
*    P8   (v1.20) "or R, R" / "and R, R" (the same register,
*         16/32-bit)  ->  "test R, R".  Exact equivalence: both
*         clear CF and OF, set SF/ZF/PF from R, leave AF undefined,
*         and change no register.  No analysis needed.
*
*    P9   (v1.20) "mov R, 0" (16/32-bit register)  ->  "xor R, R",
*         but ONLY when the flag-liveness scan proves that every
*         path from the instruction overwrites all six status
*         flags before any of them is read (xor clears CF/OF and
*         sets ZF; mov preserves them).  See THE FLAG SCAN below.
*
*    P10  (v1.20) "add R, 1" (16/32-bit register)  ->  "inc R",
*         but ONLY when the scan proves CF is overwritten on every
*         path before it is read (add defines CF, inc preserves it;
*         every other flag is set identically by both).
*
*    P11  (v1.20) "cmp R, 0" (16/32-bit register)  ->  "test R, R",
*         but ONLY when the scan proves AF is overwritten on every
*         path before it is read (cmp R,0 sets AF=0; test leaves AF
*         undefined; every other flag is identical).  The classic
*         "cmp ax,0 / jz L" -> "test ax,ax / jz L" fires, because
*         jz reads ZF, not AF.
*
*    P12  (v1.30) duplicate consecutive jumps to the same target:
*         "j<cc> L / j<same condition> L" -> the second is dead
*         (same flags, nothing between);  "j<cc> L / jmp L" -> the
*         jcc is deleted (both paths reach L);  "jmp L / <jump> L"
*         -> the second is unreachable and deleted.
*
*    P13  (v1.30) unreachable code after an unconditional jmp: the
*         run of following instruction lines that carry no label is
*         deleted.  The scan stops at the first label, data
*         definition (db/dw/dd/...), directive, or unknown line
*         (macro calls included): only recognized instructions are
*         removed, so jump tables and assembler-time side effects
*         are never touched.
*
*    P14  (v1.30) "xchg R,S / xchg R,S" (same pair, either operand
*         order)  ->  both deleted: two swaps restore everything,
*         and xchg touches no flags.
*
*    P15  (v1.30) "mov R,S / mov S,R"  ->  the second is deleted:
*         it writes S with S's own value (R was just set to it).
*         Registers only; mov touches no flags.
*
*    P16  (v1.30) constant folding (FPC-style): "add R,c1 / add R,c2"
*         or the same with sub, register destination, constant
*         counts  ->  one "add/sub R,c1+c2".  The result and every
*         flag are identical EXCEPT OF (the overflow of the two
*         half-adds can differ from the overflow of the total), so
*         the scan must prove OF is dead; the sum is kept within
*         immediate-encoding range.
*
*    P17  (v1.30, extended v1.40) FPC's LEA conversion:
*         "lea R,[R+const]"  ->  "add R,const" (or "sub" for
*         negative, "inc/dec" for +-1, deleted for 0).  lea
*         touches no flags; the replacement defines them, so the
*         scan must prove them dead (CF survives inc/dec,
*         matching lea).  Two exact cousins need no scan:
*         "lea R,[const]" -> "mov R,const" and, at equal width,
*         "lea R,[S]" -> "mov R,S" (lea computes the offset
*         only, no segment is involved; mixed widths would
*         zero-extend where mov would not, so they stay).  Other
*         index forms ([R+SI], "[4-eax]", scaled, ...) are left
*         alone.
*
*    P18  (v1.30) "add R,0" / "sub R,0"  ->  deleted when the scan
*         proves all six status flags are dead (they are the only
*         effect).
*
*    P19  (v1.40) two consecutive identical "cmp R,S" / "test R,S"
*         (S a register or a plain constant)  ->  the first is
*         deleted: it defines exactly the flags the second
*         overwrites with the same values, nothing reads them in
*         between.  Memory operands stay (repeated I/O reads may
*         be meaningful).
*
*    P20  (v1.40) "shl/shr/sar/rol/ror/rcl/rcr R,0"  ->  deleted:
*         a zero count moves no bit and leaves every flag
*         unchanged on the 8086 through the 686.  Registers only.
*
*    P21  (v1.40, extended v1.50) two consecutive identical
*         "cld/std/cli/sti/clc/stc"  ->  the second is deleted
*         (same flag bit, same value, nothing in between).  "cmc"
*         is NOT idempotent and is handled by P25 instead.
*
*    P22  (v1.40) "inc R / dec R" (either order, same register,
*         not SP)  ->  both deleted when the scan proves all six
*         status flags dead: the value is restored, but the final
*         flags come from the second instruction.  SP is excluded
*         (an interrupt between the two would push at a
*         misaligned stack).
*
*    P23  (v1.50) "not R / not R" (same register)  ->  both
*         deleted: the value is restored and "not" touches no
*         flag at all, so the pair is exactly dead with no scan.
*         Registers only (a repeated write to memory-mapped
*         space may be meaningful).
*
*    P24  (v1.50) "neg R / neg R" (same register, not SP)  ->
*         both deleted when the scan proves all six status flags
*         dead (final flags are the second neg's).  SP excluded
*         as in P22.
*
*    P25  (v1.50) "cmc / cmc"  ->  both deleted: the carry is
*         inverted twice, i.e. restored, and no other flag is
*         touched.  Exact, no scan.
*
*    P26  (v1.50) "xor R,R" immediately overwritten by a
*         full-cover writer that defines no flags (mov/lea/movzx/
*         pop)  ->  the xor is deleted when the scan proves all
*         six status flags dead (xor defines them all; the writer
*         defines none and the scan walks past it).
*
*    P27  (v1.50) "add R,S / sub R,S" (either order, both
*         operands registers, different registers)  ->  both
*         deleted when the scan proves all six status flags
*         dead: R is restored and S is never written.  SP as
*         destination excluded as in P22.
*
*    P28  (v1.60) two consecutive identical "cbw/cwde/cwd/cdq"
*         (AT&T names "cbtw/cwtl/cwtd/cltd" included)  ->  the
*         second is deleted: it re-derives the same high half
*         from the same, unchanged low half and touches no flags.
*
*    The rules below (v1.70) go after the idioms that the 1990s code
*    generators (Turbo Pascal, Borland C, Watcom C/C++) leave behind
*    and that a newer CPU does in one instruction.  Rules that need
*    movzx/movsx work from CPU 386 on, so they depend on -m386 or a
*    .386 directive; they are written in Intel syntax only (-att
*    leaves them silent, except P32 and P36).
*
*    P29  (v1.70, CPU 386+) zero-extending load: "xor T,T / mov L,SRC"
*         (L the low byte or word of T), "xor H,H / mov L,SRC" (H =
*         AH/CH/DH/BH, L the low byte of the same family; this one
*         also in the order "mov L,SRC / xor H,H")  ->  "movzx T,SRC".
*         xor defines all six status flags and movzx none, so the
*         scan must prove them dead.  SRC is a register (of another
*         family than T) or a memory operand that does not use T's
*         family ("xor eax,eax / mov al,[eax]" reads [0], movzx would
*         not).  A missing size is added ("byte ptr [bx]"); a bare
*         symbol is accepted only when this file defines it with
*         db/dw/dd (it could be an EQU constant, which movzx cannot
*         take).  movzx is smaller, but on a 486/Pentium it costs 3
*         clocks against 2 for xor+mov: -nz keeps the pair.
*
*    P30  (v1.70) the same pair with SRC a number in 0..255 and T a
*         16-bit register  ->  "mov T,SRC" (any CPU, one byte less).
*
*    P31  (v1.70, CPU 386+) "mov AL,SRC / cbw"  ->  "movsx AX,SRC" and
*         "mov AX,SRC / cwde"  ->  "movsx EAX,SRC".  Neither version
*         touches a flag, so no scan is needed; the source is read
*         before anything is written in both forms.
*
*    P32  (v1.70) "push R / pop S" (different registers of one size,
*         not SP)  ->  "mov S,R": same bytes or fewer, no stack
*         traffic, no flags.
*
*    P33  (v1.70, CPU 386+) "shl R,N / shr R,N" (or sar) with N = 16
*         or 24 on a 32-bit register, or N = 8 on a 16-bit one  ->
*         "movzx R,low" (movsx for sar).  The flags of the second
*         shift are lost, so the scan must prove all six dead.
*
*    P34  (v1.70) "and R16,0FFh" (AX..BX)  ->  "xor Rh,Rh" when the
*         scan proves ZF and PF dead (CF/OF/SF come out the same);
*         (CPU 386+) "and R32,0FFh / 0FFFFh"  ->  "movzx R32,low"
*         when all six flags are dead.
*
*    P35  (v1.70, CPU 386+) "mov R32,-1"  ->  "or R32,-1" (3 bytes
*         instead of 5) when the scan proves all six flags dead.
*
*    P36  (v1.70, CPU 186+) "mov sp,bp / pop bp"  ->  "leave".  Off
*         when the source may hold a 32-bit segment (use32, flat,
*         bits 32, .code32, any GAS source): LEAVE would then work
*         on ESP/EBP.
*
*    P10  (extended in v1.70) also takes "add R,-1" -> "dec R" and
*         "sub R,-1" -> "inc R" under the same CF-dead proof.
*
*  v1.80 NEW RULES (research-driven; patterns taken from FPC's
*  aoptx86.pas, GCC's RTL peepholes, LLVM's X86Peephole.cpp, the
*  Open Watcom peephole pass, and the Massalin-Stone superoptimizer
*  idioms).  All use the existing flag-liveness scan and the
*  existing parser helpers; no new cross-basic-block machinery.
*
*    P37  "xor R, -1"  ->  "not R" (all six flags dead).  For any
*         width w, R XOR (2^w-1) = ~R, exactly what `not` computes.
*         xor defines all six flags, not defines none.  FPC.
*
*    P38  "imul R, K" with K = 2^k (k >= 1)  ->  "shl R, k" (186+,
*         all six flags dead).  K = 1 (k = 0): the multiply is the
*         identity with flags side effects, so the line is deleted
*         when all six flags are dead.  GCC RTL, LLVM.
*
*    P39  "add R, c / sub R, c" (or reverse, c != 0)  ->  both
*         deleted (all six flags dead, R not SP).  Constant cousin
*         of P22/P27.  Net effect on R is zero; the final flags
*         come from the second instruction.
*
*    P40  "mov R, imm1 / add R, imm2" (or sub)  ->  "mov R, imm1 +
*         imm2" (all six flags dead).  FPC's constant propagation.
*         The add/sub's flags are lost; the combined mov sets none.
*
*    P41  "lea R, [R + S]" (R != S, same width)  ->  "add R, S"
*         (all six flags dead).  Two-register cousin of P17.  On
*         pre-386, restricted to the legal 16-bit LEA pairs
*         [BX+SI], [BX+DI], [BP+SI], [BP+DI]; 386+ accepts any
*         general pair.
*
*    P42  "push bp / mov bp, sp / sub sp, N"  ->  "enter N, 0"
*         (186+, 16-bit code only; all six flags dead).  enter
*         preserves the arithmetic flags; sub sp, N defines them,
*         so the rewrite changes them.  Size win (6..7 -> 4 bytes).
*
*    P43  "xor R, R / {add|sub|or|xor} R, imm"  ->  "mov R, K"
*         (K = imm or -imm; all six flags dead).  After xor R,R the
*         register is 0; the second op computes a known constant
*         from 0; xor and the second op overwrite flags; the
*         combined mov sets none.  FPC, LLVM optimizeIncDec.
*
*    P44  "xor R, R / inc R"  ->  "mov R, 1" (all six flags dead).
*
*    P45  "xor R, R / dec R"  ->  "mov R, -1" (all six flags dead).
*         The chained rewrite P45 -> P35 (mov R,-1 -> or R,-1) is
*         picked up by the multi-pass loop.
*
*    P46  "push imm / pop R"  ->  "mov R, imm" (186+, no scan: both
*         sides flag-neutral).  Size-gated for 32-bit R: when imm
*         fits in [-128, 127], `push imm8 + pop` is 3 bytes vs
*         `mov R, imm32` is 5 bytes, so the rule does NOT fire.
*         Always fires for 16-bit R.  LLVM's optimizeLEAgon.
*
*    P47  "mov R, S / add R, imm" (R != S)  ->  "lea R, [S + imm]"
*         (386+ general; pre-386 restricted to S in {BX, BP, SI, DI};
*         all six flags dead).  Inverse of P17.  Saves 2 bytes when
*         imm fits in disp8/imm8.  LLVM optimizeLEA.
*
*    P48  "xor R, R / test R, R"  ->  delete the test (NO scan
*         needed).  xor R,R sets R=0 and the flags to ZF=1, SF=0,
*         PF=1, CF=0, OF=0, AF=undef.  test R,R on R=0 produces
*         exactly the same flags (AF undefined in both).  Common
*         hand-written pattern from older compilers.
*
*    P49  "add sp, c / sub sp, c" (or reverse, c != 0, c a multiple
*         of the stack width, immediately consecutive)  ->  both
*         deleted (all six flags dead).  Net effect on SP is zero;
*         the second instruction's flags are lost.  The alignment
*         restriction prevents a misaligned interrupt push during
*         the one-instruction window.  Watcom.
*
*    P50  "imul R, K" with K = 2^k + 1 (k = 1, 2, 3)  ->  "lea R,
*         [R + R*k]" (386+; all six flags dead; Intel-only).  The
*         classic Massalin-Stone idiom for multiplying by 3, 5, 9.
*         Same size as imul when K fits in imm8; saves bytes when K
*         is large.  Also: no flag dependency for the next pass.
*
*    P51  "imul R, -1"  ->  "neg R" (186+; all six flags dead).
*         imul R,-1 computes -R; so does neg.  neg is 2 bytes vs
*         imul's 3 bytes.  Conservative: requires all six flags
*         dead (CF, OF, AF differ precisely; SF, ZF, PF match).
*
*  v1.81 NEW RULES + EXTENSIONS (research-driven; patterns taken
*  from FPC's aoptx86.pas, GCC's RTL peepholes, LLVM's
*  X86Peephole/X86ISelShuffle, Open Watcom, and the Massalin-Stone
*  superoptimizer idioms).  All reuse the existing flag-liveness
*  scan and parser helpers; no new cross-basic-block machinery.
*
*    P8 (extended) "or R,R" / "and R,R" / "or R,0" / "and R,all-ones"
*         (any width, including 8-bit; all-ones recognized as 0xFF,
*         0xFFFF, 0xFFFFFFFF, or -1) -> "test R,R" (exact: same flags,
*         no register change), OR deleted when the scan proves all
*         six status flags dead.  v1.80 only handled 16/32-bit and
*         always rewrote to test; v1.81 also deletes when no flag
*         reader is reachable.
*
*    P19 (extended) two consecutive identical "or R,S" / "and R,S"
*         (S a register or a plain constant) -> the first is
*         deleted.  or/and are idempotent on R (R | S | S = R | S;
*         R & S & S = R & S), so the first's R write and flag write
*         are both overwritten by the second with the same values.
*         Memory operands stay (a repeated I/O read may be
*         meaningful).  v1.80 covered only cmp/test.
*
*    P52  "mov R, imm1 / shl (or sal) R, k" (1 <= k < width)
*         ->  "mov R, (imm1 << k) & mask" (all six flags dead).
*         Constant folding for left shifts.  shl defines all six
*         flags, the combined mov defines none.  The result is
*         masked to the register width, exactly as the original
*         shift would produce.  Saves 2-3 bytes per fire.  GCC
*         RTL, LLVM X86ISelShuffle.
*
*    P53  "mov R, imm1 / and R, mask"  ->  "mov R, imm1 & mask"
*         (all six flags dead).  Constant folding for `and`.
*
*    P54  "mov R, imm1 / or R, imm2"  ->  "mov R, imm1 | imm2"
*         (all six flags dead).  Constant folding for `or`.
*
*    P55  "mov R, imm1 / xor R, imm2"  ->  "mov R, imm1 ^ imm2"
*         (all six flags dead).  Constant folding for `xor`.
*         Common chain: P55 + P9 + P35 (e.g. `mov R, 0 / xor R, -1`
*         -> `mov R, -1` -> `or R, -1` for 32-bit R).
*
*    P56  "add R, c1 / sub R, c2" (or reverse, mixed, c1 != c2,
*         two instructions only) -> a single "add R, c1-c2" (or
*         "sub R, c2-c1").  Net effect on R is the same; the
*         intermediate R0+/-c1 produces its own carry/borrow, so
*         CF/AF/OF can all differ from the single-op form -- all
*         six flags must be proven dead.  R must not be SP (parity
*         with P22/P24/P27/P39).  Two-instruction only; mixed
*         chains reduce step-by-step via the multi-pass loop.
*         Constant cousin of P39 with different magnitudes.  FPC.
*
*    P57  "lea R, [R + R]" (386+; the [R + R] form needs SIB)
*         ->  "shl R, 1" (all six flags dead).  Both source
*         registers equal to the destination and no displacement
*         means the LEA computes R := 2*R, exactly what shl R, 1
*         produces.  lea defines no flags, shl defines all six.
*         Saves 1 byte (3 -> 2).  Intel-only (AT&T two-register
*         forms have an index/scale we don't parse).  Massalin-
*         Stone doubling idiom.
*         (v2.15: NOT implemented as a separate rule -- it is
*         covered by the v2.21 rule P365, which canonicalizes
*         "lea R,[S+S]" to "lea R,[S*2]", plus the v2.15 rule
*         P63, which folds the scaled form to "shl R,log2 K"
*         under the same all-flags-dead gate.  A separate P57
*         could never fire; see rname[57].)
*
*    P58  "xor R, X / xor R, X" (X = register or immediate, NOT
*         memory)  ->  both deleted.  xor is involution
*         (R ^ X ^ X = R), so two consecutive identical xors
*         restore R.  The first xor's flags are overwritten by
*         the second's, but the second's flags differ from "no
*         instruction" -- all six flags must be proven dead.  R
*         must not be SP (an interrupt during the one-instruction
*         window would push at SP0 ^ X, potentially misaligned;
*         matches P22/P24/P27/P39/P49).  FPC folds the same
*         pattern in its xor-pass.
*
*  v1.81 BUG FIXES
*  ----------------
*   - Bug fix (P12 case 2, P14, P16 total==0): a label carried by
*     the first instruction line was lost when that line was
*     deleted.  A new helper, delete_keep_label(idx, pi), rewrites
*     the line to just its label text (plus any trailing comment)
*     when pi->haslabel, and falls back to DEL(idx) = 1 otherwise.
*     Other jumps to the label then land on a label-only line and
*     are assembled exactly as before; the dead instruction is
*     still removed.  The previous v1.80 code simply skipped the
*     rule when pi had a label, which lost the optimization.
*   - Bug fix (AT&T output, P38/P40/P43/P46): the previous code
*     emitted an extra "%" before pi->op0/pj->op0 even though
*     att_fix already preserves the "%" prefix on AT&T operands,
*     producing `mov $8, %%eax` (double percent) instead of
*     `mov $8, %eax`.  The new P52-P55 carry the same fix.
*   - Bug fix (att_fix): "imul" was missing from the size-suffix
*     base list, so AT&T `imull $8, %eax` stayed as "imull" and
*     the imul strength-reduction rules (P38/P50/P51) never
*     fired.  Added.
*   - Simplification (emit_lea_scaled): the AT&T branch was dead
*     (P50 is gated to !g_att); removed, along with the unused
*     `num` buffer.
*
*  v1.82 NEW RULES + REFACTOR (research-driven; patterns taken
*  from FPC `compiler/x86/aoptx86.pas`, GCC `gcc/config/i386/i386.md`
*  peephole2 #4/#9/#10/#33, LLVM `X86OptimizeLEAs.cpp`, and Open
*  Watcom `bld/cg/c/peepopt.c`).  Each rule is provably safe on the
*  value of R and uses the existing flag-liveness scan when the
*  flags differ; no new cross-basic-block machinery is introduced.
*
*    P59  "and R, 0" (reg only, any width) -> "mov R, 0" when all
*         six flags are dead.  R & 0 == 0 for every width; `and`
*         defines all six flags and `mov` defines none, so the
*         scan proves the difference is unobservable.  Memory dest
*         is left alone (GCC keeps the shorter `and $0, mem` form).
*         Chains into P9 (mov 0 -> xor) for the real byte win.
*         [FPC PrePeepholeOptAND "AND 0 -> MOV 0"]
*
*    P60  "or R16, -1" (16-bit register dest) -> "mov R16, -1" when
*         all six flags dead.  R | 0xFFFF == 0xFFFF for 16-bit; the
*         symmetric counterpart of P35 (which goes the other way
*         for 32-bit because `or R32,-1` is 2 bytes shorter).  For
*         16-bit both encodings are 3 bytes, so the mov strictly
*         subsumes the or by setting no flags.
*
*    P61  "and R, c1 / and R, c2" (same reg, both immediates) ->
*         single "and R, c1 & c2" (first deleted) when all six
*         flags dead.  AND is associative and idempotent:
*         (R & c1) & c2 == R & (c1 & c2).  Not covered by P19
*         (identical only) or P53 (mov+and).
*         [FPC OptPass1AND "AndAnd2And"]
*
*    P62  "and R, c1 / or R, c2" -> tighten the AND mask to
*         "and R, c1 & ~c2" (OR left unchanged).  The bits the OR
*         forces to 1 are guaranteed-1 in the final value, so
*         clearing them from the AND changes nothing.  NO flag
*         scan required: the rewritten AND still defines exactly
*         the same six flags, and the OR is unchanged.
*         [Open Watcom peepopt.c:192 AndOr]
*
*    P62b "or R, c1 / and R, c2" with (c2 & c1) == c2 (the AND mask
*         is a subset of the OR mask) -> "mov R, c2" when all six
*         flags dead.  When c2 ⊆ c1, (R | c1) & c2 == c2 regardless
*         of R, so the pair collapses to a single mov.
*         [Open Watcom peepopt.c:229 OrAnd subset branch]
*
*    P63  "lea R, [R * K]" (K in {2, 4, 8}, 386+) -> "shl R, log2 K".
*         Generalizes P57 (which is the K=2 case written as
*         [R + R]) to scales 4 and 8.  SIB byte was added with the
*         386, so gated on g_curcpu >= 8.  All six flags must be
*         dead: lea defines none, shl defines all six.
*         [FPC OptPass2Lea "Lea2Shl"]
*
*    P65  "dec R / cmp R, -1" -> delete the cmp when ALL six flags
*         are dead.  The cmp is redundant as a value computation;
*         we cannot relax to "ZF preserved" because after `dec R`
*         ZF reflects R_new==0 (i.e. R_old==1), whereas
*         `cmp R_new, -1` sets ZF iff R_new==-1 (i.e. R_old==0) --
*         these DIFFER.  The conservative all-six-dead formulation
*         is exact.  GCC i386.md peephole2 #33 goes further
*         (rewrites dec to sub $1 to also fix CF for jnc); this is
*         the simpler delete-the-cmp form.
*
*    P68  "xchg R, S" with one operand provably dead after the
*         swap -> "mov <alive>, <dead>" (or the symmetric form).
*         1 byte shorter on x86 for non-AX registers, same size
*         for the AX short form.  Uses the new shared helper
*         reg_dead_after() (same discipline as P2's dead-store
*         test).  SP excluded: a mov to SP changes observable
*         stack-pointer behavior between interrupts differently
*         than xchg would.  Same-width registers only (a partial
*         swap like `xchg ax, al` is not a single mov).
*         [GCC i386.md peephole2 #9/#10 REG_UNUSED xchg -> mov]
*
*    P70  "lea R, [S + off1] / lea D, [R + off2]" (R dead) ->
*         single "lea D, [S + off1 + off2]"; first LEA deleted.
*         Both LEAs are flag-free; only the intermediate R is
*         observable, and R is dead.  Uses reg_dead_after().  The
*         scaled/index form needs extra parser work and is left
*         for a future pass.
*         [FPC OptPass1LEA "LeaLea2Lea" simple sub-case]
*
*  v1.82 REFACTOR: the dead-register walk that P2 already used
*  inline (writer_ok) is extracted into a shared helper,
*  reg_dead_after(start, r), which serves both P68 and P70.  The
*  helper walks forward from `start+1` looking for the first
*  instruction that either fully overwrites r (clean kill) or
*  reads r's family.  It treats jcc/jmp/iret/ret/string ops as
*  "live" (control divergence), and is conservative on opaque
*  instructions (returns 0).  The helper is also reusable for
*  future rules that need a dead-register predicate.
*
*  v1.82 PARSER EXTENSION: a new helper, lea_scaled_single(op,
*  &r, &scale), parses the [R * K] Intel form and the (,%R,K) AT&T
*  form (single scaled register, no base, no displacement) for
*  K in {2, 4, 8}.  Used by P63.  P57 still uses the unscaled
*  lea_two_regs parser for its [R + R] form.
*
*  v1.83 BUG FIXES (correctness review of v1.81/v1.82)
*  ---------------------------------------------------
*   This release fixes ten correctness bugs identified in review of
*   the v1.81/v1.82 rules.  All fixes are conservative: rules that
*   could miscompile now refuse to fire on the offending input
*   rather than trying to be clever.  No new cross-basic-block
*   machinery was added.
*
*    P4  shift fusion: a single shift of count 1 leaves OF (and,
*        for rotates, CF) defined; a count > 1 leaves OF undefined.
*        When we fused two count-1 shifts into a count-2 shift, the
*        OF (and CF for rol/ror/rcl/rcr) of the fused instruction
*        no longer matched the original second shift's OF.  Now
*        demands F_OF dead (F_OF | F_CF for rotates) whenever the
*        fused total exceeds 1.
*
*    P50 imul->lea: the SIB byte's [R + R*scale] form requires a
*        32-bit register on 386+ (16-bit addressing has no SIB).
*        Also, ESP cannot be the index register (SIB index field 4
*        means "no index"), so `lea esp,[esp+esp*2]` cannot be
*        encoded.  Now gated on width==32 and family != SP.
*
*    P16/P56 add/sub fold: the bound was hardcoded to ±32767 (imm16)
*        for every width, which (a) refused legitimate 32-bit folds
*        and (b) accepted illegal 8-bit folds like `add al,200 /
*        add al,200 -> add al,400` (the assembler cannot encode 400
*        as imm8).  A new width_imm_limit(w) helper returns the
*        correct bound (imm8/imm16/imm32) and is used by both rules.
*
*    P42 enter in AT&T: the rule fired in AT&T mode too, emitting
*        Intel-syntax `enter N, 0` into a GAS source.  Now closed
*        to !g_att (matching P46, P47, P50).
*
*    P58 xor double: the previous test only rejected op1 containing
*        '[' or '('.  A *bare* symbol like `xor ax, myVar` (a MASM
*        memory label without brackets) passed the filter and the
*        rule deleted two MMIO reads.  Replaced with the positive
*        test the review suggested: accept X only when find_reg(op1)
*        >= 0 OR try_parse_number(op1) succeeds.
*
*    P3  push/pop of SP: on 8086/8088/80186 the PUSH SP instruction
*        pushes the *already-decremented* SP value, while on 286+
*        it pushes the original SP.  So `push sp / pop sp` is NOT
*        identity on the older CPUs (leaves SP = SP-2).  Now
*        requires g_curcpu >= 4 (286+) when the operand is SP.
*
*    P2  dead store from memory: the previous code unconditionally
*        allowed `mov R, <memory>` to be deleted as a dead store.
*        That is unsafe: a memory read may have MMIO side effects.
*        Now only register, immediate and lea sources qualify.
*
*    detect_use32: only matched lines whose first token was
*        "segment", but MASM segment definitions put the segment
*        *name* first (e.g. `_TEXT SEGMENT USE32`).  Now scans for
*        the "use32" token anywhere on the line (after the comment
*        is stripped).
*
*    P47 mov+add->lea: the 386+ branch accepted any S of any width,
*        but a 16-bit base is invalid in 32-bit addressing and a
*        32-bit base is invalid in 16-bit addressing.  Now requires
*        the source width to equal the destination width on the
*        386+ path (the pre-386 path already enforced 16-bit
*        BX/BP/SI/DI).
*
*  v1.83 NEW RULES (research: FPC aoptx86, GCC i386.md, LLVM,
*  Open Watcom peepopt, classic superoptimizer literature)
*
*    P13b  unreachable instructions after a control-flow terminator
*          that is not an unconditional jmp: ret, retf, iret, hlt,
*          ud2, int3.  Same scanning discipline as P13 (stop at a
*          label/data/directive).  INT N for N != 3 is NOT a
*          terminator (the handler typically returns via IRET).
*
*    P71   "sub R, R" -> "xor R, R" when AF is dead.  Both write R=0
*          and clear CF/OF, set SF=0/ZF=1/PF=1; only AF differs
*          (sub forces AF=0, xor leaves it undefined).  SP excluded.
*          [FPC Sub2Xor; GCC canonical R=0 to xor.]
*
*    P72   "mov R, imm1 / shr R, k" -> "mov R, imm1 >> k & mask".
*          Extends P52 (shl/sal) to logical right shift.
*
*    P73   "mov R, imm1 / sar R, k" -> arithmetic right shift fold.
*          Sign-extends v1 to the register width before the shift.
*
*    P74   "mov R, imm1 / rol R, k" -> rotate-left fold.  Periodic
*          in w (the register width).
*
*    P75   "mov R, imm1 / ror R, k" -> rotate-right fold.
*
*          P72-P75 exclude rcl/rcr (which depend on the input CF).
*
*    P76   "xor R, R / {add|or|xor} R, S" (S a register, S != R,
*          same width) -> "mov R, S".  After xor R,R the register
*          is 0; 0 | S = 0 + S = 0 ^ S = S.  `sub` excluded (would
*          need neg).  Extends P43 to register sources.
*          [GCC i386.md "xor R,R / or R,S -> mov R,S".]
*
*    P77   duplicate consecutive "mov R, X" / "lea R, X" / "movzx
*          R, X" with the SAME destination and SAME source (textual
*          match) -> first deleted.  Flag-neutral classes only;
*          memory sources excluded for mov/lea (MMIO risk).
*          Extends P19 to the move family.
*
*    P78   "lea R, [R + off1] / lea R, [R + off2]" (same dest,
*          same base R, no scan needed) -> single "lea R, [R +
*          (off1 + off2)]".  Same-dest cousin of P70.
*          [FPC LeaLea2Lea same-dest case.]
*
*    P79   "mov R, imm / push R" with R dead after the push ->
*          single "push imm".  Inverse-direction sibling of P46.
*          Uses reg_dead_after() (no flag scan needed).
*          (v2.15: implemented as the ADJACENT-kill form -- the
*          instruction right after the push already overwrites R;
*          P87 is the general reg_dead_cf form.)
*
*    P80   "push R / <writer to R that does not read R> / pop R"
*          -> push and pop both deleted (the writer is kept).  The
*          saved value is irrelevant because the writer overwrites
*          R, and the pop's restore is redundant.  No flag scan
*          (push/pop and the flag-neutral writers leave flags
*          unchanged).  16/32-bit only.
*          (v2.15 correction: the text above is UNSOUND -- the pop
*          restores the pushed value, so the writer's store is dead
*          and keeping it would change R.  rname[80] ("push+write+
*          pop->nothing") was the correct intent: all three are
*          deleted.  That is what got implemented.)
*
*    P81   "mov AL, SRC / movzx EAX, AL" -> "movzx EAX, byte ptr
*          SRC" (typed_src wraps the source).  Flag-neutral and
*          movzx reads before writing, so no scan needed.
*          386+ only, Intel-only.
*          [GCC combine mov+movzx; FPC OptPass2MovMovzx.]
*
*  v2.24 (this release)
*  --------------------------------------------------------------
*  THREE NEW RULES from the research-driven audit list:
*
*    P430  "or R,c1 / and R,c2 / or R,c3" 3-op chain -> delete the
*          first OR when (c1 & c2) & ~c3 == 0 (i.e., c1 & c2 is a
*          subset of c3).  Final value with OR1: (R & c2) |
*          (c1 & c2) | c3; without OR1: (R & c2) | c3; the diff is
*          (c1 & c2) & ~c3, which must be empty for the rewrite to
*          be exact for every R.  No flag scan: the deleted OR is
*          label-free adjacent to the AND, which overwrites all six
*          status flags before reading any.  Catches the case P62b
*          misses (P62b only fires when c2 ⊆ c1, collapsing the
*          pair to a mov).  Three-instruction pattern via the
*          existing MAXPAT=4 engine; the check function re-parses
*          the three immediates from g_pcur/g_ppair/g_pnext and
*          masks each to the destination register's width so
*          "or al, -1" and "or al, 0FFh" are treated identically.
*          [Open Watcom peepopt.c AndOr/OrAnd family, 3-op variant.]
*
*    P431  "mov R8lo, 0 / mov R8hi, 0 -> xor R16, R16" where R8lo
*          and R8hi are the low and high byte of the SAME 8-bit
*          register family (AL+AH -> AX, CL+CH -> CX, DL+DH -> DX,
*          BL+BH -> BX).  Both movs together set the whole 16-bit
*          parent to 0; a single "xor R16, R16" does the same in
*          2 bytes vs the 4 bytes of two byte-sized mov imm8.  xor
*          defines all six status flags; the two movs define none;
*          PRE_FLAGS_DEAD_ALL proves the difference is unobservable.
*          The check function (p431_al_ah_ax_check) verifies the
*          same-family + complementary-lo relationship the table's
*          OP_SAME cannot express (OP_SAME requires fam+width+lo
*          equality; here we need same fam + width but DIFFERENT
*          lo).  Families 0..3 only (SP/BP/SI/DI have no byte
*          form).  The $a16 template resolves to the 16-bit parent
*          regardless of which byte cap['a'] bound (AL -> AX,
*          AH -> AX, etc.), so the order of the two movs does not
*          matter.  Intel-only: the template emits Intel-syntax
*          register names without the AT&T "%" prefix.
*          [TP/BC emit this pattern when zeroing a 16-bit value
*          through two byte-stores; Massalin-Stone zeroing idiom
*          catalogue.]
*
*    P432  "movzx R, src / test R, R -> test src, src" when R is
*          provably dead after the test (PRE_REG_DEAD_RA) AND SF is
*          provably dead from the test onward (p432_movzx_test_check
*          calls flags_clear(next_code(j2), F_SF)).  After the movzx
*          the high bits of R are zero, so "test R, R" leaves SF=0;
*          "test src, src" leaves SF = MSB of src -- they differ
*          when src is signed-negative.  ZF/PF/CF/OF all match
*          exactly (ZF iff src==0; PF on low byte = src in both;
*          CF=OF=0 in both); AF is undef in both.  Only SF needs
*          the dead-flag scan, which is more permissive than
*          PRE_FLAGS_DEAD_ALL and lets the rule fire on the common
*          "movzx EAX, AL / test EAX, EAX / je L" pattern (je reads
*          only ZF, SF is dead).  The check also refuses movzx R, R
*          identity (handled by P424) and insists R be strictly
*          wider than src.  386+ (movzx encoding); Intel-only.
*          [LLVM X86PeepholePass optimizeCompare; GCC i386.md
*          combine movzx+test.]
*
*  P344 SOUNDNESS FIX: the constant-propagation redundant-store
*  rule (P344) used the predicate "reg_width(pk->dreg) <=
*  reg_width(kp[e].reg)" without checking bit-position coverage, so
*  after "mov al, 0" it believed AH was also known to be 0 (both
*  width 8, both fam 0, both val-mask 0) and deleted "mov ah, 0"
*  even when AH was whatever the caller left.  That is a
*  miscompile.  Replaced with covers(kp[e].reg, pk->dreg), which
*  requires the known register to actually cover every bit the
*  writing register writes.  Same blind spot as the v2.17
*  cap_regname / OP_SAME fix, just in a different place.  Sound
*  cases (mov ax,0 / mov ah,0) still fire because covers(AX, AH)
*  is true; the only thing the fix loses is the unsound deletion
*  of "mov ah, 0" after "mov al, 0", which P431 now catches
*  instead (and rewrites to a single "xor ax, ax").
*
*  v2.17 (this release)
*  --------------------------------------------------------------
*  CRITICAL FIX (P323/P324): "shl R,1 -> lea R,[R+R]" was firing on
*  16-bit registers, producing the invalid "lea ax,[ax+ax]" (A2031
*  "must be index or base register") on every pre-386 build.  The
*  [R+R] SIB form needs the 386+ SIB byte AND a 32/64-bit register;
*  16-bit addressing allows only BX/BP/SI/DI as base/index and
*  forbids the same register in both roles.  A new check function
*  (p323_lea_rr_check) gates the rewrite to 386+ with 32/64-bit
*  destinations; 8/16-bit shl R,1 stays intact.  This unblocks the
*  4VIEW 8086/386 real-mode build (five broken sites in StatLoad,
*  PopUp, DrwSt).
*
*  CRITICAL FIX (cap_regname / OP_SAME): the capture struct stored
*  only fam+width, not the bit offset (lo).  cap_regname matched
*  lo==0 unconditionally, so a capture of AH (fam=0, width=8, lo=8)
*  resolved to AL (fam=0, width=8, lo=0) -- "or ah,ah" was rewritten
*  to "test al,al" (wrong register, a miscompilation).  OP_SAME had
*  the same blind spot: "or ah,al" (same fam+width, different lo)
*  matched as "R,R" and could be wrongly rewritten.  Both are fixed:
*  capent now carries lo, OP_SAME requires lo equality, and
*  cap_regname uses the captured lo at the natural width (falling
*  back to lo==0 for forced widths like $a32).  This also stops P1
*  from deleting "mov al,ah" (not a no-op: different lo within the
*  same family).
*
*  W124 WARNING FIXES: eight tautological comparisons in P17/P70/P79
*  tripped Watcom's W124 ("Comparison result always 1").  The checks
*  guarded 32-bit range bounds (d17 <= 0xFFFFFFFFL, o70a <=
*  0x7FFFFFFFL, v79 >= -0x7FFFFFFFL-1L) that are always true because
*  long is 32-bit signed on every SMARTPP target -- the upper bound
*  promotes the signed long to unsigned long for the comparison.
*  The 32-bit case is now unconditionally true (fit17=1 / fits79=1)
*  and the P70 upper bound is dropped (the lower bound stays: it
*  rejects INT32_MIN which could negate-overflow).
*
*  NEW RULES (P390-P395): width-specific all-ones masks written as
*  UNSIGNED hex literals.  P112/P37/P60 handle the SIGNED -1 form
*  but miss the common "and al,0FFh" / "xor ax,0FFFFh" / "or al,0FFh"
*  notation (255 / 65535 != -1 as a signed long).  P390/P391 delete
*  identity AND, P392/P393 rewrite all-ones OR to MOV, P394/P395
*  rewrite all-ones XOR to NOT.  All are flag-liveness gated.
*
*  v2.16
*  --------------------------------------------------------------
*  VERBOSE LISTING: with -v, every rule firing now prints a per-line
*  notice.  The v2.13/v2.14 wave of rules (P344, P351-P356, P360-P362,
*  P365-P367, P371, P373, P377-P378, P380 second branch, P381-P386)
*  incremented their st[] counters silently, so -v listed only the
*  older rules.  A vlog() call was added at every firing site that
*  lacked one; nothing else changed in those rules.
*
*  CONST-PROP SOUNDNESS FIX: the kprop walk updated its push/pop
*  pending-slot bookkeeping but never invalidated a tracked register
*  when a pop WITHOUT a matching push wrote it ("mov eax,5 / push ebx /
*  pop eax" left eax "known" to be 5), and an esp write between the
*  push and the pop ("push eax / add esp,4 / pop ebx") broke the LIFO
*  pairing silently.  Both now kill the popped register's family /
*  the pending slot.  The documented propagations (push R / pop T
*  hands R's known value to T, including across pushes and pops of
*  OTHER registers -- "ajenos" -- since the stack is LIFO, and
*  lea T,[R+d] hands R's known value + d to T) were verified and
*  stay in place.
*
*  MORE imul FACTORS (P380): the unified imul -> lea/shl engine now
*  also covers m = 17, 19, 21, 25, 27, 37, 41, 45, 73 and 81 (two
*  leas through a dead scratch register, same discipline as
*  7/11/13/15), i.e. every K = m * 2^a with m in {3,5,7,9,11,13,15,
*  17,19,21,25,27,37,41,45,73,81}.  33 and 35 are NOT reachable with
*  two leas and legal SIB scales {1,2,4,8} (33 = 32+1 needs scale
*  16; 35 = 5*7 needs a scale-6 step), so they are absent.  Negative
*  factors are refused: neg+lea chain grows
*  the code and changes the flag pattern beyond the F_ALL6 gate.
*
*  TAIL-CALL WITH EPILOGUE (P383, -Ox): "call F / <restoration> /
*  ret" now also becomes "<restoration> / jmp F" when the code
*  between the call and the ret is EXACTLY one absolute esp
*  restoration -- "leave", or the pair "mov sp,bp / pop bp" -- and
*  the matching prologue ("push bp" then "mov bp,sp") is found up
*  the function with bp never rewritten in between, and no push of
*  any kind sits between the prologue and the call (so F reads no
*  stack arguments in a working original, and its own ret must be
*  ret 0 -- the same argument the adjacent form uses).  The
*  transformation deletes the call line, keeps the restoration lines
*  in place, and rewrites the ret into "jmp F".  The
*  pop-bp-in-pair caveat (F's entry bp is the caller's saved value,
*  exactly as in the already-accepted epilogue-before-call form)
*  is documented at tailcall_epilogue_ok().
*
*  v2.15
*  --------------------------------------------------------------
*  COVERAGE REVIEW + IMPLEMENTATION of the rules that were documented
*  but had no code behind them.  Since the v1.85 table refactor, the
*  helper parsers used by the v1.80-v1.84 rule families (lea_bracket,
*  lea_two_regs, lea_scaled_single, emit_lea_disp, width_imm_limit,
*  is_mem_only_reg, lea_mem_avoids_reg) sat unreferenced in the
*  smartpp_kept_helpers[] silence array: the rules that consumed them
*  had been lost from run_pass.  Each documented rule was checked
*  against the rules that DO fire (the st[] counter set); results:
*
*   IMPLEMENTED (were not covered by any firing rule):
*    - P17  "lea R,[R+c]" -> add/sub/inc/dec; "lea R,[const]" -> mov;
*          "lea R,[S]" -> mov R,S; "lea R,[R]/[R+0]" -> delete (this
*          also covers old P124, which had no code either).
*    - P41  "lea R,[R+S]" -> "add R,S" (flags dead; 16-bit pairs
*          restricted to BX/BP + SI/DI pre-386; Intel-only).
*    - P47  "mov R,S / add R,imm" -> "lea R,[S+imm]" (flags dead;
*          equal widths; Intel-only).  The sibling P382 (mov+lea)
*          does not cover it: the second instruction differs.
*    - P56  "add R,c1 / sub R,c2" (mixed, net != 0) -> one op with
*          the net constant (all six flags dead).  P39 only cancels
*          the net == 0 case and runs earlier; P16 (same-mnemonic
*          fold) remains unimplemented and is NOT part of this list.
*    - P63  "lea R,[R*K]" (K = 2/4/8, 386+, AT&T accepted) ->
*          "shl R,log2 K" (flags dead).  ESP refused as index.
*    - P68  "xchg R,S" with one operand dead after the swap ->
*          "mov <alive>,<dead>" (reg_dead_cf; the 1-byte xchg eax,r
*          short forms and 64-bit xchg refused so the code never
*          grows; SP excluded).
*    - P70  "lea R,[S+off1] / lea D,[R+off2]" (R dead) -> single
*          "lea D,[S+off1+off2]" (Intel-only, like its sibling P382).
*    - P79  "mov R,imm / push R" with the next instruction already
*          killing R -> "push imm" (adjacent-kill form, no scan).
*    - P80  "push R / <writer> / pop R" (adjacent; writer fully
*          overwrites R without reading it, the stack, or memory) ->
*          all three deleted.  NOTE: the v1.83 header text said
*          "the writer is kept"; that is unsound (the pop restores
*          the pushed value, so the writer's store is dead -- keeping
*          it would change R).  rname[80] ("push+write+pop->nothing")
*          was the correct intent and is what got implemented.  An
*          "xor R,R" writer defines all six flags, so they must be
*          dead; the other accepted writers (mov reg/imm, lea,
*          movzx/movsx from a register) are flag-neutral.
*    - P82  "lea r16, var" -> "mov r16, OFFSET var" (USE16, bare
*          symbol, Intel-only; 3 bytes vs 4).
*    - P85  "mov R,K / cmp R,K" (same K; R and all six flags dead
*          after the pair) -> both deleted.
*    - P86  "mov R,K / test R,K" -> both deleted (same shape).
*    - P87  "mov R,imm / push R" -> "push imm" under reg_dead_cf
*          (fires when a conditional jump separates the push from its
*          kill).  P79 above is the adjacent-kill subset, so both
*          rule numbers get real hits instead of one shadowing the
*          other.
*    - P89  "mov R,0 / setcc R8" (386+, R dead after the setcc) ->
*          the mov is deleted (setcc writes only the low byte and no
*          flags).
*
*   COVERED -- removed from the catalogue, not implemented:
*    - P57  "lea R,[R+R]" -> "shl R,1": the v2.21 rule P365 already
*          canonicalizes "lea R,[S+S]" to "lea R,[S*2]" (386+, both
*          syntaxes, no scan), and the new P63 folds the scaled form
*          to "shl R,1" under the same all-flags-dead gate P57
*          documented.  A separate P57 could never fire.  See
*          rname[57].
*
*   CORRECTED (documented pattern was mathematically wrong):
*    - P88  the documented idiom "rol eax,16 / xchg al,ah /
*          rol eax,16" does NOT compute bswap: it swaps only the two
*          HIGH bytes (x = 0x12345678 -> 0x34125678, bswap would give
*          0x78563412; verified exhaustively).  The canonical 486
*          byte-swap emulation puts the xchg FIRST:
*          "xchg al,ah / rol eax,16 / xchg al,ah" == "bswap eax"
*          exactly.  That corrected order is what P88 now matches.
*          The flags gate is also tightened: each rol writes CF (OF
*          undefined at count 16) while bswap writes no flags, so the
*          rule demands CF and OF dead (F_CFOF) instead of claiming
*          flag-neutrality.
*
*  All new rules follow the v1.83 discipline: exact rewrites need no
*  scan; flag-differing rewrites demand flags_clear(); register
*  deadness uses reg_dead_cf(); no rule deletes a labeled line; SP is
*  excluded where the stack window shape would change; memory reads
*  are never deleted.
*
*  v2.14
*  --------------------------------------------------------------
*  NAMING: the end-of-run summary no longer prints "(unnamed)" for
*  any rule that can fire.  rule_name() now consults (1) the dense
*  rname[] table (0..216), (2) a new sparse extension table for
*  343..387, and (3) the declarative table rule's own description,
*  so every table rule (205..350) is named without duplicating text.
*
*  TASM DIRECTIVES: cpu_directive_value() accepts the full TASM
*  processor-directive family in addition to the dot forms:
*  P8086/P186/P286/P286N/P286P/P386/P386N/P386P/P486/P486N/P486P/
*  P586/P586N/P586P/P686..., .286C/.386C/.486C/.586C, the FPU
*  directives .8087/.287/.387/.487/.587 + P8087..P587 (enable x87)
*  and .NO87/PNO87 (disable).
*
*  REDUNDANCIES REMOVED (all verified dead or duplicated):
*   - P1 RESTORED in the table ("mov R,R" and "xchg R,R" -> delete):
*     the v1.85.1 cleanup removed P106/P107 as "caught by P1", but P1
*     itself had never been in the table, so "mov R,R" silently
*     stopped being deleted.  Regression fix.
*   - Table P105 removed (the C rule P71 fires first under the same
*     conditions; the table copy was unreachable).
*   - Table P122 removed (the C rule P38's identity case was
*     unreachable behind the power-of-two branch; P38 fixed below).
*   - Table P126 removed (subsumed by the restored P1 xchg entry).
*   - C rule P50 removed ("imul 2^k+1 -> lea"): superseded by the
*     unified P380 engine, which handles the same factors and more.
*   - C rule P387 removed ("or/and R,R -> test"): dead behind P8.
*
*  NEW / EXTENDED:
*   - P38 fixed: "imul R,1" (identity, delete when flags dead) was
*     unreachable behind the power-of-two branch; now the first case.
*   - P380 unified strength-reduction engine: decomposes K = m*2^a
*     (m odd); m = 3/5/9 -> single lea (+ trailing shl via
*     insert_line_after); m = 7/11/13/15 -> two leas through a dead
*     scratch register found by the new find_dead_scratch() helper.
*     Covers 3,5,6,7,9,10,11,12,13,14,15 and every m*2^a form (18,
*     20, 24, 28, 30, 36, 40, 56, ...).  Width-gated to 32/64-bit
*     (SIB needs it) and excludes SP as index.
*   - Const-propagation window widened (P344/P385/P386): up to four
*     known (reg, value) pairs; propagation through push R/pop T,
*     lea T,[R+d], mov/movzx/movsx/xchg, inc/dec/not/neg,
*     imul-by-imm and shifts-by-imm; all comparisons masked to the
*     written register's width.
*   - P381 (LEA CSE) now compares semantically: [eax+4] and
*     [eax+2+2] match via the new lea_expr_eq() decomposition.
*   - P383 (call/ret -> jmp tail-call, -Ox) gained a soundness guard:
*     tailcall_stack_ok() walks backwards accumulating the esp delta
*     to a boundary and refuses to fire when the stack at the call is
*     not at function-entry depth -- previously "call F / ret" after
*     "push args" was rewritten to "jmp F" with F's ret popping the
*     argument payload (miscompile).  v2.14 also implements the
*     epilogue variant SOUNDLY: a "mov sp,bp / pop bp" (or "leave")
*     restoration pair immediately before the call is accepted when
*     the matching "push bp / mov bp,sp" prologue is found further up
*     (absolute esp restoration), or when pure push/pop/add/sub
*     arithmetic brings the walk back to zero at the entry boundary.
*     The call-first form ("call F / add esp,N / ret") stays
*     unimplemented: F's stack arguments are consumed before the jmp
*     could pass them, and without the callee's signature that cannot
*     be proven equivalent.
*
*  SOUNDNESS FIXES in existing rules:
*   - P344 (redundant xor R,R in the const-prop window): deletion now
*     requires all six status flags dead.  v2.13 deleted it
*     unconditionally, so "xor eax,eax / cmp ebx,ecx / xor eax,eax /
*     jz L" lost the jz's flag source (miscompile).
*   - P344/P385/P386: value comparisons are masked to the written
*     register's width; v2.13 compared by family only, so
*     "mov eax,K / mov ax,K" style sequences could fold on stale
*     high bits.
*   - P385 (cmp R,S -> ZF known): now requires S == R; v2.13 treated
*     any same-family pair ("cmp al,ah") as always-equal.
*   - P386 (ALU fold -> mov): new size gate -- the rewrite fires only
*     when the mov is not larger than the original (result 0, or an
*     ALU op whose immediate needed the long form); v2.13 could bloat
*     "add ax, 1" (3 bytes) into "mov ax, K+1" (3..4 bytes).
*   - Const-prop walk: opaque instructions (cpuid, rdtsc, adc/sbb,
*     setcc, ...) now break the walk; v2.13 kept scanning through
*     them with stale knowledge.
*
*  v1.86 (this release)
*  --------------------------------------------------------------
*  NEW RULES (research: Agner Fog manuals 1-5; Michael Abrash,
*  Graphics Programming Black Book ch.19-21; GCC config/i386/i386.md;
*  LLVM X86Peephole.cpp; Intel SDM Vol.1/2; Massalin-Stone 1987):
*   - P122 "imul R, 1"   -> delete (R*1 == R; flags dead; 186+).
*     In practice P38 (imul 2^k->shl, 2^0=1) fires first; P122 is the
*     table-native form documenting the rule.  Cycle win: huge on
*     pre-Pentium (imul-by-imm is 9-22 cycles); ~10 on P5/P6.
*   - P123 "imul R, 0"   -> "xor R, R" (flags dead; 186+).  R*0 == 0
*     and xor is the canonical zeroing idiom -- on PPro it breaks the
*     dependency chain via partial-register rename.  Not subsumed by
*     P38 (only 2^k), P50 (2^k+1), P51 (-1).
*   - P124 "lea R, [R]" and "lea R, [R+0]" -> delete (C rule).  lea
*     with base==R and disp==0 is a pure identity (no flags, no
*     memory).  Safe on every CPU.  Cycles: 1 on 386/486/P5; 2 on P6.
*   - P126 "xchg R, R"   -> delete (canonical NOP; 8086+).  In
*     practice P1 fires first on the same-width case; P126 documents
*     the pattern.  "xchg eax, eax" is the 1-byte NOP 0x90 on x86.
*   - P127 "bswap R / bswap R" -> "bswap R" (delete the second;
*     486+).  bswap is an involution.  1 cycle saved on 486/P5/P6.
*   - P128 "xor R, R / push R" -> "push 0" (186+).  The xor clears R
*     to 0; pushing the immediate 0 has the identical stack effect.
*     Requires R dead after the push.  Cycle win: 1 cycle on 486;
*     1 byte saved on 286+.  Distinct from P79 (mov R,imm / push R
*     -> push imm) which does not cover the xor-clearing variant.
*
*  OUTPUT REWORK (v1.86):
*   - -mark is now ON by default.  Pass -mark (or -nomark) to turn
*     OFF the "; SMARTPP 1.86: ... (PN)" trailing comments.  Rationale:
*     the marks are how a reader of the output traces what changed, so
*     making them opt-out matches the common case (auditing).
*   - -v is now ON by default.  Pass -v (or -nv) to silence the
*     per-line "rule Pn fired" notices.  The final summary table
*     always prints.  Rationale: the per-line notices are the audit
*     trail; silencing them is the exceptional case.
*   - The end-of-run summary is now a pretty-printed two-column table
*     with a banner (input/output/removed/passes/CPU), per-rule hit
*     counts, and a TOTAL row.
*   - Per-line rewrite/delete notices route through vlog(), a small
*     printf-style helper that obeys opt_verbose (so -v silences them
*     in one place rather than gating 90+ fprintf sites individually).
*
*  SAFETY ANALYSIS OF THE NEW RULES
*   - P122: imul R,1 leaves R unchanged; the only side effect is CF/OF
*     (set per the high-half rule).  PRE_FLAGS_DEAD_ALL proves no
*     reader.  Sound.
*   - P123: imul R,0 and xor R,R both zero R; their flag outputs differ
*     (xor forces CF=OF=0, imul reflects the high half of the product),
*     so PRE_FLAGS_DEAD_ALL is required.  Sound.
*   - P124: lea R,[R] / lea R,[R+0] compute R+0 = R; lea never sets
*     flags or touches memory.  No preconditions.  Sound on every CPU.
*   - P126: xchg R,R with the same register is a no-op on R, flags
*     (xchg sets none), and memory.  No preconditions.  Sound.
*   - P127: bswap is an involution; the second bswap restores the
*     original value of R.  bswap sets no flags.  PRE_CPU_486 gates the
*     instruction's availability.  Sound.
*   - P128: xor R,R zeros R; push R pushes 0; push 0 has the identical
*     stack effect.  PRE_REG_DEAD_RA proves R is not read again before
*     the function exits (reg_dead_cf returns false if control leaves
*     the function with R still live, so a `ret` after the push blocks
*     the rule unless R is overwritten first -- conservative).  Sound.
*
*  v1.85.1 (previous release)
*  --------------------------------------------------------------
*  HOTFIX over v1.85: two bugs that broke real assembly.
*
*  BUG 1 (v1.85) -- P121 "dead code after jmp" was UNSAFE with macro
*  assembler control-flow directives.  ASMC/JWasm/UASM support high-
*  level control-flow directives (.if/.endif/.else/.elseif/.case/
*  .endcase/.for/.endf/.while/.endw/.break/.continue) that the parser
*  does not all recognize as basic-block boundaries.  P121 deleted
*  them after a jmp, which unbalanced the .if/.endif pairs and made
*  the assembler fail with "directive must be in control block".
*  FIX: P121 is WITHDRAWN.  The existing C rule P13 ("unreachable
*  code after jmp") already handles the safe case (jmp to a label
*  inside the same file with no intervening directives); we rely on
*  it and do not add a competing rule.  Lesson: any peephole that
*  deletes lines forward of a jmp must understand the macro layer,
*  which is assembler-specific; the table engine is the wrong place.
*
*  BUG 2 (v1.85) -- OP_SAME matched registers by FAMILY only, not by
*  WIDTH.  This made "mov eax, ax" (a zero-extension -- NOT a no-op)
*  match the "mov R,R -> delete" pattern (P106), because eax and ax
*  share register family 0 but differ in width (32 vs 16).  Deleting
*  it would drop the zero-extension silently.
*  FIX: OP_SAME now compares BOTH family and width.  "mov eax, ax"
*  no longer matches; "mov eax, eax" still does (same family AND
*  same width).  This also tightens P105 (sub R,R), which is exact
*  only when both operands are the same width.
*
*  CLEANUP: removed the table rules that were subsumed by existing
*  C rules and never fired (P99 lea[R]->del caught by P17; P100
*  mov/mov->mov caught by P2; P101 add/sub cancel caught by P39;
*  P106 mov R,R->del caught by P1; P107 xchg R,R->del caught by
*  P1; P110 push/pop->del caught by P3; P113 add R,0->del caught
*  by P18; P114 sub R,0->del caught by P18).  They were listed for
*  documentation but only cluttered the table and the report.
*
*  REMAINING v1.85 NEW RULES (all kept, all re-verified safe):
*   - P105 "sub R,R" -> "xor R,R" (canonical zeroing idiom; on
*     PPro+ breaks the dependency chain via partial-register
*     rename.  Exact on R and flags; no preconditions).
*   - P111 "or R, 0"     -> delete (no-op on R; requires flags dead).
*   - P112 "and R, -1"   -> delete (no-op on R; requires flags dead).
*   - P115 "xor R, 0"    -> delete (no-op on R; requires flags dead).
*   - P119 "test R, K"   -> delete (test never writes R; flags dead).
*   - P120 "cmp R, K"    -> delete (cmp never writes R; flags dead).
*
*  v1.85 REFACTOR (kept): a declarative rule engine.  The simple
*  rules -- the mechanical "match a small pattern, apply a small
*  rewrite" family that was cluttering run_pass -- are now expressed
*  in a single table (g_rule_tbl) and interpreted by a small matcher.
*  Each table entry is a struct with a pattern (1 or 2 instructions),
*  a set of preconditions (flag liveness, register liveness, CPU
*  level, segment size, syntax, next-is-jcc, immediate-value), and a
*  list of actions (keep / delete / rewrite).  The matcher binds
*  captures ($a, $b for register families; $K for immediates) and
*  expands the rewrite template.  Example:
*
*      { 1, 105,
*        { { "sub", 0, RR_('a'), SM_('a'), 2 } },
*        0,    // no preconditions -- exact on R and flags
*        { { ACT_REW, "xor $a, $a" } },
*        "sub R,R -> xor R,R (dep-chain break)" }
*
*  The table runs AFTER every bespoke C rule in run_pass, so the
*  v1.84 behavior is preserved exactly for inputs the C rules
*  catch.  The table absorbs the new v1.85 rules below and provides
*  a maintainable home for future simple rules (one struct per rule,
*  no C function, no fresh counter slot allocation).
*
*  Operand pattern vocabulary:
*    OP_REG {cap, rclass}    register of a class; bind a capture
*    OP_REGCLASS {rclass}    register of a class, no capture
*    OP_SAME {same_cap}      must equal a previous capture's family
*                           AND width (v1.85.1: width check added)
*    OP_IMM {}               parses as an immediate
*    OP_IMMVAL {imm_val}     immediate equal to a specific value
*    OP_MEM {}               memory (not reg, not imm)
*    OP_ANY {}               don't care
*
*  Precondition bits (OR):
*    PRE_FLAGS_DEAD_ALL   PRE_FLAGS_DEAD_CF    PRE_FLAGS_DEAD_AF
*    PRE_REG_DEAD_RA      PRE_REG_DEAD_B       PRE_NO_CPU_8086
*    PRE_CPU_386          PRE_CPU_486          PRE_NO_USE32
*    PRE_INTEL            PRE_NEXT_IS_JCC      PRE_NEXT_JCC_NO_CF
*    PRE_NEXT_JCC_ZF_ONLY PRE_SRC_IMM          PRE_NOT_SP
*
*  Rewrite template tokens:
*    $a / $b / $c          capture's register name at bound width
*    $a8 / $a16 / $a32     capture's register name at forced width
*    $K                    immediate of inst 0
*    $K1                   immediate of inst 1
*
*  SAFETY ANALYSIS OF THE NEW RULES
*   - P105: sub R,R and xor R,R both zero R and define all six flags
*     identically (CF=0, OF=0, SF=0, ZF=1, PF=1, AF=0).  Exact on R
*     and flags; no preconditions.
*   - P111/P112/P115: the deleted op is a no-op on R (or R,0 = R;
*     and R,-1 = R; xor R,0 = R) but DOES set flags from R.  Requires
*     flags_clear(F_ALL6).  Sound.
*   - P119/P120: test/cmp never write R; the only observable effect
*     is flags, which flags_clear proves dead.  Sound.
*
*  v1.83 SAFETY DISCIPLINE (unchanged from v1.81): every new rule
*  either (a) is exact (same R, same flags) and needs no scan, or
*  (b) preserves R exactly and requires the existing flag-liveness
*  scan to prove the differing flags dead before any read.  No
*  rule deletes a labeled line.  No rule touches a memory operand
*  where a repeated read may be observable.  SP is excluded from
*  rules that change the SP-window shape (P22/P27/P39/P49/P58/P71
*  and the new P80) for parity.
*
*  v1.84 (this release)
*  --------------------------------------------------------------
*  Two structural additions and a batch of new rules, all driven by
*  the user's named targets: a register-liveness scan that follows
*  control flow (the analog of flags_clear), a -mark option that
*  leaves a "; SMARTPP 1.84: <desc> (PN)" comment on every line
*  the program rewrites (and a "was '...'" comment on every line it
*  deletes), and the SMART.INC v4.02 + 486/Pentium/PPro rule family.
*
*  STRUCTURAL
*   - reg_dead_cf(start, r): the control-flow-aware dead-register
*     scan the request asked for.  Mirrors flags_clear exactly --
*     follows both arms of conditional jumps, refuses backward
*     jumps (loops), merges, opaque instructions, calls/rets/ints/
*     string ops, and the SCAN_MAX budget.  SOUND: a 1 return is
*     provably correct; 0 means "cannot prove".  The old linear
*     reg_dead_after() is kept for the rules whose predicate is
*     "next instruction kills r" (P2, P68, P70, P79, P80) -- the
*     new helper is for the cases that need a true forward scan
*     through branches.
*   - replace_line_marked / delete_keep_label_marked: the -mark
*     output machinery.  When -mark is on, every rewrite appends a
*     " ; SMARTPP 1.84: <one-line desc> (PN)" comment so the user
*     can see at a glance, in the generated file, which
*     optimizations fired.  Without -mark the program is silent in
*     the output (the same stderr report is always produced).
*   - CPU level encoding widened so 486 / 586 / 686 are distinct
*     (1/2/4/8/16/32/64) instead of all collapsed to 8.  All
*     existing ">= 8" checks still pass because the new values are
*     strict supersets.  This unlocks 486+ (bswap, cmpxchg),
*     Pentium+ (cmpxchg8b) and P6+ (cmov) gating.
*
*  SMART.INC v4.02 PORT (the user's named "apply smart.inc
*  optimizations")
*   - P82 (item 9 of SMART.INC): "lea r16, var" -> "mov r16,
*     OFFSET var" in a USE16 segment with a 16-bit destination and
*     a direct symbol source.  3 bytes vs 4.  Items 8 (mov/xchg
*     reg,reg delete) and 10/11 (jcc/jcxz/loop range extension)
*     were already covered by P1 and by the assembler's own
*     near/short pick on 386+, so we add only what is genuinely
*     missing.
*
*  NEW RULES (the user's named "mov+cmp, mov+push, mov+test")
*   - P85 "mov R,K / cmp R,K" with R and flags dead after the cmp
*     -> both deleted.  Requires reg_dead_cf AND flags_clear on
*     F_ALL6.  (cmp reads R, so the mov is not dead on its own;
*     only the PAIR is dead when both R and the flags die.)
*   - P86 "mov R,K / test R,K" with R and flags dead -> both
*     deleted (same shape as P85 for test).
*   - P87 "mov R,K / push R" with R dead after the push -> single
*     "push K".  Uses reg_dead_cf so it fires when a conditional
*     jump separates the push from its kill (the case the old P79
*     had to refuse).  SP family excluded.
*
*  NEW RULES (486/Pentium/PentiumPro)
*   - P88 (486+): "rol eax,16 / xchg al,ah / rol eax,16" -> single
*     "bswap eax".  Saves 3 bytes and ~7 cycles on the 486.  All
*     three ops are flag-neutral; the idiom's CF/OF are unused by
*     the next user (the v1.83 review of P4 already proved this
*     for the byte-swap idiom).  Intel-only, 32-bit register only.
*     (v2.15 CORRECTION: the order documented above is NOT an
*     identity for bswap -- it swaps only the two HIGH bytes
*     (0x12345678 -> 0x34125678, bswap would give 0x78563412).
*     The canonical 486 byte-swap emulation puts the xchg FIRST:
*     "xchg al,ah / rol eax,16 / xchg al,ah" == "bswap eax"
*     exactly.  Each rol writes CF (OF undefined at count 16)
*     while bswap writes no flags, so the rule demands CF and OF
*     dead (F_CFOF) instead of claiming flag-neutrality.)
*
*  NEW RULES (research: GCC i386.md, FPC aoptx86, Open Watcom
*  peepopt, classic superoptimizer literature)
*   - P89 (386+): "mov R,0 / setcc R8" with R dead after setcc ->
*     mov deleted.  setcc only writes the low byte; the upper
*     bits are dead (proven by reg_dead_cf) and so is the mov.
*     [GCC zero_extendqisi2_qi + setcc; FPC OptPass2MOVZX.]
*   - P90 "and R, K / jcc" where K is a single-bit mask and the
*     jcc tests ZF only -> "test R, K / jcc".  Same ZF, SF, PF,
*     same CF=0/OF=0; AND writes R (which we prove dead via
*     reg_dead_cf); test does not.  Same encoding size, but test
*     is non-destructive and on the Pentium pairs on either pipe.
*     [FPC OptPass2And2Test; GCC combine and+branch.]
*   - P91 WITHDRAWN in review: "add R,S -> lea R,[R+S]" would
*     undo P41's size-positive direction (lea is 3 bytes, add is
*     2).  The pairing argument is real on PPro but a peephole
*     cannot schedule it.  Kept as a no-op slot so the numbering
*     is stable.
*   - P92 "sub R,1 / jcc" with CF dead after the sub and the jcc
*     not reading CF -> "dec R / jcc".  dec preserves CF; sub sets
*     it; if CF is dead (flags_clear on F_CF) the rewrite is
*     exact.  Lets P10's case fire even when a Jcc reads ZF.
*   - P93 "xor R,R / mov R,K" -> mov only.  The xor defines all
*     six flags; the mov overwrites R and defines none; the flags
*     of the xor die in the zero-instruction gap.  Trivial scan.
*   - P94 "mov R,0 / {or|xor|add} R,K" -> "mov R,K".  After the
*     mov R is 0; 0|K = 0^K = 0+K = K.  Strict improvement over
*     P9+P40 which require the flags to die first (P9 turns the
*     mov into xor; P40 then folds xor+add to mov); P94 fires
*     even when the flags survive.  [GCC combine "mov 0/add K ->
*     mov K"; FPC OptPass2MovAdd2Mov.]
*   - P97 "mov R,K / test R,R" with R and flags dead -> both
*     deleted.  Generalization of P86 (which requires K1==K2);
*     here the test's source is the same register.
*   - P98 "shl/shr/sal/sar R,K / mov R,0" -> mov only.  The
*     shift's flags die in the zero-instruction gap; R is then
*     overwritten by 0 anyway.  Same idea as P93 for shifts.
*
*  SAFETY ANALYSIS OF THE NEW RULES
*  --------------------------------
*   Every new rule keeps the v1.83 discipline:
*    - P82: exact on R, exact on flags (neither LEA nor MOV-with-
*      OFFSET touches flags), no MMIO (LEA never touches memory,
*      neither does MOV imm).
*    - P85/P86/P97: pair is deleted only when both the
*      destination register AND all six status flags are provably
*      dead after the pair (reg_dead_cf + flags_clear).
*    - P87/P89: register dead after the consuming op
*      (reg_dead_cf); no flag scan needed (the surviving op is
*      flag-neutral: push and setcc do not touch arithmetic
*      flags).
*    - P88: three flag-neutral instructions become one
*      flag-neutral instruction; flags are bit-for-bit identical
*      in the only case that matters (the canonical byte-swap
*      idiom whose successor does not read CF/OF).  Gated on
*      g_curcpu >= 16 (486+) so bswap never assembles on a 386.
*    - P90: register dead after the jcc (reg_dead_cf); flags
*      other than ZF (the only one the jcc reads) provably dead
*      (flags_clear on F_ALL6 & ~F_ZF).
*    - P92: CF provably dead after the sub (flags_clear on F_CF);
*      the jcc does not read CF (jcc_read_set & F_CF == 0).  All
*      other flags are bit-for-bit identical between sub R,1 and
*      dec R.
*    - P93/P94/P98: the dead instruction's flags die in the
*      zero-instruction gap before the surviving op (trivially
*      true; no scan needed).  The surviving op fully overwrites
*      the dead instruction's destination.
*   No new rule deletes a labeled line, touches a memory operand
*   with possible side effects, or changes SP-window shape.
*
*  v1.81 SAFETY ANALYSIS OF THE NEW RULES
*  -------------------------------------
*   Every new rule either (a) is exact (same R, same flags) and
*   needs no scan, or (b) preserves R exactly and requires the
*   existing flag-liveness scan to prove all six status flags
*   dead before any read.  No rule deletes a labeled line (the
*   P12/P14/P16 fixes above close the last holes).  No rule
*   touches a memory operand except P53-P55's first operand,
*   which is a mov-with-immediate (already flag- and side-effect-
*   free).  P58 explicitly rejects memory second operands so a
*   repeated read of memory-mapped I/O cannot be elided.  The
*   scan, the parser helpers, and the chunked line store are
*   reused unchanged; no new cross-basic-block machinery was
*   added.
*
*  v1.80 OTHER CHANGES
*  -------------------
*   - Multi-pass loop: run_pass is called repeatedly until no rule
*     fires or MAX_PASSES (=4) is reached.  Chained rewrites such
*     as P45 -> P35, P43 -> P9, P40 -> P9, P16 -> P18 converge
*     without further machinery.
*   - Bug fix (P16): when a constant-folded sum is 0, the run is
*     deleted in-place instead of being emitted as "add R, 0".
*   - Bug fix (P10, P11): the 16/32-bit gate is dropped so 8-bit
*     non-AL registers also benefit (`add cl, 1` -> `inc cl`;
*     `cmp cl, 0` -> `test cl, cl`).
*   - Bug fix (P17): range-check the constant before emitting
*     `add/sub R, big`; previously a wide displacement was
*     silently truncated, producing misleading source.
*   - Bug fix (P6): skip pure-label lines so "jmp L1 / L1: / mov"
*     also fires (previously only "jmp L1 / L1: mov" did).
*   - Bug fix (detect_use32): only set g_use32 when a directive
*     actually begins with `.model flat`, `option ... use32`,
*     `segment ... use32`, `bits 32`, `.code32`, `.code64`.
*     Previously a comment containing "flat" or "bits 32" would
*     trip the substring match and disable P36.
*   - Simplification: the 36+ per-rule counters (st_p1..st_p36)
*     are folded into one array `st[STSZ]`; the long summary
*     fprintf is replaced by a per-rule non-zero loop.  Adding a
*     new rule only needs the counter, an `st[k]++` increment
*     and an rname entry in the driver.
*
*  THE FLAG SCAN (P9, P10, P11, P16, P17, P18, P22, P24, P26, P27,
*  P29, P30, P33, P34, P35, P37, P38, P39, P40, P41, P42, P43, P44,
*  P45, P47, P49, P50, P51, P52, P53, P54, P55, P56, P57, P58,
*  P8-delete branch)
*  ----------------------------
*   Each of those rules knows exactly which flags differ between
*   the original and the replacement.  The scan walks forward from
*   the instruction and, on every path:
*     - an instruction that READS a still-differing flag  ->  abort;
*     - an instruction that WRITES flags removes them from the
*       differing set; when the set is empty the path is settled;
*     - a conditional jump is followed on BOTH arms (straight-on
*       and the target label), so "cmp ax,0 / jz L" still scans
*       past the jz;
*     - a backward jump (loop), a merge point seen twice, a call,
*       a jump away, a string instruction, an unknown mnemonic
*       (including SMART.INC macro calls), a line inside a macro
*       definition, or the end of the file  ->  abort.
*   A bounded exploration (64 lines) that cannot prove safety
*   simply does not rewrite: silence is always safe.
*   (v1.70) the scan now walks through stores ("mov [x],ax"), "push imm",
*   "xor R,S", adc/sbb, bt*, bsf/bsr, setcc/cmovcc, lahf, cbw/cwd/cwde/
*   cdq, xlat, bswap, in/out, cld/std/cli/sti, leave/enter and les/lds
*   & co.: before they were "unknown" and aborted every proof, so a
*   store between a "mov ax,0" and the next flag writer blocked P9.
*
*  GNU AS (GAS) SUPPORT (v1.60)
*  ----------------------------
*   Syntax is auto-detected and can be forced with -att / -intel.
*   Detected: a ".intel_syntax" / ".att_syntax" directive, AT&T
*   registers ("%eax") or GAS-only directives (".globl", ".text",
*   ".long", ...).  In GAS mode:
*     - '#' and C block comments are comments (';' too; a ';'
*       statement separator on one line is therefore not supported
*       there  split such lines first);
*     - ".Lnnn:" labels are tracked like any other label;
*     - numeric local labels "1:" are resolved positionally, the
*       way GAS does it: "1f" is the next "1:" after the jump,
*       "1b" the one before, so P5/P6/P7 work across them;
*   In AT&T mode (-att or auto-detected):
*     - size suffixes are stripped when the base is a known
*       mnemonic ("movl" -> "mov"; "jnl", "movsd", "stosb" and
*       "movzbl" are left alone  movzx/movsx rules simply do not
*       fire on AT&T's "movzbl/movswl" forms);
*     - operands are internally swapped to Intel order ("src, dst"
*       -> destination first) and '$'-immediates parse as numbers;
*       every rewrite emits AT&T order again ("add $4, %eax");
*     - "disp(%base)" memory forms parse for P17/P26; index/scale
*       forms "(%base,%index,s)" are out of scope.
*   Unknown syntax never rewrites: an operand that does not parse
*   leaves the rule silent, which is always safe.
*
*  GEMA (GenPC Elite Macro Assembler) 2.6 note
*  -------------------------------------------
*   GEMA's documented optimizer is "-o / --optimize : extended
*   automatic optimizations ( 3 passes )".  Its encoding-level half
*   (shortest jump displacements, shortest immediate forms) is
*   already done by ASMC / JWasm / UASM when they re-assemble the
*   output, so SMARTPP does not duplicate it.  Its source-level
*   half is covered by P1..P22 above; the classic rewrites that a
*   naive optimizer applies blindly (mov R,0 -> xor, add R,1 ->
*   inc, cmp R,0 -> test) are applied here only under flag-liveness
*   control.  What stays out because it cannot be proven safe on
*   source: deleting "nop" (timing loops depend on it), autoalign
*   (moves addresses; hardcoded offsets would break), and the tail
*   call "call X / ret" -> "jmp X" (unsafe when X ends in "ret N"
*   or manipulates the return address on the stack).  (v1.50) also
*   out: "dec cx / jnz L" -> "loop L" (saves a byte, but the
*   backward edge re-enters code that may read the flags "dec"
*   set, and the scan aborts on backward jumps, so it can never
*   prove them dead), and "mov cl,imm / shl R,cl" -> "shl R,imm"
*   (needs a register-liveness scan to prove cl dead afterwards;
*   new machinery for a pattern that is rare in real code).
*
*  Reference for the rule set (public sources)
*  -------------------------------------------
*   The Free Pascal x86 peephole optimizer (compiler/x86/aoptx86.pas
*   and compiler/i386/aoptcpu.pas) documents the same families this
*   tool implements: redundant move elimination (P2/P15), LEA to
*   ADD/INC/SUB (P17), arithmetic constant folding (P16), and the
*   jump/flow optimizations of its second pass (P5/P6/P7/P12/P13).
*
*  SAFETY CONTRACT
*  ---------------
*   - No instruction that reads or writes a MEMORY operand is ever
*     deleted or merged, with two exceptions: the balanced push/pop
*     pairs of P3, whose net effect on memory and flags is exactly
*     zero, and P2 loads-from-memory whose destination is provably
*     dead (a read cannot be observed once the value is discarded;
*     avoid SMARTPP on sources that read memory-mapped I/O devices
*     with read side effects).  LEA is exempt: it computes an
*     address and touches no memory.
*   - No flag-setting instruction is ever deleted ("xor ax,ax" is
*     never removed as a dead store).  "mov reg,0" becomes
*     "xor reg,reg" only through P9's flag-liveness proof, never
*     blindly (the SMART.INC flags policy).
*   - "pop" is never deleted as a dead store: it moves SP, and only
*     the paired P3 form is provably balanced.
*   - A label, a directive, or any instruction outside the known set
*     closes the optimization window.  SMART.INC macro calls
*     (FastIMul, setfield, ...) are unknown lines: they pass through
*     untouched and close windows.  Lines inside MACRO..ENDM
*     definitions are never touched at all (deleting there would
*     change every future expansion).
*   - Every rewrite is line-granular; the rest of the file is
*     preserved byte for byte, line terminators included.
*
*  USAGE
*  -----
*     smartpp [-m86|-m186|-m286|-m386] [-color|-ncolor] [-mark] [-v] [-o OUT] [IN [OUT]]
*       -m...   initial CPU level (8086 if not given).  A .8086 /
*               .186 / .286 / .386 / ... directive in the source
*               overrides it from its line on.
*       -color / -ncolor  force colored stderr diagnostics on/off
*               (default: color when stderr is a TTY)
*       -mark   append a trailing "; SMARTPP 1.84: <desc> (PN)" comment
*               to every line the program rewrites (and a "was '...'"
*               comment to every line it deletes), so the user can see
*               in the generated file exactly which optimizations
*               fired.  Without -mark the program is silent in the
*               output (the same stderr report is always produced).
*       -v      also log CPU-level changes from directives
*       -o FILE output file (default stdout; IN "-" reads stdin)
*       Every applied rewrite is reported on stderr with its line
*       number, whether or not -v is given.
*
*     Typical use with SMART.INC:
*         smartpp -m386 -o 4view.pp.asm 4view.asm
*         asmc -c -Fo4view.obj 4view.pp.asm
*
*  BUILD (one file; no headers beyond the standard four)
*  -----------------------------------------------------
*     Watcom, DOS 16-bit (large model; the chunked line store keeps
*     every allocated object well under 64K):
*         wcl -ml -os -d1 smartpp.c
*     Watcom, DOS 32-bit:
*         wcl386 -os -d1 smartpp.c
*     Watcom, Win32:
*         wcl386 -bt=nt -os -d1 smartpp.c
*     Visual C++, Win32 and Win64 (same command for both):
*         cl /O1 /W3 smartpp.c
*
*  LIMITS
*  ------
*   - INCLUDE / include / .include are followed recursively (v1.90).
*     Use -I DIR for extra search paths, -noinclude to disable.
*     Cycles are detected and skipped.  Missing includes warn and
*     leave the original directive in the output.
*   - Lines longer than 8191 characters pass through untouched.
*   - Conditional assembly is not evaluated: a .386 inside a
*     disabled {IF 0} block still raises the CPU level from its
*     line on (-m only sets the initial level; directives always
*     override it).
*   - Jumps through computed addresses are out of scope by
*     construction: in source form they are just unknown lines.
*=====================================================================*/

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#endif

/* isatty()/fileno() are POSIX.  On platforms without <unistd.h> we fall
 *  back to "no color" (color_enabled() returns 0 unconditionally). */
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__) \
    || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
#include <unistd.h>
#define SMARTPP_HAS_ISATTY 1
#else
#define SMARTPP_HAS_ISATTY 0
#endif

#define SMARTPP_VERSION "2.24"
/* Author name: use CP1252 on Windows (é = 0xE9), UTF-8 elsewhere.
 *  Windows consoles (cp850/cp1252) often mojibake UTF-8; CP1252 matches
 *  the OEM/ANSI code pages used by Spanish Windows. */
#ifdef _WIN32
#  define AUTHOR_STR "Javier Guti\xE9rrez Chamorro (Guti)"
#else
#  define AUTHOR_STR "Javier Guti\xC3\xA9rrez Chamorro (Guti)"
#endif


#define MAXTOK  256              /* operand / label / target buffer   */
#define MAXCMT  512              /* trailing comment buffer           */
#define MAXNAME 32               /* mnemonic buffer                   */
#define MAXLINE 8192             /* working line buffer               */

#define CHUNK_SHIFT 11
#define CHUNK_SIZE  (1L << CHUNK_SHIFT)

/* ---- Color support (GCC-style, v1.87) --------------------------------
 *  Colored output to stderr when (and only when) stderr is a TTY, so
 *  redirecting to a file produces clean, color-free logs -- exactly
 *  like `gcc 2> log.txt`.  The --ncolor switch forces it OFF for users
 *  who dislike color even on a TTY.
 *
 *  Color is ONLY applied to the diagnostic channel (stderr).  The
 *  optimized assembly on stdout is NEVER colored -- so it stays a
 *  valid assembler input that you can pipe straight into ASMC/JWasm. */

#define C_RESET  "\x1b[0m"
#define C_BOLD   "\x1b[1m"
#define C_DIM    "\x1b[2m"
#define C_RED    "\x1b[31m"
#define C_GREEN  "\x1b[32m"
#define C_YELLOW "\x1b[33m"
#define C_BLUE   "\x1b[34m"
#define C_MAGENTA "\x1b[35m"
#define C_CYAN   "\x1b[36m"
#define C_WHITE  "\x1b[37m"
#define C_BRIGHT_WHITE "\x1b[1;37m"  /* DOS color 15 */
#define C_GRAY   "\x1b[37m"          /* DOS color 7  */

#define C_BG_BLUE "\x1b[44m"
#define C_BRIGHT "\x1b[1;36m"

/* v1.92: colored diagnostic output.
 *  Behavior:
 *    - default: color ON.
 *    - -color:  force color ON.
 *    - -ncolor: force color OFF.
 *    - -color=auto is not exposed; opt_color=-1 still means TTY-auto
 *      if set programmatically.
 *  Color is ONLY on stderr; stdout stays plain assembler text. */
static int  opt_color = 1;        /* 1=on (default), 0=off (-ncolor), -1=auto/TTY */

static const char *cpu_name(int cpu);
static void print_summary(long nout, long ndel);
static void print_version(void);

static int color_enabled(void)
{
    if (opt_color == 0) return 0;
    if (opt_color == 1) return 1;
#if SMARTPP_HAS_ISATTY
    return isatty(fileno(stderr)) ? 1 : 0;
#else
    return 0;
#endif
}

/* Print startup / help banner: line1 = bright white (15), line2 = gray (7). */
static void print_banner(FILE *f)
{
    int col = color_enabled();
    if (col)
        fprintf(f, "%sSMARTPP %s - conservative peephole pre-processor for 8086..x86-64%s\n",
                C_BRIGHT_WHITE, SMARTPP_VERSION, C_RESET);
    else
        fprintf(f, "SMARTPP %s - conservative peephole pre-processor for 8086..x86-64\n",
                SMARTPP_VERSION);
    if (col)
        fprintf(f, "%sCopyright (c) %s%s\n", C_GRAY, AUTHOR_STR, C_RESET);
    else
        fprintf(f, "Copyright (c) %s\n", AUTHOR_STR);
    fflush(f);
}



/* ---- instruction classes ------------------------------------------*/

#define I_UNK    0               /* not parsed                        */
#define I_OTHER  1               /* content, but opaque: closes window*/
#define I_MOV    2
#define I_LEA    3
#define I_POP    4
#define I_PUSH   5
#define I_PUSHF  6
#define I_POPF   7
#define I_PUSHA  8
#define I_POPA   9
#define I_XORRR 10               /* xor reg, reg (same register)      */
#define I_XCHG  11
#define I_SHIFT 12
#define I_JMP   13
#define I_JCC   14
#define I_MOVZX 15               /* movzx / movsx                     */
#define I_X87   16               /* x87 FPU instruction (fld, fstp, fxch, ...) */

struct pinfo {
    int  cls;
    int  haslabel;
    int  hasinstr;
    int  toobig;
    int  nops;
    char op0[MAXTOK];
    char op1[MAXTOK];
    char op2[MAXTOK];             /* v2.20: third operand (imul R,S,K) */
    int  dreg;
    int  sreg;
    int  srcimm;
    long shiftcount;
    char mnem[MAXNAME];
    char prefix[MAXTOK];
    char comment[MAXCMT];
    char jtarget[MAXTOK];
    int  jtarget_ok;
};

struct reginfo {
    const char *name;
    int fam;                     /* 0..7 = AX,CX,DX,BX,SP,BP,SI,DI    */
                                 /* 8 = x87 stack register st / st(N)  */
                                 /* 9..24 = x64 r8..r15 families      */
    int lo;                      /* first bit inside the family      */
    int hi;                      /* one past the last bit            */
};

static const struct reginfo g_regs[] = {
    { "al",  0, 0,  8 }, { "ah",  0, 8, 16 }, { "ax",  0, 0, 16 }, { "eax", 0, 0, 32 }, { "rax", 0, 0, 64 },
    { "cl",  1, 0,  8 }, { "ch",  1, 8, 16 }, { "cx",  1, 0, 16 }, { "ecx", 1, 0, 32 }, { "rcx", 1, 0, 64 },
    { "dl",  2, 0,  8 }, { "dh",  2, 8, 16 }, { "dx",  2, 0, 16 }, { "edx", 2, 0, 32 }, { "rdx", 2, 0, 64 },
    { "bl",  3, 0,  8 }, { "bh",  3, 8, 16 }, { "bx",  3, 0, 16 }, { "ebx", 3, 0, 32 }, { "rbx", 3, 0, 64 },
    { "spl", 4, 8, 16 }, { "sp",  4, 0, 16 },                       { "esp", 4, 0, 32 }, { "rsp", 4, 0, 64 },
    { "bpl", 5, 8, 16 }, { "bp",  5, 0, 16 },                       { "ebp", 5, 0, 32 }, { "rbp", 5, 0, 64 },
    { "sil", 6, 8, 16 }, { "si",  6, 0, 16 },                       { "esi", 6, 0, 32 }, { "rsi", 6, 0, 64 },
    { "dil", 7, 8, 16 }, { "di",  7, 0, 16 },                       { "edi", 7, 0, 32 }, { "rdi", 7, 0, 64 },
    /* x64 r8..r15 family (9..16).  All widths present for r8-r15:       */
    { "r8b",  9, 0,  8 }, { "r8w",  9, 0, 16 }, { "r8d",  9, 0, 32 }, { "r8",  9, 0, 64 },
    { "r9b", 10, 0,  8 }, { "r9w", 10, 0, 16 }, { "r9d", 10, 0, 32 }, { "r9", 10, 0, 64 },
    { "r10b",11, 0,  8 }, { "r10w",11, 0, 16 }, { "r10d",11, 0, 32 }, { "r10",11, 0, 64 },
    { "r11b",12, 0,  8 }, { "r11w",12, 0, 16 }, { "r11d",12, 0, 32 }, { "r11",12, 0, 64 },
    { "r12b",13, 0,  8 }, { "r12w",13, 0, 16 }, { "r12d",13, 0, 32 }, { "r12",13, 0, 64 },
    { "r13b",14, 0,  8 }, { "r13w",14, 0, 16 }, { "r13d",14, 0, 32 }, { "r13",14, 0, 64 },
    { "r14b",15, 0,  8 }, { "r14w",15, 0, 16 }, { "r14d",15, 0, 32 }, { "r14",15, 0, 64 },
    { "r15b",16, 0,  8 }, { "r15w",16, 0, 16 }, { "r15d",16, 0, 32 }, { "r15",16, 0, 64 },
    /* x87 stack-register pseudo-family (fam 8).  lo==0 means "top of
     *  stack" / "any stack slot" -- the parser maps both `st` and
     *  `st(N)` to family 8, and the rules engine treats all x87 stack
     *  registers as the SAME family because x87 has no register file
     *  -- every fld/fstp addresses the stack top.  Width 80 is the
     *  x87 extended-precision register width; rules never use it. */
    { "st",  8, 0, 80 }, { "st(0)", 8, 0, 80 }, { "st(1)", 8, 1, 80 },
    { "st(2)", 8, 2, 80 }, { "st(3)", 8, 3, 80 }, { "st(4)", 8, 4, 80 },
    { "st(5)", 8, 5, 80 }, { "st(6)", 8, 6, 80 }, { "st(7)", 8, 7, 80 },
    /* MMX mm0..mm7 (fam 20..27), 64-bit */
    { "mm0", 20, 0, 64 }, { "mm1", 21, 0, 64 }, { "mm2", 22, 0, 64 }, { "mm3", 23, 0, 64 },
    { "mm4", 24, 0, 64 }, { "mm5", 25, 0, 64 }, { "mm6", 26, 0, 64 }, { "mm7", 27, 0, 64 },
    /* SSE xmm0..xmm15 (fam 30..45), 128-bit */
    { "xmm0", 30, 0, 128 }, { "xmm1", 31, 0, 128 }, { "xmm2", 32, 0, 128 }, { "xmm3", 33, 0, 128 },
    { "xmm4", 34, 0, 128 }, { "xmm5", 35, 0, 128 }, { "xmm6", 36, 0, 128 }, { "xmm7", 37, 0, 128 },
    { "xmm8", 38, 0, 128 }, { "xmm9", 39, 0, 128 }, { "xmm10",40, 0, 128 }, { "xmm11",41, 0, 128 },
    { "xmm12",42, 0, 128 }, { "xmm13",43, 0, 128 }, { "xmm14",44, 0, 128 }, { "xmm15",45, 0, 128 },
    { NULL,  0, 0,  0 }
};

/* ---- globals -------------------------------------------------------*/

static char          ***g_lc;  /* chunks of line pointers            */
static unsigned char  **g_tc;  /* chunks of terminator codes         */
static unsigned char  **g_dc;  /* chunks of deleted flags            */
static unsigned char  **g_ic;  /* chunks of inside-definition flags  */
static long g_nlines;
static long g_nchunks;
static long g_ccap;

static struct pinfo g_pcur;      /* current line (main pass)         */
static struct pinfo g_ppair;     /* second line of a pair            */
static struct pinfo g_plook;     /* P5 look-ahead                    */
static struct pinfo g_pnext;     /* next_code / instr_after_label    */
static struct pinfo g_pnew;      /* v1.70 rules: fresh parse of line i */
static struct pinfo g_pscan;     /* flags_clear                      */

static char g_scratch[MAXLINE];                      /* shared copy  */
static char g_build[MAXLINE + MAXTOK + MAXCMT];      /* rewrite buf  */

static int  opt_verbose = 0;        /* default OFF; -v enables, -nv disables */
static int  g_curcpu    = 1;
/* v2.26: g_cpu_max is the HARD CEILING set by the -m flag on the
 *  command line.  Source-file directives (.386, .286, etc.) can only
 *  set g_curcpu UP TO this ceiling -- they cannot raise it beyond
 *  what the user explicitly requested.  This prevents a .386
 *  directive in the source from enabling movzx/movsx rules when
 *  the user passed -m86 (targeting 8086 where those instructions
 *  don't exist).  When -m is NOT given, g_cpu_max stays 0 and
 *  directives are unrestricted (preserving v2.25 behavior). */
static int  g_cpu_max   = 0;    /* 0 = no ceiling (directives unrestricted) */
static int  opt_zopt    = 0;     /* -Oz: optimize for size */
static int  opt_speed   = 1;     /* -Os: optimize for speed (default) */
static int  opt_aggressive = 0;  /* -Ox: aggressive (non-100%-safe) folds */

/* Prefer xor+mov over movzx on 486/Pentium (2 clocks vs 3).
 *  386 and P6+/x64 take movzx (size / modern cores).  Replaces -nz.
 *  v2.23: with -Oz (size), always prefer movzx (smaller). */
static int prefer_xor_mov(void)
{
    if (opt_zopt) return 0;            /* -Oz: movzx is always smaller */
    return (g_curcpu == 16 || g_curcpu == 32);
}
/* v1.92: -nz removed.  prefer_xor_mov() chooses automatically:
 *  on 486 and Pentium, xor+mov is faster than movzx (2 vs 3 clocks);
 *  on 386 and on P6+/x64, movzx is preferred (size / modern cores). */
static int  g_use32     = 0;     /* a 32-bit segment may exist (no P36)  */
static int  opt_mark    = 1;     /* default ON; -nomark disables, -mark enables */
static int  g_passes_run = 0;   /* number of passes actually executed */
static int  g_nofpu     = 0;    /* .NO87 disables FPU rules; .287/.387/.8087 enable */

/* Per-rule hit counters, indexed by rule number (1..STSZ).
*  st[0] is unused.  The driver prints non-zero entries by name. */
#define STSZ 440             /* P1..P429 + spare */
static long st[STSZ];

static int  g_gas = 0;           /* GAS conventions (comments, labels) */
static int  g_att = 0;           /* AT&T operand order and % registers */
static int  g_synforced = 0;     /* -att / -intel given on the command line */

/* v1.90: INCLUDE following ------------------------------------------------
 *  Search paths (-I), recursion stack (cycle detection) and a flag that
 *  keeps the original include line as a comment when expansion succeeds. */
#define MAX_INCL_DEPTH  64
#define MAX_INCL_PATHS  64
static char *g_inc_paths[MAX_INCL_PATHS];
static int   g_ninc_paths = 0;
static char *g_incl_stack[MAX_INCL_DEPTH];
static int   g_incl_depth = 0;
static int   opt_noinclude = 0;  /* -noinclude: do not follow INCLUDE at all */


struct labent {
    char name[MAXTOK];
    long line;
    int  dup;
    int  next;           /* v1.94: hash chain index, -1 = end */
};
static struct labent *g_labs  = NULL;
static long g_nlab   = 0;
static long g_caplab = 0;
#define LAB_HASH 4096
static int g_lab_hash[LAB_HASH];   /* heads; -1 = empty */
static int g_lab_hash_ready = 0;

/* ---- small helpers --------------------------------------------------*/

/* v1.86: per-line rewrite/delete notices go through vlog so they obey
 *  opt_verbose (default OFF; -v turns it ON).  Errors and the final
 *  summary always print.
 *  v1.87: when color is enabled (TTY + --ncolor not given), the
 *  per-line notices get the leading "smartpp:" tag colored (cyan +
 *  bold) by detecting the "smartpp:" prefix on the formatted output
 *  and emitting color around it.  Output stays a single line so it
 *  greps cleanly; the ANSI escape sequences strip to nothing when
 *  redirected (most terminals do this).
 *
 *  v1.87 also adds vlog_line(i, fmt, ...) -- a wrapper that prepends
 *  the standard "smartpp: line %ld: " header and converts the 0-based
 *  line index `i` to the 1-based number the user sees.  Every per-line
 *  notice in this file uses this macro now, so the i+1 off-by-one is
 *  centralized in one place and the color wrapper's "smartpp:" prefix
 *  detection is guaranteed to hit. */
static void vlog(const char *fmt, ...)
{
    va_list ap;
    char buf[1024];
    if (!opt_verbose) return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (color_enabled() && !strncmp(buf, "smartpp:", 8)) {
        fprintf(stderr, "%s%.*s%s%s",
                C_CYAN C_BOLD, 8, buf, C_RESET, buf + 8);
    }
    else {
        fputs(buf, stderr);
    }
}

/* vlog_line: emit "smartpp: line N: <msg>" with color when enabled.
 *  `i` is the 0-based line index used throughout the optimizer; the
 *  user-facing line number is `i+1`.  Use this everywhere instead of
 *  the bare `vlog("smartpp: line %ld: ...", i+1, ...)` form. */
#define vlog_line(i, ...) \
    vlog("smartpp: line %ld: " __VA_ARGS__, (long)((i) + 1))

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (p == NULL) {
        fprintf(stderr, "smartpp: out of memory\n");
        exit(2);
    }
    return p;
}

static void *xrealloc(void *p, size_t n)
{
    void *q = (p == NULL) ? malloc(n) : realloc(p, n);
    if (q == NULL) {
        fprintf(stderr, "smartpp: out of memory\n");
        exit(2);
    }
    return q;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static int ci_eq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static int ci_eq_n(const char *a, const char *b, long n)
{
    long i;
    for (i = 0; i < n; i++) {
        if (a[i] == '\0') return 0;
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    }
    return 1;
}

static char *skip_ws(char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static int is_ident_start(int c)
{
    return isalpha(c) || c == '_' || c == '$' || c == '@' || c == '?';
}

static int is_ident_char(int c)
{
    return isalnum(c) || c == '_' || c == '$' || c == '@' || c == '?';
}

/* the comment starts at the first ';' outside a quoted string */
static char *find_comment(char *p)
{
    int in_dq = 0, in_sq = 0;
    for (; *p != '\0'; p++) {
        if (in_dq) { if (*p == '"') in_dq = 0; }
        else if (in_sq) { if (*p == '\'') in_sq = 0; }
        else if (*p == '"') in_dq = 1;
        else if (*p == '\'') in_sq = 1;
        else if (*p == ';') return p;
        else if (g_gas && *p == '#') return p;
        else if (g_gas && *p == '/' && p[1] == '*') return p;
    }
    return NULL;
}

static void trim(char *s)
{
    char *b = s;
    long n;
    while (*b == ' ' || *b == '\t') b++;
    if (b != s) memmove(s, b, strlen(b) + 1);
    n = (long)strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* Accepts only unambiguous numeric literals: decimal digits, 0x hex,
*  digit-led hex with an h suffix, and character literals.  Anything
*  else (identifiers, expressions) is treated as memory or unknown,
*  never as an immediate. */
static int try_parse_number(const char *s, long *out)
{
    long sign = 1, v = 0;
    const char *q;
    *out = 0;
    if (s == NULL || *s == '\0') return 0;
    if (*s == '$') {                 /* AT&T immediate: $5, $0x10, $-4 */
        if (isdigit((unsigned char)s[1]) || s[1] == '-') s++;
        else return 0;               /* "$" alone or "$+expr": memory */
    }
    if (*s == '-') { sign = -1; s++; }
    else if (*s == '+') s++;
    if (*s == '\0') return 0;
    if (*s == '\'') {
        if (s[1] != '\0' && s[2] == '\'') {
            *out = sign * (long)(unsigned char)s[1];
            return 1;
        }
        return 0;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        if (!isxdigit((unsigned char)*s)) return 0;
        for (q = s; *q != '\0'; q++) {
            if (!isxdigit((unsigned char)*q)) return 0;
            v = v * 16 + hexval(*q);
        }
        *out = sign * v;
        return 1;
    }
    {
        size_t l = strlen(s);
        if (l >= 2 && (s[l - 1] == 'h' || s[l - 1] == 'H')) {
            if (!isdigit((unsigned char)s[0])) return 0;  /* ABCh is a label */
            for (q = s; q < s + (l - 1); q++) {
                if (!isxdigit((unsigned char)*q)) return 0;
                v = v * 16 + hexval(*q);
            }
            *out = sign * v;
            return 1;
        }
        for (q = s; *q != '\0'; q++) {
            if (!isdigit((unsigned char)*q)) return 0;
            v = v * 10 + (*q - '0');
        }
        *out = sign * v;
        return 1;
    }
}

static int is_offset_expr(const char *s)
{
    if (ci_eq_n(s, "offset", 6)) {
        const char *r = s + 6;
        if (*r == ' ' || *r == '\t') {
            while (*r == ' ' || *r == '\t') r++;
            return (*r != '\0');
        }
    }
    return 0;
}

static int find_reg(const char *t)
{
    int i;
    if (t[0] == '%') t++;            /* AT&T: %eax */
    for (i = 0; g_regs[i].name != NULL; i++)
        if (ci_eq(t, g_regs[i].name)) return i;
    return -1;
}

/* v2.25 (S6): unified register-relation predicate.  Replaces four
 *  near-duplicate ways the code used to ask "are these two registers
 *  related?":
 *    - covers() below (used by P2/P26/P68/P70 and the dead-store walk)
 *    - OP_SAME matching in op_pat_match (fam + width + lo equality)
 *    - kprop_find_fam's "same family" lookup (P344/P385/P386)
 *    - p431_al_ah_ax_check's manual fam + lo comparison
 *  All four ask the same underlying question with different masks;
 *  reg_relation() exposes every mask shape via one enum so the
 *  callers stop re-deriving the test. */
enum reg_rel {
    REL_COVER        = 1,   /* outer fully overwrites every bit inner writes */
    REL_SAME         = 2,   /* same fam, same width, same lo (exact equality) */
    REL_SAME_FAM     = 3,   /* same family, any width/lo */
    REL_SAME_WIDTH   = 4,   /* same fam AND same width, any lo (e.g. AL vs AH) */
    REL_COMPLEMENT_LO= 5,   /* same fam + same width + los sum to width
                               (AL+AH=AX, CL+CH=CX, etc.) */
    REL_DISJOINT     = 6    /* different family */
};

static int reg_relation(int a, int b, enum reg_rel rel)
{
    if (a < 0 || b < 0) return 0;
    if (g_regs[a].fam != g_regs[b].fam) {
        return (rel == REL_DISJOINT);
    }
    switch (rel) {
        case REL_SAME_FAM:
            return 1;
        case REL_SAME_WIDTH:
            return (g_regs[a].hi - g_regs[a].lo) == (g_regs[b].hi - g_regs[b].lo);
        case REL_SAME:
            return (g_regs[a].hi - g_regs[a].lo) == (g_regs[b].hi - g_regs[b].lo) &&
                    g_regs[a].lo == g_regs[b].lo;
        case REL_COMPLEMENT_LO: {
            int wa = g_regs[a].hi - g_regs[a].lo;
            int wb = g_regs[b].hi - g_regs[b].lo;
            return wa == wb && (g_regs[a].lo + g_regs[b].lo) == wa;
        }
        case REL_COVER:
            return g_regs[a].lo <= g_regs[b].lo &&
                   g_regs[a].hi >= g_regs[b].hi;
        case REL_DISJOINT:
            return 0;   /* same fam, so not disjoint */
    }
    return 0;
}

/* outer fully overwrites every bit inner writes.  v2.25: thin wrapper
 *  around reg_relation() for the existing call sites (P2's writer_ok,
 *  P26/P68/P70 dead-store scans, P344's soundness fix). */
static int covers(int outer, int inner)
{
    return reg_relation(outer, inner, REL_COVER);
}

/* does the expression mention any register of the family? */
static int expr_uses_family(const char *e, int fam)
{
    const char *p = e;
    while (*p != '\0') {
        if (is_ident_start((unsigned char)*p)) {
            char tok[64];
            int l = 0, r;
            while (*p != '\0' && is_ident_char((unsigned char)*p)) {
                if (l < 63) tok[l++] = *p;
                p++;
            }
            tok[l] = '\0';
            r = find_reg(tok);
            if (r >= 0 && g_regs[r].fam == fam) return 1;
        } else {
            p++;
        }
    }
    return 0;
}

/* ---- chunked line store (every object stays far below 64K) ----------*/

#define L(i)      (g_lc[(i) >> CHUNK_SHIFT][(i) & (CHUNK_SIZE - 1L)])
#define TERM(i)   (g_tc[(i) >> CHUNK_SHIFT][(i) & (CHUNK_SIZE - 1L)])
#define DEL(i)    (g_dc[(i) >> CHUNK_SHIFT][(i) & (CHUNK_SIZE - 1L)])
#define INDEF(i)  (g_ic[(i) >> CHUNK_SHIFT][(i) & (CHUNK_SIZE - 1L)])

/* v2.25 (S1) -- WITHDRAWN: per-line pinfo cache.
 *
 *  The original analysis predicted ~30-40% time saving on large
 *  files from caching parse_line results.  The implementation
 *  showed this was wrong:
 *
 *    - 4VIEW (8240 lines, 3 passes): 88ms original, 89ms cached.
 *      Break-even; the memset-per-pass (later replaced by an O(1)
 *      generation counter) and the 1.6KB struct copy per hit eat
 *      the re-tokenization savings.
 *    - 12x4VIEW (~99K lines): 1.04s original, 1.08s cached.  4%
 *      SLOWER, plus 160MB of cache memory (1.6KB × 99K lines).
 *
 *  Root cause: parse_line for typical ASM lines (short operands,
 *  simple mnemonics) is ~microseconds, comparable to the 1.6KB
 *  struct copy a cache hit costs.  The cache only wins on lines
 *  with very long operands or complex tokenization, which are rare.
 *
 *  The cache infrastructure (g_pi_cache, g_pi_gen, pi_cache_grow,
 *  pi_cache_invalidate, pi_cache_invalidate_all) is left in place
 *  but inert -- pi_cache_grow is never called, so g_pi_cap stays 0
 *  and every parse_line falls through to the uncached path.  This
 *  keeps the hooks available for future experiments (e.g., caching
 *  only the expensive-to-compute fields like dreg/sreg/shiftcount,
 *  not the full pinfo) without paying the cost today.
 *
 *  The per-entry invalidation hooks in replace_line /
 *  delete_keep_label / insert_line_after / the pass loop are also
 *  kept (they call pi_cache_invalidate which is a no-op when
 *  g_pi_cap == 0); removing them would be a separate cleanup. */

/* Inert stubs: g_pi_cap stays 0 so the hit/write-back checks in
 *  parse_line always short-circuit on `g_pi_cache != NULL`.  The
 *  invalidation calls from replace_line / delete_keep_label /
 *  insert_line_after / the pass loop compile to no-ops. */
static struct pinfo *g_pi_cache = NULL;
static long         *g_pi_gen = NULL;
static long          g_pi_cur_gen = 0;
static long          g_pi_cap = 0;

static void pi_cache_grow(long cap)
{
    (void)cap;   /* inert: S1 withdrawn */
}

static void pi_cache_invalidate(long idx)
{
    (void)idx;   /* inert: g_pi_cap == 0, nothing to invalidate */
}

static void pi_cache_invalidate_all(void)
{
    /* inert: g_pi_cap == 0, nothing to invalidate */
}

static void chunk_reserve(long need)
{
    long want = (need >> CHUNK_SHIFT) + 1;
    long i;
    if (want > g_ccap) {
        long ncap = (g_ccap > 0) ? g_ccap * 2 : 16;
        char          ***nlc;
        unsigned char  **ntc;
        unsigned char  **ndc;
        unsigned char  **nic;
        if (ncap < want) ncap = want;
        nlc = (char ***)xrealloc(g_lc, (size_t)ncap * sizeof(char **));
        ntc = (unsigned char **)xrealloc(g_tc, (size_t)ncap * sizeof(unsigned char *));
        ndc = (unsigned char **)xrealloc(g_dc, (size_t)ncap * sizeof(unsigned char *));
        nic = (unsigned char **)xrealloc(g_ic, (size_t)ncap * sizeof(unsigned char *));
        g_lc = nlc; g_tc = ntc; g_dc = ndc; g_ic = nic;
        g_ccap = ncap;
    }
    while (g_nchunks < want) {
        char          *pl = (char *)xmalloc((size_t)CHUNK_SIZE * sizeof(char *));
        unsigned char *pt = (unsigned char *)xmalloc((size_t)CHUNK_SIZE);
        unsigned char *pd = (unsigned char *)xmalloc((size_t)CHUNK_SIZE);
        unsigned char *pi = (unsigned char *)xmalloc((size_t)CHUNK_SIZE);
        for (i = 0; i < CHUNK_SIZE; i++) {
            ((char **)pl)[i] = NULL;
            pt[i] = 0; pd[i] = 0; pi[i] = 0;
        }
        g_lc[g_nchunks] = (char **)pl;
        g_tc[g_nchunks] = pt;
        g_dc[g_nchunks] = pd;
        g_ic[g_nchunks] = pi;
        g_nchunks++;
    }
    /* v2.25 (S1): pi_cache_grow() would be called here to size the
     *  pinfo cache to g_nchunks * CHUNK_SIZE, but S1 was withdrawn
     *  (see comment above); the call is a no-op. */
    pi_cache_grow(g_nchunks * CHUNK_SIZE);
}

static void store_line(long i, char *s, int term)
{
    chunk_reserve(i);
    L(i) = s;
    TERM(i) = (unsigned char)term;
    if (i >= g_nlines) g_nlines = i + 1;
}

/* ---- reading ---------------------------------------------------------*/

/* v1.90: dirname of a path into out (empty string if none). */
static void path_dirname(const char *path, char *out, size_t outsz)
{
    const char *slash = NULL;
    const char *p;
    size_t n;
    if (path == NULL || outsz == 0) { if (outsz) out[0] = '\0'; return; }
    for (p = path; *p; p++)
        if (*p == '/' || *p == '\\') slash = p;
    if (slash == NULL) { out[0] = '\0'; return; }
    n = (size_t)(slash - path);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, path, n);
    out[n] = '\0';
}

/* Join dir + name into out.  If name is absolute, copy name only. */
static void path_join(const char *dir, const char *name, char *out, size_t outsz)
{
    size_t nd, nn;
    if (name == NULL || name[0] == '\0') { out[0] = '\0'; return; }
    if (name[0] == '/' || name[0] == '\\' ||
        (name[0] && name[1] == ':')) {
        strncpy(out, name, outsz - 1);
        out[outsz - 1] = '\0';
        return;
    }
    if (dir == NULL || dir[0] == '\0') {
        strncpy(out, name, outsz - 1);
        out[outsz - 1] = '\0';
        return;
    }
    nd = strlen(dir);
    nn = strlen(name);
    if (nd + 1 + nn + 1 > outsz) {
        out[0] = '\0';
        return;
    }
    memcpy(out, dir, nd);
    if (dir[nd - 1] != '/' && dir[nd - 1] != '\\') {
        out[nd] = '/';
        nd++;
    }
    memcpy(out + nd, name, nn);
    out[nd + nn] = '\0';
}

/* True if path is already on the include stack (cycle). */
static const char *path_basename(const char *path)
{
    const char *b = path ? path : "";
    const char *p;
    for (p = b; *p; p++)
        if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

static int incl_on_stack(const char *path)
{
    int i;
    const char *base;
    if (path == NULL) return 0;
    base = path_basename(path);
    for (i = 0; i < g_incl_depth; i++) {
        if (g_incl_stack[i] == NULL) continue;
        if (ci_eq(g_incl_stack[i], path)) return 1;
        /* Windows may resolve the same file with different spellings */
        if (ci_eq(path_basename(g_incl_stack[i]), base)) return 1;
    }
    return 0;
}


static FILE *open_include(const char *cur_dir, const char *name, char *resolved, size_t rsz)
{
    int i;
    FILE *f;
    path_join(cur_dir, name, resolved, rsz);
    if (resolved[0] != '\0') {
        f = fopen(resolved, "rb");
        if (f) return f;
    }
    for (i = 0; i < g_ninc_paths; i++) {
        path_join(g_inc_paths[i], name, resolved, rsz);
        if (resolved[0] == '\0') continue;
        f = fopen(resolved, "rb");
        if (f) return f;
    }
    /* plain name relative to CWD */
    strncpy(resolved, name, rsz - 1);
    resolved[rsz - 1] = '\0';
    f = fopen(resolved, "rb");
    return f;
}

/* Parse an include directive.  Returns 1 and fills fname if the line
 *  is INCLUDE / include / .include with a file name.  Strips quotes
 *  and <angle> brackets.  Comments are ignored. */
static int parse_include_line(const char *line, char *fname, size_t fsz)
{
    static char buf[MAXLINE];
    char *p, *q, *end;
    char *cmt;
    size_t n;
    if (line == NULL || fname == NULL || fsz == 0) return 0;
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    /* strip comment */
    cmt = find_comment(buf);
    if (cmt) *cmt = '\0';
    p = skip_ws(buf);
    /* skip optional "name:" label */
    if (is_ident_start((unsigned char)*p)) {
        q = p;
        while (is_ident_char((unsigned char)*q)) q++;
        if (*q == ':') {
            p = skip_ws(q + 1);
        }
    }
    /* .include (GAS) or INCLUDE / include (MASM) */
    if (*p == '.') {
        p++;
        if (!ci_eq_n(p, "include", 7) || is_ident_char((unsigned char)p[7]))
            return 0;
        p = skip_ws(p + 7);
    } else {
        if (!ci_eq_n(p, "include", 7) || is_ident_char((unsigned char)p[7]))
            return 0;
        p = skip_ws(p + 7);
    }
    if (*p == '\0') return 0;
    /* quoted, angled, or bare */
    if (*p == '"' || *p == '\'') {
        char quote = *p++;
        q = p;
        while (*q && *q != quote) q++;
        n = (size_t)(q - p);
    } else if (*p == '<') {
        p++;
        q = p;
        while (*q && *q != '>') q++;
        n = (size_t)(q - p);
    } else {
        q = p;
        while (*q && *q != ' ' && *q != '\t' && *q != ';') q++;
        n = (size_t)(q - p);
    }
    if (n == 0 || n >= fsz) return 0;
    memcpy(fname, p, n);
    fname[n] = '\0';
    /* trim trailing whitespace */
    end = fname + strlen(fname);
    while (end > fname && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
        *end = '\0';
    }
    return fname[0] != '\0';
}

static void read_file_path(const char *path); /* recursive */

/* Read one already-opened stream, expanding INCLUDE lines.  cur_path
 *  is used for diagnostics and relative resolution; may be NULL. */

/* Load entire stream into one malloc'd buffer (binary).  Returns NULL on
 *  failure.  Does not use fseek - works around Windows CRT issues where
 *  fseek/ftell before fgets can leave the FILE* unreadable. */
static char *load_entire_stream(FILE *f, long *out_sz)
{
    char *buf = NULL;
    long sz = 0, cap = 0;
    char tmp[8192];
    size_t n;
    for (;;) {
        n = fread(tmp, 1, sizeof(tmp), f);
        if (n == 0) break;
        if (sz + (long)n + 1 > cap) {
            long ncap = (cap > 0) ? cap * 2 : 16384;
            while (ncap < sz + (long)n + 1) ncap *= 2;
            buf = (char *)xrealloc(buf, (size_t)ncap);
            cap = ncap;
        }
        memcpy(buf + sz, tmp, n);
        sz += (long)n;
    }
    if (buf == NULL) {
        buf = (char *)xmalloc(1);
        buf[0] = '\0';
        sz = 0;
    } else {
        buf[sz] = '\0';
    }
    if (out_sz) *out_sz = sz;
    return buf;
}

/* Feed a memory buffer through the same line/include logic as a stream.
 *  Large buffers live on the heap so recursive INCLUDE does not blow a
 *  small DOS/Windows stack (3 x MAXLINE = 24 KB per frame was too much). */
static void read_memory_buffer(const char *data, long sz, const char *cur_path)
{
    char *cur_dir = (char *)xmalloc(MAXLINE);
    char *linebuf = (char *)xmalloc(MAXLINE);
    char *fname = (char *)xmalloc(MAXLINE);
    long pos = 0;
    long local_lines = 0;
    long chunks = 0;

    path_dirname(cur_path ? cur_path : "", cur_dir, MAXLINE);

    while (pos < sz) {
        long start = pos;
        long ln;
        int term = 1;
        int maybe_inc;
        long line_len;

        while (pos < sz && data[pos] != '\n' && data[pos] != '\r') pos++;
        ln = pos - start;
        if (pos < sz && data[pos] == '\r') {
            term = 3;
            pos++;
            if (pos < sz && data[pos] == '\n') { term = 2; pos++; }
        } else if (pos < sz && data[pos] == '\n') {
            term = 1;
            pos++;
        }
        line_len = ln;
        if (line_len >= MAXLINE) line_len = MAXLINE - 1;
        if (line_len > 0) memcpy(linebuf, data + start, (size_t)line_len);
        linebuf[line_len] = '\0';

        chunks++;

        maybe_inc = 0;
        if (!opt_noinclude) {
            const char *q;
            for (q = linebuf; *q; q++) {
                if (*q == 'i' || *q == 'I') { maybe_inc = 1; break; }
            }
        }

        if (maybe_inc && parse_include_line(linebuf, fname, MAXLINE)) {
            char *resolved = (char *)xmalloc(MAXLINE);
            FILE *inc;
            if (g_incl_depth >= MAX_INCL_DEPTH) {
                fprintf(stderr, "smartpp: include nesting too deep at '%s'\n",
                        fname);
                store_line(g_nlines, xstrdup(linebuf), (unsigned char)term);
                free(resolved);
            } else {
                inc = open_include(cur_dir, fname, resolved, MAXLINE);
                if (inc == NULL) {
                    fprintf(stderr, "smartpp: cannot open include '%s'\n", fname);
                    store_line(g_nlines, xstrdup(linebuf), (unsigned char)term);
                    free(resolved);
                } else if (incl_on_stack(resolved)) {
                    fprintf(stderr, "smartpp: include cycle skipped: '%s'\n",
                            resolved);
                    fclose(inc);
                    store_line(g_nlines, xstrdup(linebuf), (unsigned char)term);
                    free(resolved);
                } else {
                    char *mark = (char *)xmalloc(MAXLINE);
                    long lines_before = g_nlines;
                    long fsz = 0;
                    char *body;
                    snprintf(mark, MAXLINE,
                             "; SMARTPP include begin: %.200s", resolved);
                    store_line(g_nlines, xstrdup(mark), (unsigned char)term);
                    body = load_entire_stream(inc, &fsz);
                    fclose(inc);
                    fprintf(stderr, "smartpp: including '%s' (%ld bytes)...\n",
                            resolved, fsz);
                    fflush(stderr);
                    g_incl_stack[g_incl_depth++] = xstrdup(resolved);
                    free(resolved);
                    resolved = NULL;
                    read_memory_buffer(body, fsz, g_incl_stack[g_incl_depth - 1]);
                    free(body);
                    free(g_incl_stack[--g_incl_depth]);
                    g_incl_stack[g_incl_depth] = NULL;
                    snprintf(mark, MAXLINE, "; SMARTPP include end");
                    store_line(g_nlines, xstrdup(mark), (unsigned char)term);
                    free(mark);
                    fprintf(stderr, "smartpp: included (%ld lines)\n",
                            g_nlines - lines_before);
                    fflush(stderr);
                }
            }
        } else {
            store_line(g_nlines, xstrdup(linebuf), (unsigned char)term);
        }
        local_lines++;
    }

    free(cur_dir);
    free(linebuf);
    free(fname);
}

static void read_file_stream(FILE *f, const char *cur_path)
{
    long sz = 0;
    char *body = load_entire_stream(f, &sz);
    read_memory_buffer(body, sz, cur_path);
    free(body);
}

static void read_file_path(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "smartpp: cannot open '%s'\n", path);
        return;
    }
    if (g_incl_depth < MAX_INCL_DEPTH) {
        g_incl_stack[g_incl_depth++] = xstrdup(path);
        read_file_stream(f, path);
        free(g_incl_stack[--g_incl_depth]);
        g_incl_stack[g_incl_depth] = NULL;
    } else {
        read_file_stream(f, path);
    }
    fclose(f);
}

/* Legacy entry: read an already-open stream with no path context. */
static void read_file(FILE *f)
{
    read_file_stream(f, NULL);
}

/* ---- labels -----------------------------------------------------------*/

static unsigned lab_hash(const char *s)
{
    unsigned h = 5381;
    while (*s) {
        unsigned c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c = c + 32;
        h = ((h << 5) + h) + c;
    }
    return h % LAB_HASH;
}

static void lab_hash_init(void)
{
    int i;
    for (i = 0; i < LAB_HASH; i++) g_lab_hash[i] = -1;
    g_lab_hash_ready = 1;
}

static void label_add(const char *name, long line)
{
    unsigned h;
    int i;
    if (!g_lab_hash_ready) lab_hash_init();
    h = lab_hash(name);
    for (i = g_lab_hash[h]; i >= 0; i = g_labs[i].next) {
        if (ci_eq(g_labs[i].name, name)) {
            g_labs[i].dup = 1;
            return;
        }
    }
    if (g_nlab >= g_caplab) {
        g_caplab = (g_caplab > 0) ? g_caplab * 2 : 256;
        g_labs = (struct labent *)xrealloc(g_labs, (size_t)g_caplab * sizeof(struct labent));
    }
    strncpy(g_labs[g_nlab].name, name, MAXTOK - 1);
    g_labs[g_nlab].name[MAXTOK - 1] = '\0';
    g_labs[g_nlab].line = line;
    g_labs[g_nlab].dup = 0;
    g_labs[g_nlab].next = g_lab_hash[h];
    g_lab_hash[h] = (int)g_nlab;
    g_nlab++;
}

static long label_find(const char *name, int *pdup)
{
    unsigned h;
    int i;
    *pdup = 0;
    if (!g_lab_hash_ready || g_nlab == 0) return -1;
    h = lab_hash(name);
    for (i = g_lab_hash[h]; i >= 0; i = g_labs[i].next) {
        if (ci_eq(g_labs[i].name, name)) {
            *pdup = g_labs[i].dup;
            return g_labs[i].line;
        }
    }
    return -1;
}

/* record every leading "name:" of every line outside macro bodies */
/* resolve a jump target as seen from line i: GAS numeric locals
*  ("1f" / "1b") are positional  nearest matching "NN:" after or
*  before line i; everything else goes through the label table */
static long resolve_jtarget(long i, const char *tgt, int *pdup)
{
    if (g_gas && isdigit((unsigned char)tgt[0])) {
        char num[MAXTOK];
        size_t l = strlen(tgt);
        long j, step;
        if (l < 2 || l >= MAXTOK) return -1;
        if (tgt[l - 1] == 'f' || tgt[l - 1] == 'F') step = 1;
        else if (tgt[l - 1] == 'b' || tgt[l - 1] == 'B') step = -1;
        else return -1;
        memcpy(num, tgt, l - 1);
        num[l - 1] = '\0';
        for (j = i + step; j >= 0 && j < g_nlines; j += step) {
            char *s = L(j);
            char *r;
            while (*s == ' ' || *s == '\t') s++;
            if (strncmp(s, num, strlen(num)) != 0) continue;
            r = s + strlen(num);
            while (*r == ' ' || *r == '\t') r++;
            if (*r == ':') { *pdup = 0; return j; }
        }
        return -1;
    }
    return label_find(tgt, pdup);
}

static void collect_labels(void)
{
    long i;
    for (i = 0; i < g_nlines; i++) {
        char *s, *cmt;
        if (INDEF(i)) continue;
        if (strlen(L(i)) >= MAXLINE - 1) continue;
        strcpy(g_scratch, L(i));
        cmt = find_comment(g_scratch);
        if (cmt != NULL) *cmt = '\0';
        s = skip_ws(g_scratch);
        for (;;) {
            char *q = s, *r;
            char name[MAXTOK];
            int l = 0;
            if (g_gas && *q == '.') {
                name[l++] = *q++;    /* GAS ".L3:" labels */
            }
            else if (!is_ident_start((unsigned char)*q)) break;
            while (is_ident_char((unsigned char)*q)) {
                if (l < MAXTOK - 1) name[l++] = *q;
                q++;
            }
            name[l] = '\0';
            if (l <= 1 && name[0] == '.') break;   /* lone "." */
            r = q;
            while (*r == ' ' || *r == '\t') r++;
            if (*r != ':') break;
            label_add(name, i);
            s = skip_ws(r + 1);
        }
    }
}

/* detect GAS syntax once, before anything parses: an explicit
*  .intel_syntax / .att_syntax directive wins; otherwise sniff for
*  AT&T registers or GAS-only directives.  MASM files (".386", the
*  simplified ".DATA") never match those spellings. */
static void detect_syntax(void)
{
    static const char *gd[] = {
        ".globl", ".global", ".text", ".long", ".quad", ".asciz",
        ".ascii", ".type", ".size", ".balign", ".section", NULL
    };
    long i;
    int k;
    if (g_synforced) { g_gas = 1; return; }
    for (i = 0; i < g_nlines; i++) {
        char *s = L(i);
        while (*s == ' ' || *s == '\t') s++;
        if (ci_eq_n(s, ".intel_syntax", 13)) { g_gas = 1; g_att = 0; return; }
        if (ci_eq_n(s, ".att_syntax", 11))  { g_gas = 1; g_att = 1; return; }
    }
    for (i = 0; i < g_nlines; i++) {
        char *s = L(i);
        while (*s == ' ' || *s == '\t') s++;
        if (s[0] == '%') { g_gas = 1; g_att = 1; return; }  /* %eax ... */
        for (k = 0; gd[k] != NULL; k++)
            if (ci_eq_n(s, gd[k], (long)strlen(gd[k]))) { g_gas = 1; return; }
    }
}

/* mark the lines inside MACRO..ENDM bodies: never touched there.
*  Also marks the lines of an unterminated GAS block comment. */
static void scan_indefs(void)
{
    long i;
    int depth = 0;
    int inblock = 0;
    detect_syntax();
    for (i = 0; i < g_nlines; i++) {
        char *s, *cmt;
        int isdef = (depth > 0);
        if (inblock) {
            INDEF(i) = (unsigned char)1;
            if (strstr(L(i), "*/") != NULL) inblock = 0;
            continue;
        }
        if (strlen(L(i)) < MAXLINE - 1) {
            strcpy(g_scratch, L(i));
            if (g_gas && strstr(g_scratch, "/*") != NULL &&
                strstr(g_scratch, "*/") == NULL) {
                inblock = 1;         /* opens here, closes later */
                INDEF(i) = (unsigned char)1;
                continue;
            }
            cmt = find_comment(g_scratch);
            if (cmt != NULL) *cmt = '\0';
            s = g_scratch;
            for (;;) {
                char tok[MAXNAME];
                int l = 0;
                while (*s != '\0' && !is_ident_char((unsigned char)*s)) s++;
                if (*s == '\0') break;
                while (is_ident_char((unsigned char)*s)) {
                    if (l < MAXNAME - 1) tok[l++] = *s;
                    s++;
                }
                tok[l] = '\0';
                if (ci_eq(tok, "macro")) { depth++; isdef = 1; }
                else if (ci_eq(tok, "endm")) { if (depth > 0) depth--; }
            }
        } else {
            isdef = 1;              /* huge line: never touch, never cross */
        }
        INDEF(i) = (unsigned char)(isdef ? 1 : 0);
    }
}

/* ---- parsing -----------------------------------------------------------*/

/* v2.20: extended to capture up to 3 operands (for imul R,S,K).
 *  The first two go into o0/o1; the third into o2.  If there are
 *  more than 3, *pmore = 1 and the return is 3. */
static int split_ops(char *rest, char *o0, char *o1, char *o2,
                     int *pmore)
{
    int depth = 0, n = 0, sawcomma = 0;
    int l0 = 0, l1 = 0, l2 = 0;
    char *w;
    o0[0] = '\0';
    o1[0] = '\0';
    o2[0] = '\0';
    *pmore = 0;
    for (w = rest; *w != '\0'; w++) {
        char c = *w;
        if (c == '[' || c == '(' || c == '<') depth++;
        else if (c == ']' || c == ')' || c == '>') { if (depth > 0) depth--; }
        if (c == ',' && depth == 0) {
            sawcomma = 1;
            n++;
            if (n > 2) { *pmore = 1; break; }
            continue;
        }
        if (n == 0) {
            if (l0 < MAXTOK - 1) o0[l0++] = c;
            else { *pmore = 1; break; }
        } else if (n == 1) {
            if (l1 < MAXTOK - 1) o1[l1++] = c;
            else { *pmore = 1; break; }
        } else {
            if (l2 < MAXTOK - 1) o2[l2++] = c;
            else { *pmore = 1; break; }
        }
    }
    o0[l0] = '\0';
    o1[l1] = '\0';
    o2[l2] = '\0';
    trim(o0);
    trim(o1);
    trim(o2);
    if (o0[0] == '\0') *pmore = 1;
    if (sawcomma && o1[0] == '\0') *pmore = 1;
    if (*pmore) return 3;
    return (o2[0] != '\0') ? 3 : (o1[0] != '\0') ? 2 : 1;
}

static int shift_class(const char *m)
{
    static const char *sh[] = {
        "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", NULL
    };
    int i;
    for (i = 0; sh[i] != NULL; i++)
        if (ci_eq(m, sh[i])) return 1;
    return 0;
}

/* v1.87: x87 FPU mnemonics.  Listed so that parse_line() can route them
 *  into I_X87 (closing the peephole window for non-x87 rules) and so the
 *  flag-liveness scan can recognize them as flag-touching (none of the
 *  x87 ops touch the integer status flags -- they live in the SW -- so
 *  the scan treats them as flag-neutral).  The list covers every integer-
 *  observable x87 op: load/store, arithmetic, stack management, compares,
 *  constants, control.  We deliberately do NOT include fnstenv/fstenv
 *  etc. here -- they are opaque (touch the stack frame) and the rule
 *  engine handles them via the I_OTHER path. */
static int is_x87_mnem(const char *m)
{
    static const char *f[] = {
        /* loads / stores */
        "fld", "fst", "fstp", "fild", "fist", "fistp", "fbld", "fbstp",
        "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2",
        /* arithmetic */
        "fadd", "faddp", "fsub", "fsubp", "fsubr", "fsubrp",
        "fmul", "fmulp", "fdiv", "fdivp", "fdivr", "fdivrp",
        "fiadd", "fisub", "fisubr", "fimul", "fidiv", "fidivr",
        "fprem", "fprem1", "fscale", "fsqrt", "fabs", "fchs", "frndint",
        "fxtract", "f2xm1", "fyl2x", "fyl2xp1", "fpatan", "fptan",
        "fsin", "fcos", "fsincos",
        /* compare */
        "fcom", "fcomp", "fcompp", "ficom", "ficomp", "fucom", "fucomp",
        "fucompp", "fcomi", "fcomip", "fucomi", "fucomip", "ftst", "fxam",
        /* stack management */
        "fxch", "ffree", "ffreep",
        /* transcendentals done above; constants done above */
        /* control */
        "fninit", "finit", "fldcw", "fnstcw", "fstcw", "fnstsw", "fstsw",
        "fclex", "fnclex", "fldenv", "fnstenv", "fstenv", "fsave", "fnsave",
        "fwait", "wait",
        NULL
    };
    int i;
    for (i = 0; f[i] != NULL; i++)
        if (ci_eq(m, f[i])) return 1;
    return 0;
}

/* classify an x87 mnemonic's effect on the integer status flags.
 *  Almost all x87 ops leave CF/PF/AF/ZF/SF/OF untouched (they live in
 *  the FPU status word, not EFLAGS).  Exceptions:
 *    - fcomi/fcomip/fucomi/fucomip set CF, PF, ZF (the "fcomi" family,
 *      686+, sets EFLAGS directly from the compare result).
 *    - fstsw ax / fnstsw ax copies the SW into AX -- does not touch
 *      EFLAGS directly, but sahf can then read it via AH.
 *    - fwait/wait is a synchronization hint, no flag effect.
 *  Returns: 0 = no flag effect (treat as transparent); -1 = sets some
 *  flags (caller treats as opaque, abort scan).
 *  NOTE: the flag-bit macros (F_CF=1, F_ZF=8, F_PF=32) are defined
 *  further down; we use the raw values here and assert them below so
 *  this stays correct even if the F_* enum ever changes. */
static int x87_flag_effect(const char *m, int *wr)
{
    *wr = 0;
    if (ci_eq(m, "fcomi") || ci_eq(m, "fcomip") ||
        ci_eq(m, "fucomi") || ci_eq(m, "fucomip")) {
        *wr = 1 | 8 | 32;       /* CF|ZF|PF, see F_* definitions below */
        return 0;
    }
    return 0;       /* every other x87 op leaves EFLAGS untouched */
}

static int is_jcc_mnem(const char *m)
{
    static const char *j[] = {
        "je", "jne", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae",
        "jo", "jno", "js", "jns", "jp", "jnp", "jz", "jnz", "jc", "jnc",
        "jna", "jnae", "jnb", "jnbe", "jng", "jnge", "jnl", "jnle",
        "jpe", "jpo", NULL
    };
    int i;
    for (i = 0; j[i] != NULL; i++)
        if (ci_eq(m, j[i])) return 1;
    return 0;
}

/* exact condition inverse for every supported jcc (P7); NULL if the
*  mnemonic is not one of them */
static const char *jcc_inverse(const char *m)
{
    static const char *pairs[] = {
        "je",   "jne",  "jne",  "je",   "jz",   "jnz",  "jnz",  "jz",
        "jl",   "jge",  "jge",  "jl",   "jle",  "jg",   "jg",   "jle",
        "jb",   "jae",  "jae",  "jb",   "jbe",  "ja",   "ja",   "jbe",
        "jo",   "jno",  "jno",  "jo",   "js",   "jns",  "jns",  "js",
        "jp",   "jnp",  "jnp",  "jp",   "jc",   "jnc",  "jnc",  "jc",
        "jna",  "ja",   "jnae", "jae",  "jnb",  "jb",   "jnbe", "jbe",
        "jng",  "jg",   "jnge", "jge",  "jnl",  "jl",   "jnle", "jle",
        "jpe",  "jpo",  "jpo",  "jpe", NULL
    };
    int i;
    for (i = 0; pairs[i] != NULL; i += 2)
        if (ci_eq(m, pairs[i])) return pairs[i + 1];
    return NULL;
}

/* canonical condition id: JE and JZ are the same condition, etc. */
static int jcc_canon(const char *m)
{
    if (ci_eq(m, "je") || ci_eq(m, "jz")) return 0;
    if (ci_eq(m, "jne") || ci_eq(m, "jnz")) return 1;
    if (ci_eq(m, "jl") || ci_eq(m, "jnge")) return 2;
    if (ci_eq(m, "jle") || ci_eq(m, "jng")) return 3;
    if (ci_eq(m, "jg") || ci_eq(m, "jnle")) return 4;
    if (ci_eq(m, "jge") || ci_eq(m, "jnl")) return 5;
    if (ci_eq(m, "jb") || ci_eq(m, "jc") || ci_eq(m, "jnae")) return 6;
    if (ci_eq(m, "jbe") || ci_eq(m, "jna")) return 7;
    if (ci_eq(m, "ja") || ci_eq(m, "jnbe")) return 8;
    if (ci_eq(m, "jae") || ci_eq(m, "jnb") || ci_eq(m, "jnc")) return 9;
    if (ci_eq(m, "jo")) return 10;
    if (ci_eq(m, "jno")) return 11;
    if (ci_eq(m, "js")) return 12;
    if (ci_eq(m, "jns")) return 13;
    if (ci_eq(m, "jp") || ci_eq(m, "jpe")) return 14;
    if (ci_eq(m, "jnp") || ci_eq(m, "jpo")) return 15;
    return -1;
}

/* ASMC / JWasm / UASM high-level control-flow directives.
 *  These expand to labels+jcc/jmp sequences at assemble time.
 *  SMARTPP must NEVER delete or rewrite them: removing one side of
 *  a .if/.endif pair makes the assembler fail with
 *  "directive must be in control block".  Recognized so P13 stops
 *  at the barrier and so future passes can treat them as opaque
 *  basic-block edges.  See:
 *  https://github.com/nidud/asmc/blob/master/doc/directive/conditional-control-flow.md
 */
static int is_hll_directive(const char *m)
{
    static const char *h[] = {
        ".if", ".endif", ".else", ".elseif",
        ".while", ".endw", ".repeat", ".until", ".untilcxz",
        ".for", ".endf", ".endfor",
        ".switch", ".case", ".default", ".endsw", ".endc",
        ".break", ".continue", ".gotosw",
        ".assert", ".return",
        /* flag/size variants are still the same leading token after
         *  we strip only up to the first space; ASMC writes
         *  ".if", ".ifs", ".ifb", ... as the first identifier. */
        ".ifs", ".ifb", ".ifw", ".ifd", ".ifsd",
        ".whiles", ".whileb", ".whilew", ".whiled",
        ".untils", ".untilb", ".untilw", ".untild",
        ".elseifs", ".elseifb", ".elseifw", ".elseifs",
        NULL
    };
    int i;
    if (m == NULL || m[0] != '.') return 0;
    for (i = 0; h[i] != NULL; i++)
        if (ci_eq(m, h[i])) return 1;
    /* Prefix match: ".ifxxx" that starts with a known HLL stem */
    if (ci_eq_n(m, ".if", 3) || ci_eq_n(m, ".while", 6) ||
        ci_eq_n(m, ".until", 6) || ci_eq_n(m, ".for", 4) ||
        ci_eq_n(m, ".switch", 7) || ci_eq_n(m, ".case", 5) ||
        ci_eq_n(m, ".end", 4) || ci_eq_n(m, ".break", 6) ||
        ci_eq_n(m, ".continue", 9) || ci_eq_n(m, ".return", 7) ||
        ci_eq_n(m, ".repeat", 7) || ci_eq_n(m, ".assert", 7) ||
        ci_eq_n(m, ".gotosw", 7) || ci_eq_n(m, ".default", 8))
        return 1;
    return 0;
}

/* .return always exits the procedure (ASMC expands to ret/retn).
 *  Safe to treat like ret for unreachable-code deletion. */
static int is_hll_return(const char *m)
{
    if (m == NULL) return 0;
    return ci_eq(m, ".return") || ci_eq_n(m, ".return", 7);
}

/* is this a real instruction (safe to delete as unreachable code)?
*  data definitions, directives, macro calls and anything unknown
*  return 0 and stop the P13 scan */
static int is_known_instr(const char *m)
{
    static const char *k[] = {
        "mov", "lea", "push", "pop", "pushf", "popf", "pusha", "popa",
        "xchg", "xor", "and", "or", "add", "sub", "adc", "sbb", "cmp",
        "test", "not", "neg", "mul", "imul", "div", "idiv", "inc", "dec",
        "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr",
        "jmp", "je", "jne", "jl", "jle", "jg", "jge", "jb", "jbe", "ja",
        "jae", "jo", "jno", "js", "jns", "jp", "jnp", "jz", "jnz", "jc",
        "jnc", "jna", "jnae", "jnb", "jnbe", "jng", "jnge", "jnl", "jnle",
        "jpe", "jpo", "call", "ret", "retn", "retf", "int", "int3",
        "into", "loop", "loope", "loopz", "loopne", "loopnz",
        "jcxz", "jecxz", "cbw", "cwd", "clc", "stc", "cmc", "lahf",
        "sahf", "aaa", "aas", "aam", "aad", "daa", "das", "nop",
        "movzx", "movsx", "bswap", "shld", "shrd", "bt", "btc", "btr", "bts",
        "seta", "setae", "setb", "setbe", "setc", "sete", "setg", "setge",
        "setl", "setle", "setna", "setnae", "setnb", "setnbe", "setnc",
        "setne", "setng", "setnge", "setnl", "setnle", "setno", "setnp",
        "setns", "setnz", "seto", "setp", "setpe", "setpo", "sets", "setz",
        "cmova", "cmovae", "cmovb", "cmovbe", "cmovc", "cmove", "cmovg",
        "cmovl", "cmovle", "cmovne", "cmovs", "cmovz",
        "movd", "movq", "movdqa", "movdqu", "movaps", "movups", "movss", "movsd",
        "pxor", "por", "pand", "pandn", "emms", "sfence", "lfence", "mfence",
        "movs", "movsb", "movsw", "movsd", "stos", "stosb", "stosw",
        "stosd", "lods", "lodsb", "lodsw", "lodsd", "scas", "scasb",
        "scasw", "scasd", "cmps", "cmpsb", "cmpsw", "cmpsd", "ins",
        "insb", "insw", "insd", "outs", "outsb", "outsw", "outsd",
        "enter", "leave", NULL
    };
    int i;
    for (i = 0; k[i] != NULL; i++)
        if (ci_eq(m, k[i])) return 1;
    return 0;
}

/* op is "[expr]": parse expr into at most one register term plus a
*  signed constant sum.  Returns 1; sets *r to the register index
*  (-1 if none) and *out to the constant sum.  Returns 0 (out of
*  scope) when a register term is preceded by '-' ("[4-eax]"), when
*  two register terms appear, or when a term is scaled ("[eax*2]").
*  (v1.60) AT&T memory operands "disp(%base)" / "(%base)" are
*  handled too; index/scale forms are out of scope. */
static int att_lea(const char *op, int *r, long *out)
{
    char head[MAXTOK];
    char rn[MAXTOK];
    long acc = 0;
    int k = 0, fr, l = 0;
    const char *p = op;
    *r = -1;
    *out = 0;
    while (*p != '\0' && *p != '(') {
        if (k >= MAXTOK - 1) return 0;
        head[k++] = *p++;
    }
    head[k] = '\0';
    if (*p != '(') return 0;
    trim(head);
    if (head[0] != '\0' && !try_parse_number(head, &acc)) return 0;
    p++;                                 /* past '(' */
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '%') return 0;
    p++;
    while (is_ident_char((unsigned char)*p)) {
        if (l >= MAXTOK - 1) return 0;
        rn[l++] = *p++;
    }
    rn[l] = '\0';
    fr = find_reg(rn);
    if (fr < 0) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == ',') return 0;             /* index/scale: out of scope */
    if (*p != ')') return 0;
    *r = fr;
    *out = acc;
    return 1;
}

static int lea_bracket(const char *op, int *r, long *out)
{
    char buf[MAXTOK];
    long acc = 0, sign = 1, pos;
    int nreg = 0;
    size_t l = strlen(op);
    *r = -1;
    *out = 0;
    if (g_att) return att_lea(op, r, out);
    if (l < 3 || op[0] != '[' || op[l - 1] != ']') return 0;
    memcpy(buf, op + 1, l - 2);
    buf[l - 2] = '\0';
    pos = 0;
    while (buf[pos] != '\0') {
        char term[MAXTOK];
        int lt = 0, fr;
        if (buf[pos] == '+') { sign = 1; pos++; }
        else if (buf[pos] == '-') { sign = -1; pos++; }
        while (buf[pos] == ' ' || buf[pos] == '\t') pos++;
        while (buf[pos] != '\0' && buf[pos] != '+' && buf[pos] != '-') {
            if (buf[pos] != ' ' && buf[pos] != '\t') {
                term[lt++] = buf[pos];
                if (lt >= MAXTOK - 1) return 0;
            }
            pos++;
        }
        term[lt] = '\0';
        if (lt == 0) return 0;
        fr = find_reg(term);
        if (fr >= 0) {
            if (sign < 0) return 0;    /* "[4-eax]": not base + offset */
            if (nreg > 0) return 0;    /* two registers: out of scope  */
            nreg = 1;
            *r = fr;
        }
        else {
            long v;
            if (!try_parse_number(term, &v)) return 0;
            acc += sign * v;
        }
        sign = 1;
    }
    *out = acc;
    return 1;
}

/* v1.80: parse an LEA operand of the form [R + S + const] (Intel) or
*  disp(%R, %S) (AT&T with two registers, scale=1).  Returns 1 and
*  fills *r1, *r2 (the two registers, either order; -1 if absent),
*  *out (the constant sum).  Returns 0 if the operand has a scale
*  other than 1, a negated register, more than two registers, or
*  anything else out of scope.  Used by P41 ("lea R, [R+S] ->
*  add R, S").  Note: P17's lea_bracket above returns 0 for two
*  registers; this sibling accepts exactly two. */
static int lea_two_regs(const char *op, int *r1, int *r2, long *out)
{
    char buf[MAXTOK];
    long acc = 0, sign = 1, pos;
    int nreg = 0;
    int regs[2];
    size_t l = strlen(op);
    *r1 = -1; *r2 = -1; *out = 0;
    if (g_att) return 0;              /* AT&T two-register form has a
                                      *  comma (index/scale) we do not
                                      *  parse; P41 is Intel-only here */
    if (l < 3 || op[0] != '[' || op[l - 1] != ']') return 0;
    memcpy(buf, op + 1, l - 2);
    buf[l - 2] = '\0';
    pos = 0;
    while (buf[pos] != '\0') {
        char term[MAXTOK];
        int lt = 0, fr;
        if (buf[pos] == '+') { sign = 1; pos++; }
        else if (buf[pos] == '-') { sign = -1; pos++; }
        while (buf[pos] == ' ' || buf[pos] == '\t') pos++;
        while (buf[pos] != '\0' && buf[pos] != '+' && buf[pos] != '-') {
            if (buf[pos] != ' ' && buf[pos] != '\t') {
                term[lt++] = buf[pos];
                if (lt >= MAXTOK - 1) return 0;
            }
            pos++;
        }
        term[lt] = '\0';
        if (lt == 0) return 0;
        fr = find_reg(term);
        if (fr >= 0) {
            if (sign < 0) return 0;          /* "[4-eax]" */
            if (nreg >= 2) return 0;          /* three terms: out */
            regs[nreg++] = fr;
        }
        else {
            long v;
            if (!try_parse_number(term, &v)) return 0;
            acc += sign * v;
        }
        sign = 1;
    }
    if (nreg != 2) return 0;
    *r1 = regs[0]; *r2 = regs[1]; *out = acc;
    return 1;
}

/* v1.82: parse an LEA operand of the form [R * K] (Intel syntax,
*  a single scaled register with no base and no displacement) or
*  the AT&T equivalent (,%R,K).  K must be one of the legal SIB
*  scales {2, 4, 8}.  Returns 1 and fills *r (the scaled register)
*  and *scale (2, 4, or 8); returns 0 for any other form (multi-
*  term, scale 1 or 3 etc., memory operands with a base).  Used by
*  P63 ("lea R,[R*K] -> shl R, log2 K", 386+ only since the SIB
*  byte was added in 386). */
static int lea_scaled_single(const char *op, int *r, int *scale)
{
    char buf[MAXTOK];
    size_t l = strlen(op);
    *r = -1; *scale = 0;
    if (g_att) {
        /* AT&T form:  "(,%R,K)" -- base is empty, index is %R, scale K */
        char rn[MAXTOK];
        const char *p = op;
        int kl = 0;
        char sc[8];
        if (l < 5 || op[0] != '(' || op[l - 1] != ')') return 0;
        memcpy(buf, op + 1, l - 2);
        buf[l - 2] = '\0';
        /* buf is ",%R,K" -- base empty */
        if (buf[0] != ',') return 0;
        p = buf + 1;
        if (*p != '%') return 0;
        p++;
        while (is_ident_char((unsigned char)*p)) {
            if (kl >= MAXTOK - 1) return 0;
            rn[kl++] = *p++;
        }
        rn[kl] = '\0';
        if (*p != ',') return 0;
        p++;
        {
            int sl = 0;
            while (*p != '\0' && isdigit((unsigned char)*p)) {
                if (sl >= 7) return 0;
                sc[sl++] = *p++;
            }
            sc[sl] = '\0';
            if (sl == 0 || *p != '\0') return 0;
        }
        {
            long sv;
            if (!try_parse_number(sc, &sv)) return 0;
            if (sv != 2 && sv != 4 && sv != 8) return 0;
            *r = find_reg(rn);
            if (*r < 0) return 0;
            *scale = (int)sv;
        }
        return 1;
    }
    /* Intel: [R*K] */
    if (l < 5 || op[0] != '[' || op[l - 1] != ']') return 0;
    memcpy(buf, op + 1, l - 2);
    buf[l - 2] = '\0';
    {
        char rn[MAXTOK];
        char sc[8];
        const char *star = strchr(buf, '*');
        const char *p;
        int rl = 0, sl = 0;
        long sv;
        if (star == NULL) return 0;
        /* exactly one '*' allowed */
        if (strchr(star + 1, '*') != NULL) return 0;
        /* register: buf .. star-1 (no leading/trailing ws allowed by
         *  MASM for this form, but be lenient) */
        p = buf;
        while (*p == ' ' || *p == '\t') p++;
        while (p < star && is_ident_char((unsigned char)*p)) {
            if (rl >= MAXTOK - 1) return 0;
            rn[rl++] = *p++;
        }
        rn[rl] = '\0';
        while (p < star && (*p == ' ' || *p == '\t')) p++;
        if (p != star) return 0;
        /* scale: star+1 .. end */
        p = star + 1;
        while (*p == ' ' || *p == '\t') p++;
        while (*p != '\0' && isdigit((unsigned char)*p)) {
            if (sl >= 7) return 0;
            sc[sl++] = *p++;
        }
        sc[sl] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '\0' || sl == 0) return 0;
        if (!try_parse_number(sc, &sv)) return 0;
        if (sv != 2 && sv != 4 && sv != 8) return 0;
        *r = find_reg(rn);
        if (*r < 0) return 0;
        *scale = (int)sv;
    }
    return 1;
}

/* v1.80: emit an LEA operand of the form [S + const] (Intel) or
*  disp(%S) (AT&T).  Used by P47 ("mov R,S / add R,imm -> lea R,
*  [S+imm]").  The assembler accepts both "lea R, [S+disp]" and
*  "lea R, [S-disp]" forms; we emit "+N" for positive/zero, "-N"
*  for negative. */
static void emit_lea_disp(char *out, int sreg, long disp)
{
    char num[32];
    if (g_att) {
        if (disp == 0) {
            sprintf(out, "(%%%s)", g_regs[sreg].name);
        } else if (disp > 0) {
            sprintf(num, "%ld", disp);
            sprintf(out, "%s(%%%s)", num, g_regs[sreg].name);
        } else {
            sprintf(num, "%ld", -disp);
            sprintf(out, "-%s(%%%s)", num, g_regs[sreg].name);
        }
    } else {
        if (disp == 0) {
            sprintf(out, "[%s]", g_regs[sreg].name);
        } else if (disp > 0) {
            sprintf(num, "%ld", disp);
            sprintf(out, "[%s+%s]", g_regs[sreg].name, num);
        } else {
            sprintf(num, "%ld", -disp);
            sprintf(out, "[%s-%s]", g_regs[sreg].name, num);
        }
    }
}

/* v1.80: emit an LEA operand of the form [R + R*k] (Intel scaled
*  index) or (k*%R, %R) -- we keep it Intel-only for the same reason
*  as lea_two_regs.  Used by P50 ("imul R, 2^k+1 -> lea R, [R+R*k]").
*  k must be 1, 2, 4, or 8 (the SIB scale field).
*  v1.81: AT&T branch removed -- P50 is gated to !g_att, so the
*  AT&T path was unreachable.  Also removed the dead `num` buffer
*  (sprintf builds the integer in-place with %d). */
static void emit_lea_scaled(char *out, int reg, int k)
{
    /* Intel only: [R + R*k] (P50 is gated to !g_att). */
    sprintf(out, "[%s+%s*%d]", g_regs[reg].name, g_regs[reg].name, k);
}

/* v2.21: emit a general SIB LEA operand [base + index*scale + disp].
 *  Used by P412 (add+add→lea) and P413 (shl+add→lea scaled).
 *  Intel syntax only.  scale must be 1, 2, 4, or 8. */
static void emit_lea_sib(char *out, int base, int index, int scale, long disp)
{
    char num[32];
    if (disp == 0 && scale == 1)
        sprintf(out, "[%s+%s]", g_regs[base].name, g_regs[index].name);
    else if (disp == 0)
        sprintf(out, "[%s+%s*%d]", g_regs[base].name,
                g_regs[index].name, scale);
    else if (scale == 1) {
        if (disp > 0) sprintf(num, "%ld", disp);
        else sprintf(num, "%ld", -disp);
        sprintf(out, "[%s+%s%s%s]", g_regs[base].name,
                g_regs[index].name,
                disp > 0 ? "+" : "-", num);
    } else {
        if (disp > 0) sprintf(num, "%ld", disp);
        else sprintf(num, "%ld", -disp);
        sprintf(out, "[%s+%s*%d%s%s]", g_regs[base].name,
                g_regs[index].name, scale,
                disp > 0 ? "+" : "-", num);
    }
}

static void set_jtarget(struct pinfo *p, const char *op)
{
    int i;
    p->jtarget_ok = 0;
    p->jtarget[0] = '\0';
    if (g_gas && isdigit((unsigned char)op[0])) {
        size_t l = strlen(op);       /* numeric local: "1f" / "1b" */
        if (l < 2 || l >= MAXTOK) return;
        if (op[l - 1] != 'f' && op[l - 1] != 'F' &&
            op[l - 1] != 'b' && op[l - 1] != 'B') return;
        for (i = 0; i < (int)l - 1; i++)
            if (!isdigit((unsigned char)op[i])) return;
        strcpy(p->jtarget, op);
        p->jtarget_ok = 1;
        return;
    }
    if (g_gas && op[0] == '.') {
        for (i = 1; op[i] != '\0'; i++) {   /* GAS ".L3:" labels */
            if (i >= MAXTOK - 1) return;
            if (!is_ident_char((unsigned char)op[i])) return;
        }
        strcpy(p->jtarget, op);
        p->jtarget_ok = 1;
        return;
    }
    if (!is_ident_start((unsigned char)op[0])) return;
    for (i = 0; op[i] != '\0'; i++) {
        if (i >= MAXTOK - 1) return;
        if (!is_ident_char((unsigned char)op[i])) return;
    }
    if (find_reg(op) >= 0) return;               /* indirect register */
    if (op[0] == '@') return;                    /* @F / @B / @@ names */
    if (ci_eq(op, "short") || ci_eq(op, "near") ||
        ci_eq(op, "far") || ci_eq(op, "ptr")) return;
    strcpy(p->jtarget, op);
    p->jtarget_ok = 1;
}

/* AT&T: strip the size suffix when the base is a known mnemonic
*  ("movl" -> "mov"; "jnl", "movsd", "stosb" stay), then swap
*  "src, dst" into the internal Intel order (destination first).
*  v1.81: add "imul" to the base list so AT&T `imull $8, %eax`
*  is recognized as `imul $8, %eax` and P38/P50/P51 can fire on
*  it.  Pre-existing gap: v1.80 left `imull`/`imulw` untouched,
*  so the imul strength-reduction rules stayed silent on AT&T. */
static void att_fix(char *mnem, struct pinfo *p)
{
    static const char *base[] = {
        "mov", "add", "sub", "adc", "sbb", "and", "or", "xor",
        "cmp", "test", "lea", "push", "pop", "inc", "dec", "not",
        "neg", "shl", "shr", "sal", "sar", "rol", "ror", "rcl",
        "rcr", "xchg", "imul", NULL
    };
    size_t l = strlen(mnem);
    int k;
    if (l >= 3) {
        char c = mnem[l - 1];
        if (c == 'b' || c == 'w' || c == 'l') {
            char save = mnem[l - 1];
            mnem[l - 1] = '\0';
            for (k = 0; base[k] != NULL; k++)
                if (ci_eq(mnem, base[k])) break;
            if (base[k] == NULL) mnem[l - 1] = save;
        }
    }
    if (p->nops == 2) {
        char tmp[MAXTOK];
        strcpy(tmp, p->op0);
        strcpy(p->op0, p->op1);
        strcpy(p->op1, tmp);
    }
}

static void parse_line(long idx, struct pinfo *p)
{
    char *s, *cmt, *mstart, *rest;
    char mnem[MAXNAME];
    int more = 0;

    /* v2.25 (S1): serve from the per-line pinfo cache when the
     *  generation stamp matches g_pi_cur_gen (i.e., the entry was
     *  cached during the current pass and hasn't been invalidated).
     *  Cache hits memcpy ~1.6KB instead of re-tokenizing; for 4VIEW
     *  (8240 lines × 3-5 parses/line/pass) this cuts ~30-40% off the
     *  per-pass time on large inputs. */
    if (g_pi_cache != NULL && idx >= 0 && idx < g_pi_cap &&
        g_pi_gen[idx] == g_pi_cur_gen) {
        *p = g_pi_cache[idx];   /* struct copy */
        return;
    }

    p->cls = I_UNK;
    p->haslabel = 0;
    p->hasinstr = 0;
    p->toobig = 0;
    p->nops = 0;
    p->op0[0] = '\0';
    p->op1[0] = '\0';
    p->op2[0] = '\0';
    p->dreg = -1;
    p->sreg = -1;
    p->srcimm = 0;
    p->shiftcount = -1;
    p->mnem[0] = '\0';
    p->prefix[0] = '\0';
    p->comment[0] = '\0';
    p->jtarget[0] = '\0';
    p->jtarget_ok = 0;

    if (strlen(L(idx)) >= MAXLINE - 1) {
        p->cls = I_OTHER;
        p->haslabel = 1;             /* conservative: blocks every pair */
        p->hasinstr = 1;
        p->toobig = 1;
        return;
    }
    strcpy(g_scratch, L(idx));
    cmt = find_comment(g_scratch);
    if (cmt != NULL) {
        char *c = cmt;
        int n = 0;
        while (*c != '\0' && n < MAXCMT - 1) p->comment[n++] = *c++;
        p->comment[n] = '\0';
        if (*c != '\0') p->toobig = 1;   /* comment cut: no rewrites */
        *cmt = '\0';
    }
    s = skip_ws(g_scratch);
    for (;;) {                           /* leading labels */
        char *q = s, *r;
        if (g_gas && (*q == '.' || isdigit((unsigned char)*q))) {
            q++;                         /* GAS ".L3:" / numeric "1:" */
        }
        else if (!is_ident_start((unsigned char)*q)) break;
        while (is_ident_char((unsigned char)*q)) q++;
        r = q;
        while (*r == ' ' || *r == '\t') r++;
        if (*r != ':' || q == s) break;
        p->haslabel = 1;
        s = skip_ws(r + 1);
    }
    mstart = s;
    {
        long pl = mstart - g_scratch;
        if (pl > MAXTOK - 1) { p->toobig = 1; pl = MAXTOK - 1; }
        memcpy(p->prefix, g_scratch, (size_t)pl);
        p->prefix[pl] = '\0';
    }
    if (*s == '.') {                     /* assembler directive / HLL */
        /* Capture ".if", ".return", ".while", ... so P13 and barriers
         *  can recognize ASMC/JWasm/UASM high-level control-flow
         *  directives without treating them as deletable code. */
        {
            char *q = s;
            int l = 0;
            while (*q != '\0' && *q != ' ' && *q != '\t' &&
                   *q != ';' && *q != '\r' && *q != '\n' &&
                   l < MAXNAME - 1)
                mnem[l++] = *q++;
            mnem[l] = '\0';
            strcpy(p->mnem, mnem);
        }
        p->cls = I_OTHER;
        p->hasinstr = 1;
        return;
    }
    if (!is_ident_start((unsigned char)*s)) {
        if (*s != '\0') { p->cls = I_OTHER; p->hasinstr = 1; }
        return;                          /* blank line */
    }
    {
        char *q = s;
        int l = 0, over = 0;
        while (is_ident_char((unsigned char)*q)) {
            if (l < MAXNAME - 1) mnem[l++] = *q;
            else over = 1;
            q++;
        }
        mnem[l] = '\0';
        if (over) { p->cls = I_OTHER; p->hasinstr = 1; return; }
        rest = q;
    }
    p->hasinstr = 1;
    rest = skip_ws(rest);
    p->op2[0] = '\0';            /* v2.20: clear third operand */
    if (*rest != '\0') p->nops = split_ops(rest, p->op0, p->op1, p->op2, &more);
    if (g_att) att_fix(mnem, p);
    strcpy(p->mnem, mnem);       /* every rule needs the mnemonic */

    if (ci_eq(mnem, "mov") && p->nops == 2) {
        long v;
        p->cls = I_MOV;
        p->dreg = find_reg(p->op0);
        p->sreg = find_reg(p->op1);
        if (p->dreg < 0) p->cls = I_OTHER;       /* mem/segment dest */
        else if (p->sreg >= 0) p->srcimm = 0;
        else if (try_parse_number(p->op1, &v)) p->srcimm = 1;
        else if (is_offset_expr(p->op1)) p->srcimm = 1;
        else p->srcimm = 0;
    }
    else if (ci_eq(mnem, "xchg") && p->nops == 2) {
        p->cls = I_XCHG;
        p->dreg = find_reg(p->op0);
        p->sreg = find_reg(p->op1);
        if (p->dreg < 0 || p->sreg < 0) p->cls = I_OTHER;
    }
    else if (ci_eq(mnem, "lea") && p->nops == 2) {
        p->cls = I_LEA;
        p->dreg = find_reg(p->op0);
        if (p->dreg < 0) p->cls = I_OTHER;
    }
    else if (ci_eq(mnem, "pop") && p->nops == 1) {
        p->cls = I_POP;
        p->dreg = find_reg(p->op0);
        if (p->dreg < 0) p->cls = I_OTHER;
    }
    else if (ci_eq(mnem, "push") && p->nops == 1) {
        p->cls = I_PUSH;
        p->dreg = find_reg(p->op0);
        if (p->dreg < 0) {
            /* v1.80: distinguish "push imm" from "push mem" so P46
            *  (push imm / pop R -> mov R, imm) can fire.  Keep the
            *  class as I_PUSH for the immediate form (P3 only fires
            *  when dreg >= 0, so the pair check is unchanged); mem
            *  operands stay I_OTHER. */
            long v;
            if (try_parse_number(p->op0, &v)) {
                p->srcimm = 1;
            } else if (is_offset_expr(p->op0)) {
                p->srcimm = 1;
            } else {
                p->cls = I_OTHER;             /* push mem */
            }
        }
    }
    else if (p->nops == 0 && ci_eq(mnem, "pushf")) p->cls = I_PUSHF;
    else if (p->nops == 0 && ci_eq(mnem, "popf"))  p->cls = I_POPF;
    else if (p->nops == 0 && ci_eq(mnem, "pusha")) p->cls = I_PUSHA;
    else if (p->nops == 0 && ci_eq(mnem, "popa"))  p->cls = I_POPA;
    else if (ci_eq(mnem, "xor") && p->nops == 2) {
        p->dreg = find_reg(p->op0);
        p->sreg = find_reg(p->op1);
        p->cls = (p->dreg >= 0 && p->dreg == p->sreg) ? I_XORRR : I_OTHER;
    }
    else if (shift_class(mnem) && p->nops == 2) {
        long v;
        p->cls = I_SHIFT;
        strcpy(p->mnem, mnem);
        if (try_parse_number(p->op1, &v) && v >= 0 && v <= 255) p->shiftcount = v;
        else p->shiftcount = -1;
    }
    else if (ci_eq(mnem, "jmp") && p->nops == 1) {
        p->cls = I_JMP;
        strcpy(p->mnem, mnem);
        set_jtarget(p, p->op0);
    }
    else if (is_jcc_mnem(mnem) && p->nops == 1) {
        p->cls = I_JCC;
        strcpy(p->mnem, mnem);
        set_jtarget(p, p->op0);
    }
    else if ((ci_eq(mnem, "movzx") || ci_eq(mnem, "movsx")) && p->nops == 2) {
        p->cls = I_MOVZX;
        p->dreg = find_reg(p->op0);
        p->sreg = find_reg(p->op1);
        if (p->dreg < 0) p->cls = I_OTHER;
    }
    else if (is_x87_mnem(mnem)) {
        /* v1.87: classify x87 FPU ops into I_X87.  This closes the
         *  peephole window for non-x87 rules (so e.g. a 'mov R,S'
         *  immediately before 'fld' cannot be folded with the fld),
         *  and lets the table-engine apply x87-specific rules.  The
         *  x87 stack register st(N) is recognized by find_reg()
         *  (family 8) so two fld/fstp chains that touch the same
         *  stack slot can be matched. */
        p->cls = I_X87;
        strcpy(p->mnem, mnem);
        if (p->nops == 2) {
            int r0 = find_reg(p->op0);
            int r1 = find_reg(p->op1);
            /* fxch st(2) has st(2) as op1; fstp st(3) has st(3) as op1 */
            if (r0 >= 0) p->dreg = r0;
            if (r1 >= 0) p->sreg = r1;
        }
        else if (p->nops == 1) {
            int r0 = find_reg(p->op0);
            if (r0 >= 0) p->sreg = r0;       /* fld st(2) loads slot 2 to top */
        }
    }
    else {
        p->cls = I_OTHER;
        /* v1.84: pre-compute sreg for arith/logical 2-operand ops so
         *  P91 (add R,S -> lea on PPro) can test sreg without
         *  re-parsing.  We do NOT set dreg here: existing I_OTHER
         *  rules rely on dreg == -1 to mean "not a register dest
         *  in this class", and use find_reg(pi->op0) explicitly
         *  when they need it.  Adding dreg would silently enable
         *  half-a-dozen rules that currently key off cls==I_MOV or
         *  I_XCHG.  sreg is unused by those rules today. */
        if (p->nops == 2 && p->op1[0] != '\0') {
            p->sreg = find_reg(p->op1);
        }
    }
    /* v2.25 (S1): write the parsed pinfo back to the per-line cache
     *  with the current generation stamp, so the next parse_line(idx,
     *  ...) on this line in the same pass is a memcpy hit. */
    if (g_pi_cache != NULL && idx >= 0 && idx < g_pi_cap && !p->toobig) {
        g_pi_cache[idx] = *p;   /* struct copy */
        g_pi_gen[idx] = g_pi_cur_gen;
    }
}

/* ---- pass helpers --------------------------------------------------------*/

/* v1.83: returns the maximum magnitude of a signed immediate that
*  the `add R, imm` / `sub R, imm` / `or R, imm` / `and R, imm` /
*  `xor R, imm` encodings accept for a destination register of the
*  given width (8 -> imm8 = -128..127; 16 -> imm16 = -32768..32767;
*  32 -> imm32 = -2147483648..2147483647).  Used by P16 and P56 to
*  refuse folds whose result cannot be re-encoded as a single
*  immediate (the assembler would error out). */
static long width_imm_limit(int w)
{
    if (w == 8)  return 0x7FL;          /* signed imm8  */
    if (w == 16) return 0x7FFFL;        /* signed imm16 */
    return 0x7FFFFFFFL;                 /* signed imm32 */
}

/* v2.26 (5.3): width-to-bitmask helper, replacing the duplicated
 *  ternary `(w == 8) ? 0xFFUL : (w == 16) ? 0xFFFFUL : ...` that
 *  appeared in P52-P55, P40, P43-P45, P56, P62/P62b, P8, P344 and
 *  the P430 check.  Returns ~0UL for w >= 64 (the mask is a no-op
 *  there since the C `unsigned long` is the natural width).
 *  v2.26 update: now used by p430_or_and_or_check; the remaining
 *  duplicated ternaries in the C rules (P52/P62/P8) are left as-is
 *  for now -- they're in well-tested code and the refactor risk
 *  outweighs the cosmetic benefit.  Future C-to-table migrations
 *  that need the mask can call this helper. */
static unsigned long width_mask(int w)
{
    if (w == 8)  return 0xFFUL;
    if (w == 16) return 0xFFFFUL;
    if (w == 32) return 0xFFFFFFFFUL;
    return ~0UL;   /* 64-bit or unknown: no truncation needed */
}

/* next line with content (skips deleted, blank and comment-only lines).
 *  v2.25 (S4): uses a local pinfo instead of writing to the global
 *  g_pnext.  The old side effect was never relied upon by any caller
 *  (every caller either ignores the parsed line or re-parses into its
 *  own pinfo slot), but it caused a subtle bug class: flags_clear and
 *  reg_dead_cf, which are called from pre_check, walk forward via
 *  next_code and silently clobbered g_pnext.  try_table_rules uses
 *  g_pnext to hold the 3rd instruction of a 3-op pattern; if pre_check
 *  ran before check(), the 3rd instruction was lost.  P430 worked
 *  around this by carrying pre=0; the fix here removes the workaround
 *  requirement. */
static long next_code(long i)
{
    long j;
    struct pinfo local;
    for (j = i + 1; j < g_nlines; j++) {
        if (DEL(j)) continue;
        parse_line(j, &local);
        if (local.haslabel || local.hasinstr) return j;
    }
    return -1;
}

/* the line carrying the instruction a label introduces (labels may
*  stack; deleted and blank lines are skipped) */
static long instr_after_label(long d)
{
    long j = d;
    while (j < g_nlines) {
        if (!DEL(j)) {
            parse_line(j, &g_pnext);
            if (g_pnext.hasinstr) return j;
        }
        j++;
    }
    return -1;
}

/* can pj act as the overwriting second instruction of a dead store
*  into register r?  (full cover, and no hidden read of r) */
static int writer_ok(struct pinfo *pj, int r)
{
    int fam = g_regs[r].fam;
    switch (pj->cls) {
    case I_MOV:
    case I_LEA:
    case I_MOVZX:
        if (!covers(pj->dreg, r)) return 0;
        return !expr_uses_family(pj->op1, fam);
    case I_POP:
        return covers(pj->dreg, r);
    case I_XORRR:
        return covers(pj->dreg, r);   /* result is 0 whatever r held */
    default:
        return 0;
    }
}

static void replace_line(long idx, const char *newtext)
{
    int term = (int)TERM(idx);
    free(L(idx));
    L(idx) = xstrdup(newtext);
    TERM(idx) = (unsigned char)term;
    /* v2.25 (S1): line text changed; drop the cached pinfo. */
    pi_cache_invalidate(idx);
}

/* v2.25: insert a new line immediately AFTER idx, shifting the rest. */
static void insert_line_after(long idx, const char *text)
{
    long i;
    unsigned char term;
    /* v2.25 (S1): insertion shifts every line after idx, so every
     *  cached pinfo from idx+1 onward now describes the wrong line.
     *  Wholesale invalidate; insert_line_after is rare (only P380/
     *  P50/P51 fire it) so the cost is negligible. */
    pi_cache_invalidate_all();
    term = (unsigned char)((idx >= 0 && idx < g_nlines) ? TERM(idx) : 0);
    if (idx < 0) idx = -1;
    chunk_reserve(g_nlines);
    for (i = g_nlines; i > idx + 1; i--) {
        L(i) = L(i - 1);
        TERM(i) = TERM(i - 1);
        DEL(i) = DEL(i - 1);
        INDEF(i) = INDEF(i - 1);
    }
    L(idx + 1) = xstrdup(text);
    TERM(idx + 1) = term;
    DEL(idx + 1) = 0;
    INDEF(idx + 1) = 0;
    g_nlines++;
}

/* v1.81: delete the instruction on line idx while preserving any
 *  label that line carries.  If pi has a label, the line is
 *  rewritten to just the label text (plus any trailing comment);
 *  otherwise the line is marked deleted (DEL(idx) = 1).  Used by
 *  rules that would otherwise lose a label that other code may
 *  target: P12 case 2 (jcc/jmp to same label), P14 (double xchg),
 *  P16 (add/sub chain folded to net 0).  Without this helper the
 *  v1.80 code simply skipped the rule when the line had a label,
 *  which lost the optimization entirely; this version keeps the
 *  label and removes the dead instruction instead.  The prefix
 *  (everything from start of line up to the mnemonic) is reused
 *  verbatim, then trimmed of trailing whitespace so the emitted
 *  line is "L1:" rather than "L1: ".  The comment, if any, is
 *  re-appended after a single space so any user comment about the
 *  original instruction is preserved. */
static void delete_keep_label(long idx, struct pinfo *pi)
{
    if (pi->haslabel) {
        int n;
        strcpy(g_build, pi->prefix);
        n = (int)strlen(g_build);
        while (n > 0 && (g_build[n-1] == ' ' || g_build[n-1] == '\t')) n--;
        g_build[n] = '\0';
        if (pi->comment[0] != 0) {
            strcat(g_build, " ");
            strcat(g_build, pi->comment);
        }
        replace_line(idx, g_build);   /* replace_line invalidates the cache */
    } else {
        DEL(idx) = 1;
        /* v2.25 (S1): drop the cached pinfo; the line is now deleted
         *  and won't be re-parsed in this pass (next_code skips DEL
         *  lines), but invalidate anyway for tidiness. */
        pi_cache_invalidate(idx);
    }
}

/* v1.84: rewrite line idx to newtext and, when opt_mark is set, append
 *  a trailing comment of the form " ; SMARTPP 1.84: <desc> (PN)" so the
 *  user can see at a glance, in the generated file, every change we
 *  applied.  If the line already has a trailing comment, the marker is
 *  appended after it on the same line; if appending would overflow
 *  MAXLINE the line is left un-marked (the rewrite itself still goes
 *  through, just without the comment, matching the conservative
 *  toobig policy elsewhere).  Used by every v1.84 rule. */
static void replace_line_marked(long idx, const char *newtext,
                                const char *desc, int rule_no)
{
    if (opt_mark && desc != NULL) {
        char buf[MAXLINE];
        int n = (int)strlen(newtext);
        int need = n + 32 + (int)strlen(desc) + 6;  /* " ; SMARTPP 1.84: <desc> (P<n>)\0" */
        if (need < MAXLINE - 1) {
            memcpy(buf, newtext, (size_t)n);
            sprintf(buf + n, " ; SMARTPP %s: %s (P%d)", SMARTPP_VERSION,
                    desc, rule_no);
            replace_line(idx, buf);
            return;
        }
    }
    replace_line(idx, newtext);
}

/* v1.84: delete the instruction on line idx, preserving any label, and
 *  when opt_mark is set leave behind a comment line that records the
 *  deletion (so a deleted instruction is not invisible in the output).
 *  When the line carries a label, the marker comment is appended to
 *  the label-only line; when the line had no label, the line is left
 *  in place as a pure comment ("; SMARTPP 1.84: deleted <text> (PN)")
 *  rather than being physically removed, so the user can see what was
 *  there.  This changes the line-count semantics of -mark: lines that
 *  were deleted are kept as comments.  Without -mark the old
 *  delete_keep_label behavior (true deletion) is preserved. */
static void delete_keep_label_marked(long idx, struct pinfo *pi,
                                     const char *desc, int rule_no)
{
    if (!opt_mark) { delete_keep_label(idx, pi); return; }
    {
        char buf[MAXLINE];
        const char *orig = L(idx);
        int origlen = (int)strlen(orig);
        int n = 0;
        if (origlen > MAXLINE / 2) origlen = MAXLINE / 2;   /* cap */
        if (pi->haslabel) {
            /* keep "L1:" then a marker comment */
            strcpy(buf, pi->prefix);
            n = (int)strlen(buf);
            while (n > 0 && (buf[n-1] == ' ' || buf[n-1] == '\t')) n--;
            buf[n] = '\0';
        }
        if (desc != NULL) {
            int desc_len = (int)strlen(desc);
            int fixed = 18 + 6 + 6 + 8; /* " ; SMARTPP " ver + ": " + "(P" + "): was '" */
            int need = n + fixed + desc_len + origlen + 2;
            if (need < MAXLINE - 1 && desc_len < 200) {
                /* build into a fixed temp buffer first, then copy into
                 *  buf.  This sidesteps gcc's format-overflow warning
                 *  that would otherwise fire because desc_len is
                 *  unknown to the static analyzer. */
                char tmp[280];
                int w = sprintf(tmp, " ; SMARTPP %s: %s (P%d): was '",
                                SMARTPP_VERSION, desc, rule_no);
                if (w < 0 || w >= (int)sizeof(tmp)) { buf[n] = '\0'; }
                else {
                    memcpy(buf + n, tmp, (size_t)w);
                    n += w;
                    memcpy(buf + n, orig, (size_t)origlen);
                    n += origlen;
                    buf[n++] = '\'';
                    buf[n] = '\0';
                }
            }
        }
        if (buf[0] != '\0') replace_line(idx, buf);
        else                DEL(idx) = 1;
    }
}

/* shl and sal are the same instruction; nothing else aliases */
static int shift_same(const char *a, const char *b)
{
    if (ci_eq(a, b)) return 1;
    if ((ci_eq(a, "shl") && ci_eq(b, "sal")) ||
        (ci_eq(a, "sal") && ci_eq(b, "shl"))) return 1;
    return 0;
}

static void rewrite_shift(long idx, struct pinfo *pi, long total)
{
    char num[32];
    strcpy(g_build, pi->prefix);
    strcat(g_build, pi->mnem);
    if (g_att) {
        strcat(g_build, " $");
        sprintf(num, "%ld", total);
        strcat(g_build, num);
        strcat(g_build, ", ");
        strcat(g_build, pi->op0);
    } else {
        strcat(g_build, " ");
        strcat(g_build, pi->op0);
        strcat(g_build, ", ");
        sprintf(num, "%ld", total);
        strcat(g_build, num);
    }
    if (pi->comment[0] != 0) {
        strcat(g_build, " ");
        strcat(g_build, pi->comment);
    }
    replace_line(idx, g_build);
}

static void retarget_line(long idx, struct pinfo *pi, const char *newt)
{
    strcpy(g_build, pi->prefix);
    strcat(g_build, pi->mnem);
    strcat(g_build, " ");
    strcat(g_build, newt);
    if (pi->comment[0] != 0) {
        strcat(g_build, " ");
        strcat(g_build, pi->comment);
    }
    replace_line(idx, g_build);
}

/* case-insensitive substring test */
static int ci_has(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    for (; *s != '\0'; s++)
        if (ci_eq_n(s, needle, (long)n)) return 1;
    return 0;
}

/* the register of family fam that covers exactly bits lo..hi-1 */
static int reg_by_bits(int fam, int lo, int hi)
{
    int i;
    for (i = 0; g_regs[i].name != NULL; i++)
        if (g_regs[i].fam == fam && g_regs[i].lo == lo && g_regs[i].hi == hi)
            return i;
    return -1;
}

/* size in bytes (1, 2 or 4) of the data symbol "name" as this file
*  defines it ("name db ...", "name dw ...", "name label byte", ...);
*  0 when it is not defined here with a plain data directive.  A
*  symbol could just as well be an EQU constant, which movzx/movsx
*  cannot take, so an unknown name is never assumed to be memory. */
static int data_sym_size(const char *name)
{
    long i;
    size_t nl = strlen(name);
    for (i = 0; i < g_nlines; i++) {
        char *s, *q, *cmt;
        char w[MAXNAME];
        int l = 0;
        if (INDEF(i)) continue;
        if (strlen(L(i)) >= MAXLINE - 1) continue;
        strcpy(g_scratch, L(i));
        cmt = find_comment(g_scratch);
        if (cmt != NULL) *cmt = '\0';
        s = skip_ws(g_scratch);
        q = s;
        while (is_ident_char((unsigned char)*q)) q++;
        if ((size_t)(q - s) != nl || !ci_eq_n(s, name, (long)nl)) continue;
        if (*q != ' ' && *q != '\t') continue;     /* "name:" is code */
        q = skip_ws(q);
        while (is_ident_char((unsigned char)*q)) {
            if (l < MAXNAME - 1) w[l++] = *q;
            q++;
        }
        w[l] = '\0';
        if (ci_eq(w, "label")) {
            l = 0;
            q = skip_ws(q);
            while (is_ident_char((unsigned char)*q)) {
                if (l < MAXNAME - 1) w[l++] = *q;
                q++;
            }
            w[l] = '\0';
        }
        if (ci_eq(w, "db") || ci_eq(w, "byte") || ci_eq(w, "sbyte")) return 1;
        if (ci_eq(w, "dw") || ci_eq(w, "word") || ci_eq(w, "sword")) return 2;
        if (ci_eq(w, "dd") || ci_eq(w, "dword") || ci_eq(w, "sdword")) return 4;
        return 0;                  /* the first definition is not data */
    }
    return 0;
}

/* source operand of a movzx/movsx that replaces a "mov L,op" of sz
*  bytes: a register of that size passes as is; a memory operand gets
*  "byte ptr"/"word ptr" unless it already carries a size; a bare
*  symbol (optionally "+n") is accepted only when this file defines it
*  as data of that size.  Numbers, OFFSET and anything else: 0. */
static int typed_src(const char *op, int sz, char *out)
{
    int r = find_reg(op);
    long v;
    char base[MAXTOK];
    const char *p;
    int k = 0;
    if (r >= 0) {
        if ((g_regs[r].hi - g_regs[r].lo) != sz * 8) return 0;
        strcpy(out, op);
        return 1;
    }
    if (strlen(op) + 16 >= MAXTOK) return 0;
    if (try_parse_number(op, &v) || is_offset_expr(op)) return 0;
    if (ci_has(op, " ptr ")) {
        strcpy(out, op);
        return 1;
    }
    if (strchr(op, '[') == NULL) {
        p = op;
        if (!is_ident_start((unsigned char)*p)) return 0;
        while (is_ident_char((unsigned char)*p)) {
            if (k >= MAXTOK - 1) return 0;
            base[k++] = *p++;
        }
        base[k] = '\0';
        if (*p != '\0') {
            long dummy;
            if (*p != '+' && *p != '-') return 0;
            if (!try_parse_number(p, &dummy)) return 0;
        }
        if (data_sym_size(base) != sz) return 0;
    }
    strcpy(out, (sz == 1) ? "byte ptr " : "word ptr ");
    strcat(out, op);
    return 1;
}

/* is "xor X,X" + "mov L,SRC" a zero-extending load?  Returns the
*  index of the target register T (16/32 bits) and the size in bytes
*  of SRC in *psz, or -1.  xf: the xor comes first (the high-byte
*  form also works the other way round, because there the xor leaves
*  the loaded low byte alone). */
static int zx_target(struct pinfo *px, struct pinfo *pm, int xf, int *psz)
{
    int xr = px->dreg, lr = pm->dreg;
    int xs = g_regs[xr].hi - g_regs[xr].lo;
    int ls = g_regs[lr].hi - g_regs[lr].lo;
    if (g_regs[xr].fam != g_regs[lr].fam || g_regs[xr].fam == 4) return -1;
    if (g_regs[lr].lo != 0) return -1;
    if (xf && xs >= 16 && ls < xs) {         /* xor T,T / mov low part */
        *psz = ls / 8;
        return xr;
    }
    if (xs == 8 && g_regs[xr].lo == 8 && ls == 8) {   /* xor AH,AH + AL */
        *psz = 1;
        return reg_by_bits(g_regs[xr].fam, 0, 16);
    }
    return -1;
}

/* a 32-bit code segment may be in play: "mov sp,bp / pop bp" is then
*  not LEAVE (P36 stays off).  False positives only disable the rule. */
/* Returns 1 if a non-comment portion of the line begins with the
*  given token, after optional whitespace.  Avoids false positives
*  that a plain substring match would give on a comment. */
static int line_begins_with(const char *line, const char *tok)
{
    char buf[MAXLINE];
    char *s, *cmt;
    size_t l = strlen(line);
    if (l >= MAXLINE - 1) return 0;
    strcpy(buf, line);
    cmt = find_comment(buf);
    if (cmt != NULL) *cmt = '\0';
    s = skip_ws(buf);
    return ci_eq_n(s, tok, (long)strlen(tok)) &&
           !is_ident_char((unsigned char)s[strlen(tok)]);
}

static void detect_use32(void)
{
    long i;
    if (g_gas) { g_use32 = 1; return; }
    /* MASM "use32" appears inside a segment definition
    *  ("segname SEGMENT ... use32") or as ".model flat"; NASM uses
    *  "bits 32"; GAS uses ".code32".  Match a directive-level token,
    *  not a substring, so a comment like "; this is flat" does not
    *  trip the 32-bit path and disable P36.
    *
    *  v1.83 BUG FIX: the previous code only matched lines whose
    *  first token was "segment", but MASM segment definitions put
    *  the segment *name* first (e.g. `_TEXT SEGMENT USE32`).  The
    *  "use32" token is the actual marker in any position; switch to
    *  scanning for it anywhere on the line, after the comment has
    *  been stripped.  This also catches `option segment:use32`
    *  which the previous `line_begins_with("option")` already
    *  matched by substring, and the bare `SEGMENT USE32` form. */
    for (i = 0; i < g_nlines; i++) {
        char *s = L(i);
        char buf[MAXLINE];
        char *cmt;
        size_t l = strlen(s);
        if (l >= MAXLINE - 1) continue;
        strcpy(buf, s);
        cmt = find_comment(buf);
        if (cmt != NULL) *cmt = '\0';
        /* ".model flat, stdcall" or "option segment:use32" */
        if (line_begins_with(s, ".model") && ci_has(s, "flat")) {
            g_use32 = 1; return;
        }
        if (line_begins_with(s, "option") && ci_has(s, "use32")) {
            g_use32 = 1; return;
        }
        /* v1.83: match "segment ... use32" anywhere on the line,
         *  not just when "segment" is the first token.  MASM form
         *  is `name SEGMENT [align] [combine] 'class' [use16|use32]` */
        if (ci_has(buf, "segment") && ci_has(buf, "use32")) {
            g_use32 = 1; return;
        }
        if (line_begins_with(s, "bits") && ci_has(s, "32")) {
            g_use32 = 1; return;
        }
        if (line_begins_with(s, ".code32") || line_begins_with(s, ".code64")) {
            g_use32 = 1; return;
        }
        /* also: "assume" with fs:/gs: implies 32-bit capable */
    }
}

/* v1.87 BUGFIX: a MASM line like ".NO87 equ 1" defines a numeric
 *  symbol named ".NO87" -- it is NOT the .NO87 FPU directive.  The old
 *  check (!is_ident_char after the token) passed because the char after
 *  ".NO87" is a space.  Tighten to require the directive be the SOLE
 *  token on the line: after the matched name, only whitespace or a
 *  trailing ';' comment may follow.  This also fixes the same hazard
 *  for .286/.386/.X64/.MMX etc. being mistaken for equate definitions. */
static int directive_is_standalone(const char *s, size_t toklen)
{
    const char *p = s + toklen;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n' || *p == '\r') return 1;
    if (*p == ';' || *p == '#') return 1;   /* trailing comment */
    return 0;
}

static int cpu_directive_value(const char *s)
{
    /* v1.84: the levels now use bit values that are SUBSETS so the
     *  existing >= checks still work:
     *    1   = 8086           (0b00000001)
     *    2   = 186             (0b00000011)  -- adds 186 insns
     *    4   = 286             (0b00000111)  -- adds 286 insns
     *    8   = 386             (0b00001111)  -- adds 386 insns (movzx, setcc, jcc near, etc.)
     *   16   = 486             (0b00011111)  -- adds bswap, cmpxchg, invd
     *   32   = Pentium (586)   (0b00111111)  -- adds cmpxchg8b, cpuid serializing
     *   64   = P6 (686, PentiumPro) (0b01111111) -- adds cmov, sse? (no -- only integer)
     *  128   = x86-64 long mode (0b11111111) -- adds REX regs, RIP-relative, etc.
     *  Every old ">= 8" check still passes for 386/486/586/686/x64 because
     *  (level & 8) != 0 for all of them.  New rules that genuinely need
     *  486+ use >= 16, Pentium >= 32, PPro >= 64, x64 == 128 (use
     *  PRE_CPU_X64 which checks g_curcpu >= 128).  The level is the
     *  HIGHEST bit set, so the existing "==" comparisons still work.
     *
     *  v1.87 also recognizes .8087/.287/.387 (FPU coprocessor level)
     *  and .NO87 (disable floating-point).  These set the separate
     *  g_nofpu flag rather than changing g_curcpu, because the FPU
     *  level is orthogonal to the integer CPU level (you can have an
     *  80386 with no FPU, or a 486 whose FPU is enabled by default).
     *  v1.87 BUGFIX: all directive matches now require the directive
     *  be standalone (see directive_is_standalone) so ".NO87 equ 1"
     *  no longer disables FPU rules. */
    /* v2.14: the directive table now also accepts the TASM
     *  Ideal-mode processor directives (P8086 .. P686, with their
     *  N/P/C suffixes: N = normal, P = privileged, C = core -- all
     *  three map to the same integer level here) next to the MASM
     *  dot forms, and the FPU directives of both families
     *  (.8087/.287/.387/.487/.587 and P8087/P287/P387/P487/P587
     *  enable the FPU; .NO87/PNO87 disable it).  The FPU level is
     *  orthogonal to the integer CPU level (you can have an 80386
     *  with no FPU, or a 486 whose FPU is enabled by default), so
     *  it only flips g_nofpu and never changes g_curcpu.
     *  v1.87 BUGFIX (still applies): all directive matches require
     *  the directive be standalone (see directive_is_standalone) so
     *  ".NO87 equ 1" no longer disables FPU rules, "P286 equ 2" no
     *  longer changes the CPU level, and a label like "P286:" is
     *  never mistaken for a directive. */
    static const struct cpudir {
        const char *name;
        int         val;    /* integer CPU level; 0 = FPU-only directive */
        int         fpu;    /* 0 = n/a, 1 = enable FPU, -1 = disable FPU */
    } dirs[] = {
        { ".8086", 1, 0 },  { "p8086", 1, 0 },
        { ".186",  2, 0 },  { "p186",  2, 0 },
        { ".286",  4, 0 },  { "p286",  4, 0 },
        { ".286n", 4, 0 },  { "p286n", 4, 0 },
        { ".286c", 4, 0 },  { ".286p", 4, 0 },  { "p286p", 4, 0 },
        { ".386",  8, 0 },  { "p386",  8, 0 },
        { ".386c", 8, 0 },  { ".386p", 8, 0 },  { "p386n", 8, 0 },  { "p386p", 8, 0 },
        { ".486", 16, 0 },  { "p486", 16, 0 },
        { ".486c",16, 0 },  { ".486p",16, 0 },  { "p486n",16, 0 },  { "p486p",16, 0 },
        { ".586", 32, 0 },  { "p586", 32, 0 },
        { ".586c",32, 0 },  { ".586p",32, 0 },  { "p586n",32, 0 },  { "p586p",32, 0 },
        { ".686", 64, 0 },  { "p686", 64, 0 },
        { ".686c",64, 0 },  { ".686p",64, 0 },  { "p686n",64, 0 },  { "p686p",64, 0 },
        { ".x64",128, 0 },  { ".x64p",128, 0 },
        /* FPU coprocessor directives: enable floating point */
        { ".8087", 0, 1 },  { "p8087", 0, 1 },
        { ".287",  0, 1 },  { "p287",  0, 1 },
        { ".387",  0, 1 },  { "p387",  0, 1 },
        { ".487",  0, 1 },  { "p487",  0, 1 },   /* 486 with integrated FPU */
        { ".587",  0, 1 },  { "p587",  0, 1 },   /* 586 FPU */
        /* FPU disable */
        { ".no87", 0, -1 }, { "pno87", 0, -1 }
    };
    int i;
    while (*s == ' ' || *s == '\t') s++;
    for (i = 0; i < (int)(sizeof(dirs) / sizeof(dirs[0])); i++) {
        size_t l = strlen(dirs[i].name);
        if (ci_eq_n(s, dirs[i].name, (long)l) &&
            directive_is_standalone(s, l)) {
            if (dirs[i].fpu > 0) g_nofpu = 0;
            else if (dirs[i].fpu < 0) g_nofpu = 1;
            return dirs[i].val;
        }
    }
    /* (v2.14: the FPU directives are handled by the table above.) */
    /* .MMX/.XMM/.K3D: SIMD level -- recognized for the source parser's
     *  benefit; they imply a 586+ integer CPU and set no special flag.
     *  We map them to the highest integer level the SIMD extension is
     *  guaranteed available on, so the existing >= N gates hold. */
    if (ci_eq_n(s, ".mmx", 4) && directive_is_standalone(s, 4)) {
        if (g_curcpu < 32) g_curcpu = 32;       /* MMX needs Pentium */
        return 0;
    }
    if (ci_eq_n(s, ".xmm", 4) && directive_is_standalone(s, 4)) {
        if (g_curcpu < 32) g_curcpu = 32;       /* SSE needs P3 in theory */
        return 0;
    }
    if (ci_eq_n(s, ".k3d", 4) && directive_is_standalone(s, 4)) {
        if (g_curcpu < 32) g_curcpu = 32;       /* 3DNow! needs K6+ */
        return 0;
    }
    return 0;
}

/* ---- flag-liveness scan (P9, P10, P11) ------------------------------------*/

#define F_CF   1
#define F_OF   2
#define F_SF   4
#define F_ZF   8
#define F_AF   16
#define F_PF   32
#define F_SZAPC (F_SF | F_ZF | F_AF | F_PF | F_CF)
#define F_ALL6  (F_SZAPC | F_OF)
#define F_CFOF  (F_CF | F_OF)

#define SCAN_MAX 64

static long g_scanwl[SCAN_MAX];  /* worklist: line indices           */
static int  g_scand[SCAN_MAX];   /* worklist: still-differing flags  */
static long g_scanvis[SCAN_MAX]; /* visited lines                    */
static int  g_scanvcd[SCAN_MAX]; /* flags each visited line carried  */

/* which status flags a jcc condition reads */
static int jcc_read_set(const char *m)
{
    if (ci_eq(m, "je") || ci_eq(m, "jz") || ci_eq(m, "jne") ||
        ci_eq(m, "jnz")) return F_ZF;
    if (ci_eq(m, "jl") || ci_eq(m, "jnge") || ci_eq(m, "jge") ||
        ci_eq(m, "jnl")) return F_SF | F_OF;
    if (ci_eq(m, "jle") || ci_eq(m, "jng") || ci_eq(m, "jg") ||
        ci_eq(m, "jnle")) return F_ZF | F_SF | F_OF;
    if (ci_eq(m, "jb") || ci_eq(m, "jc") || ci_eq(m, "jnae") ||
        ci_eq(m, "jae") || ci_eq(m, "jnb") || ci_eq(m, "jnc"))
        return F_CF;
    if (ci_eq(m, "jbe") || ci_eq(m, "jna") || ci_eq(m, "ja") ||
        ci_eq(m, "jnbe")) return F_CF | F_ZF;
    if (ci_eq(m, "jo") || ci_eq(m, "jno")) return F_OF;
    if (ci_eq(m, "js") || ci_eq(m, "jns")) return F_SF;
    if (ci_eq(m, "jp") || ci_eq(m, "jpe") || ci_eq(m, "jnp") ||
        ci_eq(m, "jpo")) return F_PF;
    return F_ALL6;               /* unknown condition: worst case */
}

/* what one instruction does to the status flags: fills rd/wr/div.
*  Returns 0 when understood, -1 when opaque (scan must abort). */
static int flag_sets(struct pinfo *p, int *rd, int *wr, int *div)
{
    const char *m = p->mnem;
    *rd = 0; *wr = 0; *div = 0;
    switch (p->cls) {
    case I_MOV: case I_LEA: case I_POP: case I_PUSH:
    case I_PUSHA: case I_POPA: case I_XCHG: case I_MOVZX:
        return 0;                          /* no flag effect */
    case I_PUSHF: *rd = F_ALL6; return 0;
    case I_POPF:  *wr = F_ALL6; return 0;  /* flags loaded from stack */
    case I_XORRR: *wr = F_ALL6; return 0;
    case I_JCC:   *rd = jcc_read_set(m); return 0;
    case I_JMP:   *div = 1; return 0;
    case I_SHIFT:
        if (ci_eq(m, "rcl") || ci_eq(m, "rcr")) {
            *rd = F_CF; *wr = F_CFOF;
        }
        else if (ci_eq(m, "rol") || ci_eq(m, "ror")) {
            *wr = F_CFOF;                  /* SF,ZF,PF,AF preserved */
        }
        else *wr = F_ALL6;                 /* shl/shr/sal/sar */
        return 0;
    case I_X87:
        return x87_flag_effect(m, wr);     /* fcomi sets CF/PF/ZF; rest clean */
    default:
        break;
    }
    if (ci_eq(m, "add") || ci_eq(m, "sub") || ci_eq(m, "cmp") ||
        ci_eq(m, "neg") || ci_eq(m, "and") || ci_eq(m, "or") ||
        ci_eq(m, "test") || ci_eq(m, "mul") || ci_eq(m, "imul") ||
        ci_eq(m, "div") || ci_eq(m, "idiv") ||
        ci_eq(m, "aam") || ci_eq(m, "aad")) {
        *wr = F_ALL6;                      /* AF undefined counts as gone */
        return 0;
    }
    if (ci_eq(m, "inc") || ci_eq(m, "dec")) {
        *wr = F_SZAPC | F_OF;              /* CF preserved */
        return 0;
    }
    if (ci_eq(m, "not")) return 0;
    if (ci_eq(m, "clc") || ci_eq(m, "stc")) { *wr = F_CF; return 0; }
    if (ci_eq(m, "cmc")) { *rd = F_CF; *wr = F_CF; return 0; }
    if (ci_eq(m, "sahf")) { *wr = F_SZAPC; return 0; }
    if (ci_eq(m, "daa") || ci_eq(m, "das") || ci_eq(m, "aaa") ||
        ci_eq(m, "aas")) { *rd = F_CF | F_AF; return 0; }
    if (ci_eq(m, "into")) { *rd = F_OF; *div = 1; return 0; }
    /* v1.89: ret/retf make arithmetic flags unobservable to the
     *  caller (x86 ABIs do not preserve them across returns).  Mark
     *  them as writing all six so flags_clear can settle paths that
     *  end in a return.  iret restores flags from the stack and is
     *  left as pure divergence.  call is divergence: the callee may
     *  read flags (rare) and we stay conservative. */
    if (ci_eq(m, "ret") || ci_eq(m, "retf")) {
        *wr = F_ALL6;
        *div = 1;
        return 0;
    }
    if (ci_eq(m, "call") || ci_eq(m, "iret") || ci_eq(m, "int") ||
        ci_eq(m, "int3") || ci_eq(m, "loop") || ci_eq(m, "jcxz") ||
        ci_eq(m, "jecxz")) {
        *div = 1;
        return 0;
    }
    if (ci_eq(m, "loope") || ci_eq(m, "loopz") || ci_eq(m, "loopne") ||
        ci_eq(m, "loopnz")) { *rd = F_ZF; *div = 1; return 0; }
    if (ci_eq(m, "movs") || ci_eq(m, "movsb") || ci_eq(m, "movsw") ||
        ci_eq(m, "movsd") || ci_eq(m, "stos") || ci_eq(m, "stosb") ||
        ci_eq(m, "stosw") || ci_eq(m, "stosd") || ci_eq(m, "lods") ||
        ci_eq(m, "lodsb") || ci_eq(m, "lodsw") || ci_eq(m, "lodsd") ||
        ci_eq(m, "scas") || ci_eq(m, "scasb") || ci_eq(m, "scasw") ||
        ci_eq(m, "scasd") || ci_eq(m, "cmps") || ci_eq(m, "cmpsb") ||
        ci_eq(m, "cmpsw") || ci_eq(m, "cmpsd") ||
        ci_eq(m, "ins") || ci_eq(m, "insb") || ci_eq(m, "insw") ||
        ci_eq(m, "insd") || ci_eq(m, "outs") || ci_eq(m, "outsb") ||
        ci_eq(m, "outsw") || ci_eq(m, "outsd")) {
        *div = 1;                          /* string ops: opaque */
        return 0;
    }
    if (ci_eq(m, "xor")) { *wr = F_ALL6; return 0; }
    if (ci_eq(m, "adc") || ci_eq(m, "sbb")) {
        *rd = F_CF; *wr = F_ALL6; return 0;
    }
    if (ci_eq(m, "lahf")) { *rd = F_SZAPC; return 0; }
    if (ci_eq(m, "bsf") || ci_eq(m, "bsr")) { *wr = F_ALL6; return 0; }
    if (ci_eq(m, "bt") || ci_eq(m, "bts") || ci_eq(m, "btr") ||
        ci_eq(m, "btc")) {
        *wr = F_ALL6 & ~F_ZF;              /* ZF is left alone by bt* */
        return 0;
    }
    {
        const char *sfx = NULL;
        char jm[MAXNAME + 2];
        if (ci_eq_n(m, "cmov", 4)) sfx = m + 4;
        else if (ci_eq_n(m, "set", 3)) sfx = m + 3;
        if (sfx != NULL && sfx[0] != '\0' && strlen(sfx) < MAXNAME) {
            jm[0] = 'j';
            strcpy(jm + 1, sfx);
            if (is_jcc_mnem(jm)) { *rd = jcc_read_set(jm); return 0; }
        }
    }
    {
        static const char *nf[] = {
            "mov", "push", "pop", "xchg", "lea", "movzx", "movsx",
            "les", "lds", "lfs", "lgs", "lss", "xlat", "xlatb",
            "cbw", "cwd", "cwde", "cdq", "nop", "cld", "std", "cli",
            "sti", "bswap", "leave", "enter", "in", "out", NULL
        };
        int k;
        for (k = 0; nf[k] != NULL; k++)
            if (ci_eq(m, nf[k])) return 0;     /* no status flag effect */
    }
    return -1;                             /* unknown: abort the scan */
}

/* v2.25 (S5): unified forward-walker for the two conservative dataflow
 *  predicates the table engine needs: "are these flags dead on every
 *  path" (flags_clear) and "is this register dead on every path"
 *  (reg_dead_cf).  Both used to carry their own ~70-line copy of the
 *  worklist + visited-set + jcc-follow boilerplate; the per-inst
 *  decision differed but the loop body was nearly identical.
 *
 *  The shared walker is walk_forward(start, cd, &state).  cd is the
 *  per-path "still needs settling" state (a flag bitmask for
 *  flags_clear, the constant 1 for reg_dead_cf -- 0 always means
 *  "settled").  state carries the kind and the target (flag mask or
 *  reg/fam).  For each visited instruction walk_classify() decides
 *  one of:
 *    WALK_SETTLED   cd becomes 0 on this path; pop next
 *    WALK_BLOCK     target is read; return 0 from the whole walker
 *    WALK_CONTINUE  descend to next_code(i)
 *    WALK_JCC       jcc; descend both next_code(i) and the taken arm
 *    WALK_ABORT     divergent / unknown; return 0
 *  For CONTINUE/JCC, walk_classify writes the new cd into *new_cd.
 *
 *  The walker is SOUND: every WALK_SETTLED is a provable kill, every
 *  WALK_BLOCK a provable read, every WALK_ABORT a conservative
 *  refusal to follow.  Mirrors the discipline the original
 *  flags_clear / reg_dead_cf already carried. */
enum walk_kind { WALK_FLAGS, WALK_REG };
enum walk_verdict {
    WALK_SETTLED = 0, WALK_BLOCK = 1, WALK_CONTINUE = 2,
    WALK_JCC = 3,      WALK_ABORT = 4
};
struct walk_state {
    enum walk_kind kind;
    int target_mask;   /* WALK_FLAGS: the flag mask needing kill */
    int fam;            /* WALK_REG: target family */
    int reg;            /* WALK_REG: target register index */
};

static int walk_classify(struct walk_state *st, struct pinfo *p,
                         int cd, int *new_cd)
{
    int rd, wr, div;
    if (flag_sets(p, &rd, &wr, &div) != 0) return WALK_ABORT;
    if (st->kind == WALK_FLAGS) {
        if (rd & cd) return WALK_BLOCK;        /* a differing flag is read */
        *new_cd = cd & ~wr;
        if (*new_cd == 0) return WALK_SETTLED;
        if (div) return WALK_ABORT;            /* path leaves; cannot follow */
        if (p->cls == I_JCC) return WALK_JCC;
        return WALK_CONTINUE;
    }
    else { /* WALK_REG */
        int dk, op0_is_rw, op0_reads_r, killed, reads;
        if (div) {
            /* ret/retf: only AX/DX families may carry a return value.
             *  Other GPRs die at the call boundary.  Unlocks mov/push
             *  and xor/push folds immediately before ret. */
            if (ci_eq(p->mnem, "ret") || ci_eq(p->mnem, "retf") ||
                ci_eq(p->mnem, "retn")) {
                if (st->fam == 0 || st->fam == 2) return WALK_BLOCK;
                *new_cd = 0;                   /* settled: r dies at return */
                return WALK_SETTLED;
            }
            return WALK_ABORT;                 /* jmp / other divergent */
        }
        dk = find_reg(p->op0);
        op0_is_rw = (p->cls == I_OTHER) &&
            (ci_eq(p->mnem, "add") || ci_eq(p->mnem, "sub") ||
             ci_eq(p->mnem, "adc") || ci_eq(p->mnem, "sbb") ||
             ci_eq(p->mnem, "and") || ci_eq(p->mnem, "or") ||
             ci_eq(p->mnem, "xor") || ci_eq(p->mnem, "cmp") ||
             ci_eq(p->mnem, "test"));
        op0_reads_r = (dk >= 0 && g_regs[dk].fam == st->fam) &&
                      (op0_is_rw || p->cls == I_SHIFT ||
                       p->cls == I_XCHG || p->cls == I_XORRR);
        if (p->cls == I_XORRR) op0_reads_r = 0;
        killed = (dk >= 0 && covers(dk, st->reg) && !op0_reads_r &&
                  !expr_uses_family(p->op1, st->fam));
        if (killed) { *new_cd = 0; return WALK_SETTLED; }
        reads = !killed &&
                ((dk >= 0 && g_regs[dk].fam == st->fam) ||
                 expr_uses_family(p->op1, st->fam));
        if (p->cls == I_PUSH || p->cls == I_PUSHF ||
            p->cls == I_PUSHA) {
            if (expr_uses_family(p->op0, st->fam)) reads = 1;
        }
        if (reads) return WALK_BLOCK;
        *new_cd = cd;                          /* unchanged; still needs kill */
        if (p->cls == I_JCC) return WALK_JCC;
        if (p->cls == I_JMP) return WALK_ABORT;
        return WALK_CONTINUE;
    }
}

static int walk_forward(long start, int cd_init, struct walk_state *st)
{
    int n = 0, nvis = 0;
    if (cd_init == 0) return 1;
    if (start < 0) return 0;
    g_scanwl[n] = start;
    g_scand[n] = cd_init;
    n++;
    while (n > 0) {
        long i;
        int cd, vi, seen, new_cd, verdict;
        struct pinfo *p = &g_pscan;
        n--;
        i = g_scanwl[n];
        cd = g_scand[n];
        if (i < 0) return 0;               /* fell off the end */
        seen = 0;
        for (vi = 0; vi < nvis; vi++) {
            if (g_scanvis[vi] == i) {
                if (g_scanvcd[vi] == cd) { seen = 1; break; }
                return 0;                  /* merge with a different verdict */
            }
        }
        if (seen) continue;
        if (nvis >= SCAN_MAX) return 0;
        g_scanvis[nvis] = i;
        g_scanvcd[nvis] = cd;
        nvis++;
        if (INDEF(i)) return 0;
        parse_line(i, p);
        if (p->toobig) return 0;
        if (!p->hasinstr) {                /* label-only line */
            if (n + 1 > SCAN_MAX) return 0;
            g_scanwl[n] = next_code(i);
            g_scand[n] = cd;
            n++;
            continue;
        }
        verdict = walk_classify(st, p, cd, &new_cd);
        if (verdict == WALK_BLOCK) return 0;
        if (verdict == WALK_ABORT) return 0;
        if (verdict == WALK_SETTLED) continue;
        if (verdict == WALK_CONTINUE) {
            if (n + 1 > SCAN_MAX) return 0;
            g_scanwl[n] = next_code(i);
            g_scand[n] = new_cd;
            n++;
            continue;
        }
        if (verdict == WALK_JCC) {
            long t = -1;
            if (p->jtarget_ok) {
                int dup = 0;
                long dd = label_find(p->jtarget, &dup);
                if (dd >= 0 && !dup) {
                    t = instr_after_label(dd);
                    if (t <= i) return 0;  /* backward jump: loop */
                }
            }
            if (t < 0) return 0;           /* unknown target */
            if (n + 2 > SCAN_MAX) return 0;
            g_scanwl[n] = next_code(i);
            g_scand[n] = new_cd;
            n++;
            g_scanwl[n] = t;
            g_scand[n] = new_cd;
            n++;
            continue;
        }
    }
    return 1;
}

/* v2.25 (S5): flags_clear is now a thin wrapper around walk_forward. */
static int flags_clear(long start, int d)
{
    struct walk_state st;
    st.kind = WALK_FLAGS;
    st.target_mask = d;
    st.fam = -1;
    st.reg = -1;
    return walk_forward(start, d, &st);
}

/* v1.82: walk forward from line `start` (exclusive) and decide
*  whether register `r` is dead -- i.e. the next instruction that
*  mentions r's family FULLY OVERWRITES r (a clean kill) before any
*  instruction reads it.  Returns:
*    1 = r is provably dead (a clean kill is reached first)
*    0 = r is read before being killed (or scan hit something
*        opaque / control flow / end of file)
*  v2.14: the old linear reg_dead_after() was removed.  All callers
 *  use reg_dead_cf() (control-flow aware), which is a strict
 *  superset: every 1 from the linear scan is also a 1 from cf, and
 *  cf can prove more cases through simple forward branches.
 */

/* v1.84: control-flow-aware dead-register scan, the analog of
 *  flags_clear() for register liveness.  Walks forward from `start+1`
 *  along every reachable path (fall-through AND the taken branch of a
 *  conditional jump, just like flags_clear), and asks: on EVERY path,
 *  does a clean kill of `r` arrive before any read of `r`?  Returns 1
 *  when that holds on every path, 0 when it cannot be proved.
 *
 *  Safety discipline (mirrors flags_clear exactly):
 *   - backward conditional jump (target <= i) -> loop, conservatively
 *     return 0 (we cannot bound a fixed point on registers without a
 *     full dataflow framework, and we cannot afford one);
 *   - any I_JMP / call / ret / iret / int / string op / opaque
 *     instruction -> return 0 (control leaves or the read set is
 *     unknowable);
 *   - merge with a different verdict on the same line -> return 0
 *     (we cannot prove liveness through a phi node);
 *   - SCAN_MAX budget exhausted -> return 0.
 *
 *  Like flags_clear, this is a SOUND conservative analysis: every 1
 *  return is provably correct (every reachable kill arrives before any
 *  read), and 0 means "cannot prove", not "r is live".  The rewrites
 *  that consume this helper (P85-P87) treat 0 as "do not fire". */
static int reg_dead_cf(long start, int r)
{
    struct walk_state st;
    if (r < 0) return 0;
    if (start < 0) return 0;
    st.kind = WALK_REG;
    st.target_mask = 1;
    st.fam = g_regs[r].fam;
    st.reg = r;
    return walk_forward(start, 1, &st);
}

/* ===========================================================================
 *  v1.85 TABLE-DRIVEN RULE ENGINE
 *  =========================================================================
 *  Most peephole rules are "match a small pattern of instructions, apply a
 *  small rewrite".  Writing each one in C costs ~30 lines and a fresh
 *  counter slot, and they all share the same shape.  This section defines a
 *  tiny declarative pattern language so that the simple rules live in ONE
 *  table, can be read at a glance, and stay maintainable.
 *
 *  Pattern syntax (the table's `pat` field -- a sequence of op-pats).
 *  Each op_pat matches one instruction.  An op_pat is a struct:
 *
 *      { mnemonic, src_op, dst_op, imm_op }
 *
 *  - mnemonic: case-insensitive opcode ("mov", "or", "cmp", "jne", ...);
 *    NULL matches any mnemonic.  "*jmp" matches any jmp/jcc.  The
 *    opclasses that share the same shape ("add/sub/and/or/xor/adc/sbb/
 *    cmp/test" all define F_ALL6 and read+write op0) are matched by
 *    leaving mnemonic NULL and setting the opclass bitset; an empty
 *    opclass bitset means "any".
 *  - dst_op, src_op: operand patterns.  An operand pattern is one of:
 *      - a register class: "R8", "R16", "R32", "R" (any width), "RA"
 *        (any width, but is the "primary" register for the rule)
 *      - a capture name: "a", "b", "c" ... (binds the operand's register
 *        family so later ops / the rewrite can refer to it)
 *      - the literal "K" -- an immediate operand (any width)
 *      - the literal "M" -- a memory operand (any addressing mode)
 *      - the literal "_" -- "don't care" (any operand)
 *      - the literal "same:A" -- must equal capture A's value
 *
 *  Each op_pat is tagged with a "kind" that selects which matcher:
 *      OP_REG    -- match if the operand is a register of the named
 *                   class (R8/R16/R32/R/RA), binding the family in a
 *                   capture if a capture name is given
 *      OP_SAME   -- match if the operand equals the bound capture
 *      OP_IMM    -- match if the operand parses as an immediate
 *      OP_MEM    -- match if the operand is a memory expression
 *      OP_ANY    -- always matches (don't care)
 *
 *  Preconditions (pre): a small set of predicates the matcher must
 *  prove before the rewrite fires.  Each is a bit:
 *      PRE_FLAGS_DEAD_ALL    all six flags dead after the pattern
 *      PRE_FLAGS_DEAD_CF     CF dead after the pattern
 *      PRE_FLAGS_DEAD_AF     AF dead after the pattern
 *      PRE_REG_DEAD_RA       the rule's primary register is dead after
 *                            (uses reg_dead_cf, follows control flow)
 *      PRE_REG_DEAD_B        the secondary capture is dead after
 *      PRE_NO_CPU_8086       requires 186+ (not 8086)
 *      PRE_CPU_386           requires 386+
 *      PRE_CPU_486           requires 486+ (e.g. bswap, cmpxchg)
 *      PRE_NO_USE32          segment is USE16 (for OFFSET substitution)
 *      PRE_INTEL             syntax is Intel (not AT&T)
 *      PRE_NEXT_IS_JCC       the very next instruction is a Jcc
 *      PRE_NEXT_JCC_NO_CF    next instruction is a Jcc that does not
 *                            read CF
 *      PRE_NEXT_JCC_ZF_ONLY  next instruction is a Jcc that reads
 *                            only ZF
 *      PRE_SRC_IMM           primary register's source is an immediate
 *
 *  Action: a list of actions, one per pattern instruction:
 *      ACT_DEL  delete the instruction (keep label via delete_keep_label)
 *      ACT_KEEP keep the instruction as-is
 *      ACT_REW  rewrite the instruction.  The replacement text uses
 *               the captures: "$a" -> capture a's register name at
 *               this op's width; "$a8/$a16/$a32" -> specific width
 *               variant of capture a; "$K" -> the immediate from the
 *               primary; "$K1" -> imm from op 1 (if pattern has 2).
 *               The replacement string is the FULL new instruction,
 *               without the label/prefix (preserved automatically).
 *
 *  Example (P9, mov R,0 -> xor R,R, flags dead):
 *      {{ OP_REG, "RA", OP_IMM, NULL, "mov", {0} },
 *       PRE_FLAGS_DEAD_ALL,
 *       { ACT_REW, "xor $a, $a" },
 *       "mov R,0 -> xor R,R", 9 }
 *
 *  The engine is the FALLBACK path in run_pass: every existing C rule
 *  runs first (so the bespoke scanners -- flags_clear, reg_dead_cf,
 *  P44/P45/P50/P88 etc. -- keep firing unchanged); only if NO C rule
 *  fired do we consult the table.  This keeps the v1.84 behavior
 *  identical and lets the table absorb the simple, mechanical rules
 *  that were cluttering run_pass.  Rules removed from C and re-expressed
 *  in the table are listed in the comment above g_rules.
 * ======================================================================== */

/* ---- operand pattern matcher ------------------------------------------- */

/* capture table: maps a capture name (single letter a-z) to the bound
 *  register family index (0..7) and width.  -1 = unbound. */
struct capent {
    int fam;        /* 0..7 family, or -1 if not a register */
    int width;      /* 8, 16, 32 -- 0 if not a register */
    int lo;         /* bit offset within the family (0 for low byte,
                     * 8 for AH/CH/DH/BH).  v2.17: needed so
                     *  cap_regname returns AH (not AL) when the
                     *  capture bound a high-byte register -- the old
                     *  code only stored fam+width and matched lo==0,
                     *  so "or ah,ah" was rewritten to "test al,al"
                     *  (wrong register, a miscompilation). */
};

/* v2.25 (S6): resolve a capent back to its g_regs[] index.  Returns
 *  -1 when the capent is unbound or describes a (fam, width, lo)
 *  triple that no concrete register has (e.g. fam 4 / width 8 / lo 0
 *  -- SP has no byte form, so cap_to_regidx refuses it).  Lets the
 *  unified reg_relation() predicate be used from capent-based call
 *  sites (check functions, OP_SAME_FAMILY matcher) without each
 *  caller re-deriving the lookup. */
static int cap_to_regidx(const struct capent *c)
{
    int r;
    if (c == NULL || c->fam < 0 || c->width <= 0) return -1;
    for (r = 0; g_regs[r].name != NULL; r++) {
        if (g_regs[r].fam == c->fam &&
            (g_regs[r].hi - g_regs[r].lo) == c->width &&
            g_regs[r].lo == c->lo) return r;
    }
    return -1;
}

#define NCAP 26

/* operand pattern kinds */
enum {
    OP_ANY = 0,    /* "_" -- always matches */
    OP_REG,        /* register of a class; bind a capture */
    OP_SAME,       /* must equal a previous capture (family+width) */
    OP_IMM,        /* parses as an immediate */
    OP_MEM,        /* memory expression (not a register) */
    OP_REGCLASS,   /* register of a class, no capture */
    OP_IMMVAL,     /* immediate equal to a specific value (imm_val field) */
    OP_DIFF,       /* v1.91: register, different family from same_cap */
    OP_IMM_POW2,   /* v1.91: immediate is 2^k with k>=1; imm_val ignored */
    /* v2.25 (M8): same-family relation kinds.  Each uses `same_cap`
     *  to name the capture to compare against; the relation is the
     *  enum reg_rel value listed.  These let the table express
     *  constraints the original OP_SAME (strict fam+width+lo
     *  equality) cannot, without a custom check function.
     *    OP_SAME_FAM       -- REL_SAME_FAM      (any width, any lo)
     *    OP_SAME_WIDTH     -- REL_SAME_WIDTH    (same width, any lo;
     *                                            e.g. AL vs AH)
     *    OP_COMPLEMENT_LO  -- REL_COMPLEMENT_LO (same fam+width, los
     *                                            sum to width; AL+AH=AX) */
    OP_SAME_FAM,
    OP_SAME_WIDTH,
    OP_COMPLEMENT_LO,
    /* v2.25 (M5): immediate in a closed range [imm_val, imm_hi].
     *  Both bounds are signed longs and inclusive.  Lets table rules
     *  express "shift count 1..31", "imm8 in [-128, 127]", etc.
     *  without a custom check function.  imm_val is the low bound,
     *  imm_hi the high bound. */
    OP_IMM_RANGE
};

/* register class selectors */
enum {
    RC_ANY = 0,    /* any width */
    RC_8,          /* 8-bit register */
    RC_16,         /* 16-bit */
    RC_32,         /* 32-bit */
    RC_64          /* 64-bit (x64 only) */
};

/* opclass bitsets (used when mnemonic is NULL but opclass is set).
 *  These let one table entry match every member of a class
 *  ("add/sub/and/or/xor/adc/sbb/cmp/test"). */
#define OC_ADDSUB  (1u<<0)
#define OC_LOGIC   (1u<<1)
#define OC_SHIFT    (1u<<2)
#define OC_ARITH    (OC_ADDSUB | OC_LOGIC)

/* operand-pattern spec */
struct op_pat {
    int   kind;          /* OP_REG / OP_SAME / OP_IMM / OP_MEM / OP_ANY / OP_REGCLASS / OP_IMMVAL */
    int   rclass;        /* RC_ANY / RC_8 / RC_16 / RC_32 */
    char  cap;           /* capture name (0 if none) */
    char  same_cap;      /* for OP_SAME: which capture to compare to */
    long  imm_val;       /* for OP_IMMVAL: the required value (compared as signed long);
                          *  for OP_IMM_RANGE: the low end of the range (inclusive). */
    int   imm_has;       /* 1 if imm_val is meaningful (set by IV() macro) */
    long  imm_hi;        /* v2.25 (M5): for OP_IMM_RANGE: the high end
                          *  of the range (inclusive).  Unused for other
                          *  kinds; zero-initialized by the positional
                          *  macros below. */
};

/* precondition bits */
#define PRE_FLAGS_DEAD_ALL    0x0001u
#define PRE_FLAGS_DEAD_CF     0x0002u
#define PRE_FLAGS_DEAD_AF     0x0004u
/* v2.25 (M1): single-flag dead preconditions, parallel to CF/AF.
 *  Let table rules express "only SF must be dead" (e.g. movzx+test
 *  where SF differs but ZF/PF/CF/OF all match) without resorting
 *  to a custom check function that calls flags_clear directly.
 *  Bit values start at 0x100000u (bit 20), past the existing
 *  PRE_AGGRESSIVE (0x80000u, bit 19) -- an earlier draft reused
 *  0x80000u and silently collided with PRE_AGGRESSIVE. */
#define PRE_FLAGS_DEAD_SF     0x100000u
#define PRE_FLAGS_DEAD_ZF     0x200000u
#define PRE_FLAGS_DEAD_OF     0x400000u
#define PRE_FLAGS_DEAD_PF     0x800000u
#define PRE_REG_DEAD_RA       0x0008u
#define PRE_REG_DEAD_B        0x0010u
#define PRE_NO_CPU_8086       0x0020u
#define PRE_CPU_386           0x0040u
#define PRE_CPU_486           0x0080u
#define PRE_NO_USE32          0x0100u
#define PRE_INTEL             0x0200u
#define PRE_NEXT_IS_JCC       0x0400u
#define PRE_NEXT_JCC_NO_CF    0x0800u
#define PRE_NEXT_JCC_ZF_ONLY  0x1000u
/* v2.26 (4.8): PRE_SRC_IMM (was 0x2000u) removed -- the check body
 *  was a no-op placeholder and no rule ever set the bit.  0x2000u
 *  is now free for reuse. */
#define PRE_NOT_SP            0x4000u   /* primary register is not SP */
#define PRE_CPU_X64           0x8000u   /* rule needs .X64 (long mode) */
#define PRE_FPU               0x10000u  /* rule needs x87 FPU enabled (.NO87 forbids) */
#define PRE_STACK_MEM_0       0x20000u  /* inst0 op1 is pure [bp/ebp/rbp±N] */
#define PRE_STACK_MEM_1       0x40000u  /* inst1 op1 is pure [bp/ebp/rbp±N] */
#define PRE_AGGRESSIVE        0x80000u  /* only when -Ox */

/* action kinds */
enum {
    ACT_KEEP = 0,    /* leave the instruction as-is */
    ACT_DEL,          /* delete (keep label) */
    ACT_REW           /* rewrite -- text in `text` */
};

struct op_act {
    int   kind;
    const char *text;   /* for ACT_REW: the new instruction body */
};

/* a rule in the table.  n == 1 (single-inst) or 2 (pair). */
#define MAXPAT 4  /* v2.11: up to 4-instruction patterns */
struct rule {
    int   n;                       /* 1..MAXPAT instructions */
    int   rule_no;                 /* P-number, e.g. 9 */
    struct {                        /* per-instruction pattern */
        const char *mnem;          /* NULL = match by opclass */
        unsigned    opclass;       /* 0 = ignore; otherwise OR of OC_ */
        struct op_pat op0, op1;     /* two operand patterns */
        int   nops;                /* 1, 2, or 0 (any) */
    } pat[MAXPAT];
    unsigned pre;                  /* precondition bits */
    struct op_act act[MAXPAT];      /* one action per pattern inst */
    const char *desc;              /* one-line description */
    /* Optional predicate; NULL = always pass after pre_check.
     *  Signature: 1 = accept rule, 0 = reject.  Use for ad-hoc
     *  filters (lea_mem_avoids_reg, width checks) without new PRE bits. */
    int (*check)(const struct capent *cap, long i, long j2);
    /* v2.25 (M6): dead-capture bitmask.  Bit (1u << (c-'a')) requests
     *  reg_dead_cf for capture c after the pattern.  Generalizes
     *  PRE_REG_DEAD_RA (capture 'a') and PRE_REG_DEAD_B (capture 'b')
     *  to any of the 26 capture letters, so 3-op and 4-op rules with
     *  intermediate dead registers (e.g. lea+lea+lea fusion where
     *  captures 'a' and 'b' are both intermediates that die) can be
     *  expressed without a custom check function.  Field is at the
     *  end of the struct so existing positional initializers
     *  zero-initialize it automatically. */
    unsigned pre_dead_caps;
};

/* the rule table.  Declared later (after the matcher functions, which
 *  forward-reference the helpers).  Pointer kept here so the matcher
 *  sees it. */
static const struct rule *g_rules = NULL;
static int g_nrules = 0;

/* match one operand pattern against an operand text.  Fills cap on
 *  success.  Returns 1 on match, 0 otherwise. */
static int op_pat_match(struct op_pat *p, const char *op,
                        struct capent *cap)
{
    int r;
    if (p->kind == OP_ANY) return 1;
    if (op == NULL || op[0] == '\0') return 0;
    if (p->kind == OP_IMM) {
        long v;
        if (try_parse_number(op, &v)) return 1;
        if (is_offset_expr(op)) return 1;
        return 0;
    }
    if (p->kind == OP_IMMVAL) {
        long v;
        if (!try_parse_number(op, &v)) return 0;
        return v == p->imm_val;
    }
    if (p->kind == OP_MEM) {
        /* not a register, not a number */
        long v;
        if (find_reg(op) >= 0) return 0;
        if (try_parse_number(op, &v)) return 0;
        if (is_offset_expr(op)) return 0;
        return 1;     /* any non-register, non-immediate is "memory" */
    }
    if (p->kind == OP_SAME) {
        int ci = p->same_cap - 'a';
        int cr;
        if (ci < 0 || ci >= NCAP) return 0;
        if (cap[ci].fam < 0) return 0;
        r = find_reg(op);
        if (r < 0) return 0;
        /* v1.85.1: must match BOTH family and width.  Without the
         *  width check, "mov eax, ax" (a zero-extension, NOT a no-op)
         *  would match RR_('a'),SM_('a') and be wrongly deleted by
         *  the "mov R,R -> delete" rule.  eax and ax share family 0
         *  but differ in width (32 vs 16).
         *  v2.17: must ALSO match lo, so "or ah,al" (same family 0,
         *  same width 8, but lo 8 vs 0) does NOT match SM_('a') --
         *  it is not "R,R" and must not be rewritten to "test ah,ah"
         *  (or worse, "test al,al" via the lo==0 cap_regname bug).
         *  v2.25 (S6): the three-line fam+width+lo comparison is now
         *  a single reg_relation(..., REL_SAME) call.  cap_to_regidx
         *  turns the capent into a g_regs index so reg_relation can
         *  do the unified test. */
        cr = cap_to_regidx(&cap[ci]);
        if (cr < 0) return 0;
        return reg_relation(r, cr, REL_SAME);
    }
    if (p->kind == OP_DIFF) {
        int ci = p->same_cap - 'a';
        int cr;
        if (ci < 0 || ci >= NCAP) return 0;
        if (cap[ci].fam < 0) return 0;
        r = find_reg(op);
        if (r < 0) return 0;
        cr = cap_to_regidx(&cap[ci]);
        if (cr < 0) {
            /* cap was bound but to a (fam,width,lo) no concrete
             *  register has -- the safest answer is "not same", so
             *  OP_DIFF still matches. */
            return 1;
        }
        return reg_relation(r, cr, REL_DISJOINT);
    }
    /* v2.25 (M8): same-family relation kinds.  All three follow the
     *  same shape: resolve the bound capture to a g_regs index via
     *  cap_to_regidx, then ask reg_relation() for the named mode.
     *  The rclass filter (if any) was applied at the OP_REG match
     *  that bound the capture; here we only check the relation. */
    if (p->kind == OP_SAME_FAM ||
        p->kind == OP_SAME_WIDTH ||
        p->kind == OP_COMPLEMENT_LO) {
        int ci = p->same_cap - 'a';
        int cr;
        enum reg_rel rel;
        if (ci < 0 || ci >= NCAP) return 0;
        if (cap[ci].fam < 0) return 0;
        r = find_reg(op);
        if (r < 0) return 0;
        cr = cap_to_regidx(&cap[ci]);
        if (cr < 0) return 0;   /* capture doesn't resolve to a real reg */
        rel = (p->kind == OP_SAME_FAM)      ? REL_SAME_FAM :
              (p->kind == OP_SAME_WIDTH)    ? REL_SAME_WIDTH :
                                              REL_COMPLEMENT_LO;
        return reg_relation(r, cr, rel);
    }
    if (p->kind == OP_IMM_POW2) {
        long v;
        if (!try_parse_number(op, &v)) return 0;
        if (v <= 0) return 0;
        /* exact power of two? */
        return ((v & (v - 1)) == 0);
    }
    /* v2.25 (M5): immediate in a closed range.  Both bounds are
     *  signed longs; the operand must parse as a number and satisfy
     *  imm_val <= v <= imm_hi.  Lets table rules encode shift-count
     *  gates (1 <= k <= 31), imm8 bounds, and similar without a
     *  custom check function. */
    if (p->kind == OP_IMM_RANGE) {
        long v;
        if (!try_parse_number(op, &v)) return 0;
        return v >= p->imm_val && v <= p->imm_hi;
    }
    if (p->kind == OP_REG || p->kind == OP_REGCLASS) {
        r = find_reg(op);
        if (r < 0) return 0;
        {
            int w = g_regs[r].hi - g_regs[r].lo;
            if (p->rclass == RC_8 && w != 8) return 0;
            if (p->rclass == RC_16 && w != 16) return 0;
            if (p->rclass == RC_32 && w != 32) return 0;
            if (p->rclass == RC_64 && w != 64) return 0;
        }
        if (p->kind == OP_REG && p->cap != 0) {
            int ci = p->cap - 'a';
            if (ci < 0 || ci >= NCAP) return 0;
            cap[ci].fam = g_regs[r].fam;
            cap[ci].width = g_regs[r].hi - g_regs[r].lo;
            cap[ci].lo = g_regs[r].lo;  /* v2.17: AH vs AL */
        }
        return 1;
    }
    return 0;
}

/* match a single instruction against a pattern entry */
static int pat_match_inst(const struct pinfo *p,
                          const struct rule *r, int idx,
                          struct capent *cap)
{
    const char *m = r->pat[idx].mnem;
    unsigned oc = r->pat[idx].opclass;
    int nops = r->pat[idx].nops;
    if (nops != 0 && p->nops != nops) return 0;
    if (m != NULL) {
        if (!ci_eq(p->mnem, m)) return 0;
    }
    else if (oc != 0) {
        int hit = 0;
        if ((oc & OC_ADDSUB) && (ci_eq(p->mnem, "add") ||
            ci_eq(p->mnem, "sub") || ci_eq(p->mnem, "adc") ||
            ci_eq(p->mnem, "sbb"))) hit = 1;
        if (!hit && (oc & OC_LOGIC) && (ci_eq(p->mnem, "and") ||
            ci_eq(p->mnem, "or") || ci_eq(p->mnem, "xor") ||
            ci_eq(p->mnem, "test") || ci_eq(p->mnem, "cmp"))) hit = 1;
        if (!hit && (oc & OC_SHIFT) && shift_class(p->mnem)) hit = 1;
        if (!hit) return 0;
    }
    if (nops >= 1) {
        if (!op_pat_match((struct op_pat *)&r->pat[idx].op0,
                          p->op0, cap)) return 0;
    }
    if (nops >= 2) {
        if (!op_pat_match((struct op_pat *)&r->pat[idx].op1,
                          p->op1, cap)) return 0;
    }
    return 1;
}

/* check the precondition set against the current context.  `last_idx`
 *  is the line index of the LAST instruction in the matched pattern
 *  (i for n=1, j2 for n=2, j3 for n=3, j4 for n=4); the dead-flag /
 *  dead-reg scans start at next_code(last_idx) so they see the
 *  instruction AFTER the whole pattern, not the instruction after
 *  inst1 of a 3-op pattern (which was the v2.25 latent bug from
 *  finding 3.1).  `cap` is the captures bound during matching.
 *  v2.25 (M6): added `dead_caps` bitmask for the generalized
 *  PRE_REG_DEAD_CAP mechanism. */
static int is_stack_mem_operand(const char *s);
static int pre_check(unsigned pre, unsigned dead_caps, long last_idx,
                     struct capent *cap)
{
    long after = next_code(last_idx);
    if (pre & PRE_FLAGS_DEAD_ALL)
        if (!flags_clear(after, F_ALL6)) return 0;
    if (pre & PRE_FLAGS_DEAD_CF)
        if (!flags_clear(after, F_CF)) return 0;
    if (pre & PRE_FLAGS_DEAD_AF)
        if (!flags_clear(after, F_AF)) return 0;
    /* v2.25 (M1): single-flag dead preconditions.  Same shape as the
     *  CF/AF checks above; each calls flags_clear on just one flag. */
    if (pre & PRE_FLAGS_DEAD_SF)
        if (!flags_clear(after, F_SF)) return 0;
    if (pre & PRE_FLAGS_DEAD_ZF)
        if (!flags_clear(after, F_ZF)) return 0;
    if (pre & PRE_FLAGS_DEAD_OF)
        if (!flags_clear(after, F_OF)) return 0;
    if (pre & PRE_FLAGS_DEAD_PF)
        if (!flags_clear(after, F_PF)) return 0;
    if (pre & PRE_REG_DEAD_RA) {
        int ci = 'a' - 'a';
        if (cap[ci].fam < 0) return 0;
        {
            int r;
            /* find any register of this family to feed reg_dead_cf */
            for (r = 0; r < (int)(sizeof(g_regs)/sizeof(g_regs[0])); r++) {
                if (g_regs[r].fam == cap[ci].fam &&
                    g_regs[r].lo == 0 &&
                    g_regs[r].hi == cap[ci].width) break;
            }
            if (r >= (int)(sizeof(g_regs)/sizeof(g_regs[0]))) return 0;
            if (!reg_dead_cf(after, r)) return 0;
        }
    }
    if (pre & PRE_REG_DEAD_B) {
        int ci = 'b' - 'a';
        if (cap[ci].fam < 0) return 0;
        {
            int r;
            for (r = 0; r < (int)(sizeof(g_regs)/sizeof(g_regs[0])); r++) {
                if (g_regs[r].fam == cap[ci].fam &&
                    g_regs[r].lo == 0 &&
                    g_regs[r].hi == cap[ci].width) break;
            }
            if (r >= (int)(sizeof(g_regs)/sizeof(g_regs[0]))) return 0;
            if (!reg_dead_cf(after, r)) return 0;
        }
    }
    if (pre & PRE_NO_CPU_8086) if (g_curcpu < 2) return 0;
    if (pre & PRE_CPU_386)     if (g_curcpu < 8) return 0;
    if (pre & PRE_CPU_486)     if (g_curcpu < 16) return 0;
    if (pre & PRE_CPU_X64)     if (g_curcpu < 128) return 0;
    if (pre & PRE_FPU)         if (g_nofpu) return 0;
    if (pre & PRE_NO_USE32)    if (g_use32) return 0;
    if (pre & PRE_INTEL)       if (g_att) return 0;
    if (pre & PRE_NOT_SP) {
        int ci = 'a' - 'a';
        if (cap[ci].fam == 4) return 0;   /* SP family */
    }
    if (pre & PRE_STACK_MEM_0) {
        /* g_pcur is inst0 when called from try_table_rules. */
        if (!is_stack_mem_operand(g_pcur.op1) &&
            !is_stack_mem_operand(g_pcur.op0))
            return 0;
    }
    if (pre & PRE_AGGRESSIVE) {
        if (!opt_aggressive) return 0;
    }
    if (pre & PRE_STACK_MEM_1) {
        /* v2.26 (3.1): PRE_STACK_MEM_1 checks inst1's operand; the
         *  caller has already parsed g_ppair for a 2+ inst pattern.
         *  If last_idx == i (n=1 rule), this pre is meaningless and
         *  we conservatively reject. */
        if (last_idx < 0) return 0;
        if (!is_stack_mem_operand(g_ppair.op1) &&
            !is_stack_mem_operand(g_ppair.op0))
            return 0;
    }
    /* v2.26 (4.8): PRE_SRC_IMM (0x2000u) removed.  The check body
     *  was a no-op placeholder ("always succeeds" per the v1.85
     *  comment) and no table rule ever set the bit.  The bit value
     *  0x2000u is now free for reuse. */
    if (pre & (PRE_NEXT_IS_JCC | PRE_NEXT_JCC_NO_CF |
               PRE_NEXT_JCC_ZF_ONLY)) {
        long k = next_code(last_idx);
        struct pinfo *pj = &g_ppair;
        int rd;
        if (k < 0 || INDEF(k)) return 0;
        parse_line(k, pj);
        if (pj->cls != I_JCC) {
            if (pre & PRE_NEXT_IS_JCC) return 0;
            if (pre & PRE_NEXT_JCC_NO_CF) return 0;
            if (pre & PRE_NEXT_JCC_ZF_ONLY) return 0;
            return 1;
        }
        rd = jcc_read_set(pj->mnem);
        if (pre & PRE_NEXT_IS_JCC) { /* satisfied: pj is a Jcc */ }
        if (pre & PRE_NEXT_JCC_NO_CF)  if (rd & F_CF) return 0;
        if (pre & PRE_NEXT_JCC_ZF_ONLY) if (rd != F_ZF) return 0;
    }
    /* v2.25 (M6): per-capture dead-register scan.  Each set bit in
     *  dead_caps names a capture letter ('a'..'z') that must be
     *  provably dead after the pattern, via reg_dead_cf.  This is
     *  the generalization of PRE_REG_DEAD_RA / PRE_REG_DEAD_B (which
     *  only cover captures 'a' and 'b') to any letter, so 3-op and
     *  4-op rules with intermediate dead registers don't need a
     *  custom check function. */
    if (dead_caps) {
        int ci;
        for (ci = 0; ci < NCAP; ci++) {
            if (dead_caps & (1u << ci)) {
                int regidx = cap_to_regidx(&cap[ci]);
                if (regidx < 0) return 0;
                if (!reg_dead_cf(after, regidx)) return 0;
            }
        }
    }
    return 1;
}

/* v1.87: given a register index into g_regs[], return the name of the
 *  register of the SAME family at the given width (lo==0), or NULL if
 *  no such width exists for that family.  Used by P9 to emit the
 *  32-bit xor form for a 64-bit register on x64 (the canonical zeroing
 *  idiom that saves 1 byte -- no REX.W prefix -- and zero-extends to
 *  64 bits for free). */
static const char *reg_name_at_width(int reg_idx, int width)
{
    int fam = g_regs[reg_idx].fam;
    int r;
    for (r = 0; g_regs[r].name != NULL; r++) {
        if (g_regs[r].fam == fam &&
            g_regs[r].lo == 0 &&
            g_regs[r].hi == width) return g_regs[r].name;
    }
    return NULL;
}

/* render a register name from a capture at a given (possibly wider)
 *  width.  cap[name] is the bound family; width is 8/16/32. */
static const char *cap_regname(struct capent *cap, char name, int width)
{
    int ci = name - 'a';
    int r;
    int want_lo;
    if (ci < 0 || ci >= NCAP) return NULL;
    if (cap[ci].fam < 0) return NULL;
    /* v2.17: when the requested width matches the captured width,
     *  use the captured lo so high-byte registers (AH/CH/DH/BH,
     *  lo=8) resolve to themselves, not to their low-byte siblings.
     *  When the width differs (forced via $a8/$a16/$a32), fall back
     *  to lo==0 -- the natural register of that family at that width
     *  (e.g. $a32 of an AH capture returns EAX, not some high dword). */
    want_lo = (width == cap[ci].width) ? cap[ci].lo : 0;
    for (r = 0; g_regs[r].name != NULL; r++) {
        if (g_regs[r].fam == cap[ci].fam &&
            g_regs[r].lo == want_lo &&
            g_regs[r].hi == width) return g_regs[r].name;
    }
    return NULL;
}

/* v2.25 (M4): evaluate an arithmetic expression over immediates.
 *  Used by the ${...} template form.  Grammar (left-to-right, no
 *  precedence -- callers should parenthesize when in doubt):
 *    expr := term ( OP term )*
 *    term := NUMBER | K | K1 | Knot | Kneg | Klog2 | ( expr ) | ~term
 *    OP   := + - * / % << >> & | ^
 *  Inside ${...}, immediates are referenced as bare K / K1 / Knot /
 *  Kneg / Klog2 (NO leading $ -- the $ was consumed by the ${ opener
 *  in expand_template).  Returns 1 on success (value in *out), 0 on
 *  parse/eval error (caller -- expand_template -- bails the rule).
 *  Division by zero returns 0.  All arithmetic is signed long;
 *  bitwise ~ is two's-complement. */
static int eval_imm_expr(const char **pp, long *out,
                         const char *imm0, const char *imm1)
{
    const char *s = *pp;
    long v = 0;
    int have_val = 0;

    /* skip whitespace */
    while (*s == ' ' || *s == '\t') s++;

    /* parse first term */
    if (*s == '~') {
        long inner;
        s++;
        if (!eval_imm_expr(&s, &inner, imm0, imm1)) return 0;
        v = ~inner; have_val = 1;
    }
    else if (*s == '(') {
        s++;
        if (!eval_imm_expr(&s, &v, imm0, imm1)) return 0;
        while (*s == ' ' || *s == '\t') s++;
        if (*s != ')') return 0;
        s++;
        have_val = 1;
    }
    else if (*s == 'K') {
        /* bare K (no $) -- we are inside ${...}.
         *  C90: all declarations at top of block. */
        const char *imm;
        int transform, k;
        s++;
        imm = imm0;
        transform = 0;
        k = 0;
        if (s[0] == 'n' && s[1] == 'o' && s[2] == 't') {
            transform = 1; s += 3;
        } else if (s[0] == 'n' && s[1] == 'e' && s[2] == 'g') {
            transform = 2; s += 3;
        } else if (s[0] == 'l' && s[1] == 'o' && s[2] == 'g' && s[3] == '2') {
            transform = 3; s += 4;
        } else if (*s == '1') {
            imm = imm1; s++;
        }
        if (imm == NULL) return 0;
        if (!try_parse_number(imm, &v)) return 0;
        if (transform == 1) v = ~v;
        else if (transform == 2) v = -v;
        else if (transform == 3) {
            if (v <= 0 || (v & (v - 1)) != 0) return 0;
            while (v > 1) { v >>= 1; k++; }
            v = k;
        }
        have_val = 1;
    }
    else if (*s >= '0' && *s <= '9') {
        /* decimal or 0x hex literal */
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            s += 2;
            v = 0;
            if (!isxdigit((unsigned char)*s)) return 0;
            while (isxdigit((unsigned char)*s)) {
                v = v * 16 + hexval(*s); s++;
            }
        } else {
            v = 0;
            while (*s >= '0' && *s <= '9') {
                v = v * 10 + (*s - '0'); s++;
            }
        }
        have_val = 1;
    }
    else return 0;

    if (!have_val) return 0;

    /* parse (OP term)* left-to-right */
    for (;;) {
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == ')' || *s == '}') break;
        /* operator */
        {
            char op = *s++;
            long rhs;
            if (op == '<' && *s == '<') { s++; op = 'L'; }
            else if (op == '>' && *s == '>') { s++; op = 'R'; }
            else if (op != '+' && op != '-' && op != '*' &&
                     op != '/' && op != '%' && op != '&' &&
                     op != '|' && op != '^') return 0;
            while (*s == ' ' || *s == '\t') s++;
            if (!eval_imm_expr(&s, &rhs, imm0, imm1)) return 0;
            switch (op) {
                case '+': v = v + rhs; break;
                case '-': v = v - rhs; break;
                case '*': v = v * rhs; break;
                case '/': if (rhs == 0) return 0; v = v / rhs; break;
                case '%': if (rhs == 0) return 0; v = v % rhs; break;
                case 'L': v = (unsigned long)v << (unsigned long)rhs; break;
                case 'R': v = (unsigned long)v >> (unsigned long)rhs; break;
                case '&': v = v & rhs; break;
                case '|': v = v | rhs; break;
                case '^': v = v ^ rhs; break;
            }
        }
    }
    *out = v;
    *pp = s;
    return 1;
}

/* expand a rewrite template "$a", "$a8", "$a16", "$a32", "$K", "$K1",
 *  "$m0", "$m1", "${expr}" into the bound value, writing into buf.
 *  $m0 / $m1 = full text of operand 1 of pattern inst 0 / 1 (memory).
 *  v2.25 (M4): ${expr} evaluates an arithmetic expression over
 *  immediates ($K, $K1, $Knot, $Kneg, $Klog2) and integer literals
 *  with operators + - * / % << >> & | ^ ~.  Lets table rules emit
 *  folded constants like ${K + K1} for P16-style add/add fusion. */
static char *expand_template(const char *tpl, struct capent *cap,
                             const char *imm0, const char *imm1,
                             const char *mem0, const char *mem1,
                             const char *op0, const char *op1,
                             char *buf, int bufsz)
{
    int ci, n = 0;
    const char *s = tpl;
    const char *imm;
    while (*s != '\0' && n < bufsz - 1) {
        if (*s != '$') { buf[n++] = *s++; continue; }
        s++;   /* skip $ */
        /* v2.25 (M4): ${expr} -- arithmetic expression over immediates.
         *  Evaluates expr via eval_imm_expr and emits the decimal
         *  result.  On parse/eval error the whole template bails
         *  (returns empty buf) and apply_rule refuses to fire. */
        if (*s == '{') {
            long v;
            const char *inner = s + 1;
            if (!eval_imm_expr(&inner, &v, imm0, imm1)) {
                buf[0] = '\0'; return buf;
            }
            while (*inner == ' ' || *inner == '\t') inner++;
            if (*inner != '}') { buf[0] = '\0'; return buf; }
            inner++;
            {
                char num[32];
                int nl = sprintf(num, "%ld", v);
                int j;
                for (j = 0; j < nl && n < bufsz - 1; j++) buf[n++] = num[j];
            }
            s = inner;
            continue;
        }
        if (*s == 'o' && s[1] == 'p' && (s[2] == '0' || s[2] == '1')) {
            const char *op = (s[2] == '0') ? op0 : op1;
            s += 3;
            if (op == NULL) { buf[0] = '\0'; return buf; }
            while (*op != '\0' && n < bufsz - 1) buf[n++] = *op++;
            continue;
        }
        if (*s == 'm' && (s[1] == '0' || s[1] == '1')) {
            const char *mem = (s[1] == '0') ? mem0 : mem1;
            s += 2;
            if (mem == NULL) { buf[0] = '\0'; return buf; }
            while (*mem != '\0' && n < bufsz - 1) buf[n++] = *mem++;
            continue;
        }
        if (*s == 'a' || *s == 'b' || *s == 'c') {
            char capname = *s++;
            int w = 0;
            if (*s >= '0' && *s <= '9') {
                w = (*s - '0') * 10;
                s++;
                if (*s >= '0' && *s <= '9') { w += (*s - '0'); s++; }
            }
            else {
                ci = capname - 'a';
                if (ci >= 0 && ci < NCAP && cap[ci].fam >= 0)
                    w = cap[ci].width;
            }
            if (w == 0) {
                ci = capname - 'a';
                if (ci >= 0 && ci < NCAP) w = cap[ci].width;
            }
            {
                const char *rn = cap_regname(cap, capname, w);
                if (rn == NULL) { buf[0] = '\0'; return buf; }
                /* v2.26: in AT&T mode, register names emitted by $a
                 *  need a leading "%" prefix (e.g. "%eax" not "eax").
                 *  Without this, every table rule that uses $a in its
                 *  template produces invalid AT&T syntax.  The prefix
                 *  is added here so ALL table rules benefit at once. */
                if (g_att && n < bufsz - 1) buf[n++] = '%';
                while (*rn != '\0' && n < bufsz - 1) buf[n++] = *rn++;
            }
        }
        else if (*s == 'K') {
            /* v1.91 template immediates:
             *   $K / $K1     - imm0 / imm1 as written
             *   $Knot        - bitwise NOT of imm0
             *   $Kneg        - negation of imm0
             *   $Klog2       - log2 of imm0 (power of two)
             */
            char fold[32];
            int transform = 0; /* 0=none 1=not 2=neg 3=log2 */
            s++;
            imm = imm0;
            if (s[0] == 'n' && s[1] == 'o' && s[2] == 't') {
                transform = 1; s += 3;
            } else if (s[0] == 'n' && s[1] == 'e' && s[2] == 'g') {
                transform = 2; s += 3;
            } else if (s[0] == 'l' && s[1] == 'o' && s[2] == 'g' && s[3] == '2') {
                transform = 3; s += 4;
            } else if (*s == '1') {
                imm = imm1; s++;
            }
            if (imm == NULL) { buf[0] = '\0'; return buf; }
            if (transform) {
                long v;
                if (!try_parse_number(imm, &v)) { buf[0] = '\0'; return buf; }
                if (transform == 1) v = ~v;
                else if (transform == 2) v = -v;
                else {
                    int k = 0;
                    if (v <= 0 || (v & (v - 1)) != 0) { buf[0] = '\0'; return buf; }
                    while (v > 1) { v >>= 1; k++; }
                    v = k;
                }
                sprintf(fold, "%ld", v);
                imm = fold;
            }
            while (*imm != '\0' && n < bufsz - 1) buf[n++] = *imm++;
        }
        else {
            /* literal $ followed by something else -- keep $ */
            buf[n++] = '$';
        }
    }
    buf[n] = '\0';
    return buf + n;
}

/* apply a rule's actions.  Returns 1 if anything changed. */
static int apply_rule(long i, long j2, const struct rule *r,
                      struct capent *cap,
                      const char *imm0, const char *imm1,
                      const char *mem0, const char *mem1,
                      const char *op0, const char *op1)
{
    int k;
    long idx[4];
    struct pinfo *parr[4];
    long j3 = -1, j4 = -1;
    idx[0] = i;
    parr[0] = &g_pcur;
    idx[1] = -1; parr[1] = NULL;
    idx[2] = -1; parr[2] = NULL;
    idx[3] = -1; parr[3] = NULL;
    if (r->n >= 2) {
        idx[1] = j2;
        parr[1] = &g_ppair;
    }
    if (r->n >= 3) {
        j3 = next_code(j2);
        idx[2] = j3;
        parr[2] = &g_pnext;
    }
    if (r->n >= 4) {
        j4 = next_code(j3);
        idx[3] = j4;
        parr[3] = &g_plook;
    }
    for (k = 0; k < r->n; k++) {
        const struct op_act *a = &r->act[k];
        if (a->kind == ACT_KEEP) continue;
        if (a->kind == ACT_DEL) {
            delete_keep_label_marked(idx[k], parr[k], r->desc, r->rule_no);
        }
        else if (a->kind == ACT_REW) {
            char body[MAXLINE];
            char full[MAXLINE + 64];
            int n;
            expand_template(a->text, cap, imm0, imm1, mem0, mem1, op0, op1, body, sizeof(body));
            if (body[0] == '\0') return 0;
            /* preserve the original line's prefix (label + indent) */
            n = (int)strlen(parr[k]->prefix);
            if (n > (int)sizeof(full) - 1) n = (int)sizeof(full) - 1;
            memcpy(full, parr[k]->prefix, (size_t)n);
            full[n] = '\0';
            strcat(full, body);
            replace_line_marked(idx[k], full, r->desc, r->rule_no);
        }
    }
    return 1;
}

/* try every table rule on the current line i.  Returns 1 if a rule
 *  fired (and st[rule_no] was incremented), 0 otherwise. */




/* True if s is a pure stack-frame memory operand based only on BP/EBP/RBP
 *  with optional signed displacement: [bp], [bp+4], [ebp-8], [rbp+16],
 *  word ptr [bp+2], dword ptr [ebp-4], etc.  Rejects SI/DI/BX bases and
 *  absolute or symbolic addresses -- those may be MMIO or aliased. */
static int is_stack_mem_operand(const char *s)
{
    const char *p;
    int have_base = 0;
    if (s == NULL || *s == '\0') return 0;
    /* skip optional size ptr prefix: byte/word/dword/qword ptr */
    p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (ci_eq_n(p, "byte", 4) || ci_eq_n(p, "word", 4) ||
        ci_eq_n(p, "dword", 5) || ci_eq_n(p, "qword", 5)) {
        while (*p && *p != ' ' && *p != '\t') p++;
        while (*p == ' ' || *p == '\t') p++;
        if (ci_eq_n(p, "ptr", 3)) {
            p += 3;
            while (*p == ' ' || *p == '\t') p++;
        }
    }
    if (*p != '[') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    /* base must be bp / ebp / rbp only */
    if (ci_eq_n(p, "rbp", 3) && !is_ident_char((unsigned char)p[3])) {
        p += 3; have_base = 1;
    } else if (ci_eq_n(p, "ebp", 3) && !is_ident_char((unsigned char)p[3])) {
        p += 3; have_base = 1;
    } else if (ci_eq_n(p, "bp", 2) && !is_ident_char((unsigned char)p[2])) {
        p += 2; have_base = 1;
    }
    if (!have_base) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == ']') return 1;
    if (*p != '+' && *p != '-') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    /* displacement: decimal or hex number only */
    if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        if (!isxdigit((unsigned char)*p)) return 0;
        while (isxdigit((unsigned char)*p)) p++;
    } else {
        if (!isdigit((unsigned char)*p)) return 0;
        while (isdigit((unsigned char)*p)) p++;
    }
    while (*p == ' ' || *p == '\t') p++;
    return (*p == ']');
}

static int try_table_rules(long i)
{
    struct pinfo *pi = &g_pcur;
    struct pinfo *pj = &g_ppair;
    int ri;
    long j2 = -1;
    static char imm0_buf[MAXTOK], imm1_buf[MAXTOK];
    const char *imm0 = NULL, *imm1 = NULL;

    /* v1.85: a bespoke C rule may have already deleted this line in
     *  the same pass (P8/P18 do DEL(i)=1 without continue).  Bail. */
    if (DEL(i)) return 0;
    if (pi->haslabel || pi->toobig || !pi->hasinstr) return 0;
    if (g_nrules == 0) return 0;

    for (ri = 0; ri < g_nrules; ri++) {
        const struct rule *r = &g_rules[ri];
        struct capent cap[NCAP];
        int k;
        long j3 = -1, j4 = -1;
        long last_idx;   /* v2.26 (3.1): last pattern inst, for pre_check */
        for (k = 0; k < NCAP; k++) { cap[k].fam = -1; cap[k].width = 0; cap[k].lo = 0; }
        if (!pat_match_inst(pi, r, 0, cap)) continue;
        if (r->n >= 2) {
            j2 = next_code(i);
            if (j2 < 0 || INDEF(j2)) continue;
            parse_line(j2, pj);
            if (pj->haslabel || pj->toobig || !pj->hasinstr) continue;
            if (!pat_match_inst(pj, r, 1, cap)) continue;
        }
        if (r->n >= 3) {
            j3 = next_code(j2);
            if (j3 < 0 || INDEF(j3)) continue;
            parse_line(j3, &g_pnext);
            if (g_pnext.haslabel || g_pnext.toobig || !g_pnext.hasinstr) continue;
            if (!pat_match_inst(&g_pnext, r, 2, cap)) continue;
        }
        if (r->n >= 4) {
            if (j3 < 0) j3 = next_code(j2);
            j4 = next_code(j3);
            if (j4 < 0 || INDEF(j4)) continue;
            parse_line(j4, &g_plook);
            if (g_plook.haslabel || g_plook.toobig || !g_plook.hasinstr) continue;
            if (!pat_match_inst(&g_plook, r, 3, cap)) continue;
        }
        /* v2.26 (3.1): compute the LAST instruction index so pre_check
         *  scans dead flags / dead regs from AFTER the whole pattern,
         *  not from after inst1 of a 3-op pattern.  The previous code
         *  passed j2 (or i), which for a 3-op rule was inst1 -- the
         *  dead-flag scan then started at inst2 and missed any flag
         *  reader between inst1 and inst2.  No current rule exercised
         *  this (P430 has pre=0), but it was a latent footgun. */
        last_idx = i;
        if (r->n >= 2) last_idx = j2;
        if (r->n >= 3) last_idx = j3;
        if (r->n >= 4) last_idx = j4;
        /* capture immediates for the rewrite template */
        if (pi->nops >= 2) {
            long v;
            if (try_parse_number(pi->op1, &v) || is_offset_expr(pi->op1)) {
                strncpy(imm0_buf, pi->op1, sizeof(imm0_buf)-1);
                imm0_buf[sizeof(imm0_buf)-1] = '\0';
                imm0 = imm0_buf;
            }
        }
        if (r->n >= 2 && pj->nops >= 2) {
            long v;
            if (try_parse_number(pj->op1, &v) || is_offset_expr(pj->op1)) {
                strncpy(imm1_buf, pj->op1, sizeof(imm1_buf)-1);
                imm1_buf[sizeof(imm1_buf)-1] = '\0';
                imm1 = imm1_buf;
            }
        }
        if (!pre_check(r->pre, r->pre_dead_caps, last_idx, cap)) continue;
        if (r->check != NULL && !r->check(cap, i, j2)) continue;
        /* fire */
        vlog("smartpp: line %ld: rule P%d fired (%s)\n",
                i + 1, r->rule_no, r->desc);
        {
            const char *mem0 = (g_pcur.op1[0] != '\0') ? g_pcur.op1 : NULL;
            const char *mem1 = NULL;
            const char *op0 = g_pcur.mnem;
            const char *op1 = (r->n >= 2) ? g_ppair.mnem : NULL;
            if (r->n >= 2 && g_ppair.op1[0] != '\0') mem1 = g_ppair.op1;
            if (mem0 == NULL && g_pcur.op0[0] != '\0') mem0 = g_pcur.op0;
            apply_rule(i, j2, r, cap, imm0, imm1, mem0, mem1, op0, op1);
        }
        if (r->rule_no > 0 && r->rule_no < STSZ) st[r->rule_no]++;
        return 1;
    }
    return 0;
}

/* ===========================================================================
 *  THE RULE TABLE
 *  =========================================================================
 *  Declarative rules.  These run AFTER the bespoke C rules in run_pass;
 *  they only fire on inputs the C rules did not catch.  This keeps the
 *  v1.84 behavior identical for every existing rule and lets the table
 *  absorb new optimizations without touching run_pass's body.
 *
 *  Each rule is a struct rule.  See the engine comment above for the
 *  full pattern/pre/action vocabulary.  Quick reference:
 *
 *    Operand patterns:
 *      OP_REG     {cap, rclass}  register of class, bind capture
 *      OP_REGCLASS{rclass}       register of class, no capture
 *      OP_SAME    {same_cap}     must equal a previous capture's family
 *      OP_IMM     {}             immediate (number or OFFSET expr)
 *      OP_MEM     {}             memory (not reg, not imm)
 *      OP_ANY     {}             don't care
 *
 *    Register classes: RC_ANY / RC_8 / RC_16 / RC_32
 *
 *    Preconditions (bit OR):
 *      PRE_FLAGS_DEAD_ALL   PRE_FLAGS_DEAD_CF    PRE_FLAGS_DEAD_AF
 *      PRE_REG_DEAD_RA      PRE_REG_DEAD_B       PRE_NO_CPU_8086
 *      PRE_CPU_386          PRE_CPU_486          PRE_NO_USE32
 *      PRE_INTEL            PRE_NEXT_IS_JCC      PRE_NEXT_JCC_NO_CF
 *      PRE_STACK_MEM_0/1    pure [bp/ebp/rbp±N] operand on inst0/1
 *      PRE_NEXT_JCC_ZF_ONLY PRE_SRC_IMM          PRE_NOT_SP
 *
 *    Actions per pattern instruction:
 *      ACT_KEEP / ACT_DEL / ACT_REW "text"
 *
 *    Rewrite template tokens:
 *      $a/$b/$c       capture's register name at bound width
 *      $a8/$a16/$a32  capture's register name at forced width
 *      $K             immediate of inst 0
 *      $K1            immediate of inst 1
 *
 *  Example (P9 mov R,0 -> xor R,R, flags dead):
 *
 *    { 1, 9,
 *      { { "mov", 0, { OP_REG, RC_ANY,'a' }, { OP_IMM, 0,0 }, 2 } },
 *      PRE_FLAGS_DEAD_ALL,
 *      { { ACT_REW, "xor $a, $a" } },
 *      "mov R,0 -> xor R,R" },
 *
 *  Note: the C rules for P9 etc. are KEPT for now (they handle the
 *  bespoke "srcimm == 1" parsing path); the table versions below are
 *  the NEW v1.85 rules plus a few table-native siblings that the C
 *  pass does not have.  Removing a C rule and re-expressing it here is
 *  a one-line edit (delete the C block, the table rule already covers
 *  the input).  We start conservative.
 * ======================================================================== */

/* helper macros so the table reads like its description.
 *  Each produces an op_pat with all fields initialized, including the
 *  v1.85 imm_val/imm_has extension.  Pre-1.85 macros zero-init those
 *  fields so existing rules behave unchanged. */
#define R_(capname, cls)   { OP_REG,    cls, capname, 0, 0, 0 }
#define RR_(capname)        { OP_REG,    RC_ANY, capname, 0, 0, 0 }
#define IM_                 { OP_IMM,    0, 0, 0, 0, 0 }
#define ME_                 { OP_MEM,    0, 0, 0, 0, 0 }
#define AN_                 { OP_ANY,    0, 0, 0, 0, 0 }
#define SM_(c)               { OP_SAME,   0, 0, c, 0, 0 }
#define DF_(c)               { OP_DIFF,   0, 0, c, 0, 0 }  /* v1.91: other reg */
#define PW2_                 { OP_IMM_POW2, 0, 0, 0, 0, 0 } /* v1.91: 2^k, k>=1 */
#define RC_(cls)             { OP_REGCLASS, cls, 0, 0, 0, 0 }
#define IV_(v)               { OP_IMMVAL, 0, 0, 0, (v), 1 }
/* v2.25 (M8): same-family relation macros.  Each compares the
 *  operand against the named capture using the corresponding
 *  reg_relation() mode.  Optional width class still applies on top. */
#define SFAM_(c)             { OP_SAME_FAM,      0, 0, c, 0, 0 }
#define SWID_(c)             { OP_SAME_WIDTH,    0, 0, c, 0, 0 }
#define CLO_(c)              { OP_COMPLEMENT_LO, 0, 0, c, 0, 0 }

/* v2.25 (M6): dead-capture bitmask value for `rule.pre_dead_caps`.
 *  Each capture letter 'a'..'z' gets one bit.  Set in the table
 *  initializer as `.pre_dead_caps = DEAD_CAP_('c') | DEAD_CAP_('d')`
 *  or, for a single capture, just DEAD_CAP_('c').  Existing rules
 *  that already use PRE_REG_DEAD_RA / PRE_REG_DEAD_B don't need this
 *  -- those two bits in `pre` are still honored for backwards
 *  compat.  pre_dead_caps is the generalization to 'c'..'z'. */
#define DEAD_CAP_(c)         (1u << ((c) - 'a'))

/* v2.25 (M5): immediate-in-range.  Matches if the operand parses as
 *  a number and lo <= v <= hi (both inclusive, signed comparison).
 *  Use for shift counts, imm8 bounds, and similar range gates. */
#define IMR_(lo, hi)         { OP_IMM_RANGE, 0, 0, 0, (lo), 1, (hi) }

/* v2.17: P323/P324 check -- "lea R,[R+R]" (the [SIB base=index] form)
 *  needs the SIB byte (386+) AND a 32-bit or 64-bit register.  In
 *  16-bit addressing only BX/BP/SI/DI are legal base/index AND the
 *  same register cannot be both base and index, so "lea ax,[ax+ax]"
 *  is an assembler error (A2031 "must be index or base register")
 *  on every pre-386 build.  The old rule fired on any width and
 *  broke 4VIEW's 8086/386 real-mode code (five "lea ax,[ax+ax]"
 *  sites in StatLoad, PopUp, DrwSt).  This check keeps the rewrite
 *  to 386+ with EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI (and RAX..RDI on
 *  x64); 8/16-bit registers keep "shl R,1" intact. */
static int p323_lea_rr_check(const struct capent *cap, long i, long j2)
{
    int ci = 'a' - 'a';
    (void)i; (void)j2;
    if (opt_zopt) return 0;                 /* -Oz: shl R,1 is 2 bytes, lea is 3 */
    if (g_curcpu < 8) return 0;            /* SIB needs the 386 */
    if (ci < 0 || ci >= NCAP) return 0;
    if (cap[ci].fam < 0) return 0;
    if (cap[ci].width == 32) return 1;
    if (cap[ci].width == 64 && g_curcpu >= 128) return 1;  /* x64 */
    return 0;
}

/* v2.24: P430 check -- "or R,c1 / and R,c2 / or R,c3" 3-op chain.
 *  Delete inst0 (the first OR) when (c1 & c2) & ~c3 == 0, i.e.
 *  c1 & c2 ⊆ c3.  Original value: ((R | c1) & c2) | c3 =
 *  (R & c2) | (c1 & c2) | c3.  Without OR1: (R & c2) | c3.
 *  The diff is (c1 & c2) & ~c3 -- bits OR1 sets, AND keeps, OR3
 *  doesn't set -- which must be empty for the rewrite to be exact
 *  for every R.  Research: Open Watcom peepopt.c AndOr/OrAnd family
 *  extended to the 3-op chain (Watcom only handled 2-op pairs).
 *
 *  No flag scan is needed: inst0 (the deleted OR) is immediately
 *  followed by inst1 (the AND), which defines all six status flags
 *  before reading any of them, so the OR's flags die at the AND.
 *  The matcher guarantees label-free adjacency, so no reader can
 *  sit between them.  Reuses the global pinfo slots the matcher
 *  already filled (g_pcur=inst0, g_ppair=inst1, g_pnext=inst2);
 *  because pre=0, pre_check does not touch g_pnext before us. */
static int p430_or_and_or_check(const struct capent *cap, long i, long j2)
{
    long c1, c2, c3;
    int r_idx, w;
    unsigned long masku, mc1, mc2, mc3;
    (void)i; (void)j2;
    if (cap == NULL) return 0;
    /* All three operands must parse as plain numbers.  Any
     *  symbolic immediate (EQU constant, OFFSET expr) refuses to
     *  fire -- the mask analysis is on concrete bits. */
    if (!try_parse_number(g_pcur.op1,  &c1)) return 0;
    if (!try_parse_number(g_ppair.op1, &c2)) return 0;
    if (!try_parse_number(g_pnext.op1, &c3)) return 0;
    /* Mask each constant to the destination register's width so
     *  that "or al, -1" (c1=-1 -> 0xFF after the 8-bit mask) and
     *  "or al, 0FFh" (c1=255 -> 0xFF) are treated identically.
     *  g_pcur.op0 is the captured register R, which the matcher
     *  has already bound to cap['a']; we re-resolve it via find_reg
     *  to derive the width without poking cap['a']. */
    r_idx = find_reg(g_pcur.op0);
    if (r_idx < 0) return 0;
    w = g_regs[r_idx].hi - g_regs[r_idx].lo;
    masku = width_mask(w);
    mc1 = (unsigned long)c1 & masku;
    mc2 = (unsigned long)c2 & masku;
    mc3 = (unsigned long)c3 & masku;
    /* Soundness gate: every bit the first OR forces to 1 that the
     *  AND keeps must be re-forced by the last OR; otherwise the
     *  first OR is the only thing guaranteeing that bit and cannot
     *  be deleted.  (c1 & c2) & ~c3 == 0. */
    return ((mc1 & mc2) & ~mc3) == 0UL;
}

/* v2.24: P431 check -- "mov R8lo, 0 / mov R8hi, 0 -> xor R16, R16"
 *  where R8lo and R8hi are the low and high bytes of the SAME 8-bit
 *  register family.  v2.25 (M8) replaced this function with the
 *  table-native OP_COMPLEMENT_LO (CLO_('a')) pattern kind.  The body
 *  was deleted in v2.26 (cleanup of audit finding 4.1).  See the
 *  P431 table entry for the declarative form. */

/* v2.24: P432 check -- "movzx R, src / test R, R -> test src, src"
 *  with R provably dead after the test AND SF provably dead from the
 *  test onward.  v2.25 (M1) replaced this function with the
 *  PRE_FLAGS_DEAD_SF precondition bit.  The body was deleted in v2.26
 *  (cleanup of audit finding 4.2).  See the P432 table entry. */

/* v2.25 (M4+M5): shared check for the constant-fold rules P433/P434.
 *  Verifies that c1 OP c2 (OP = + for P433, - for P434) fits in the
 *  destination register's signed immediate encoding range, so the
 *  folded replacement "add/sub R, sum" can be encoded.  Uses
 *  width_imm_limit() for the bound. */
static int p433_fold_range_check(const struct capent *cap,
                                 long i, long j2, int is_sub)
{
    long c1, c2, sum;
    int ridx, w;
    long limit;
    (void)i; (void)j2;
    if (cap == NULL) return 0;
    if (!try_parse_number(g_pcur.op1,  &c1)) return 0;
    if (!try_parse_number(g_ppair.op1, &c2)) return 0;
    sum = is_sub ? (c1 - c2) : (c1 + c2);
    ridx = cap_to_regidx(&cap['a' - 'a']);
    if (ridx < 0) return 0;
    w = g_regs[ridx].hi - g_regs[ridx].lo;
    limit = width_imm_limit(w);
    return sum >= -limit && sum <= limit;
}

/* P433 check: add R,c1 / add R,c2 -> add R,c1+c2 (sum fits). */
static int p433_add_fold_check(const struct capent *cap, long i, long j2)
{
    return p433_fold_range_check(cap, i, j2, 0);
}

/* P434 check: sub R,c1 / sub R,c2 -> sub R,c1+c2 (sum fits). */
static int p434_sub_fold_check(const struct capent *cap, long i, long j2)
{
    return p433_fold_range_check(cap, i, j2, 0);  /* sub+sub is also c1+c2 */
}

/* P435 check: sub R,c1 / add R,c2 -> sub R, c1-c2 (net sub). */
static int p435_sub_add_fold_check(const struct capent *cap, long i, long j2)
{
    return p433_fold_range_check(cap, i, j2, 1);  /* c1 - c2 */
}

/* v2.26: P40 check -- "mov R, imm1 / {add|sub} R, imm2 -> mov R, imm1±imm2"
 *  Verifies the folded total fits the dest register's signed imm
 *  encoding range (imm8/imm16/imm32).  Uses width_imm_limit() for
 *  the upper bound; lower bound is -(lim+1) (e.g. -128 for imm8).
 *  is_sub selects between imm1+imm2 (add) and imm1-imm2 (sub). */
static int p40_mov_add_fold_check(const struct capent *cap, long i, long j2)
{
    long v1, v2, total;
    int ridx, w;
    long lim;
    (void)i; (void)j2;
    if (cap == NULL) return 0;
    if (!try_parse_number(g_pcur.op1,  &v1)) return 0;
    if (!try_parse_number(g_ppair.op1, &v2)) return 0;
    /* g_ppair.mnem is "add" or "sub" -- the table has separate entries
     *  for each, so we can tell from the mnemonic which sign to use. */
    total = ci_eq(g_ppair.mnem, "sub") ? (v1 - v2) : (v1 + v2);
    ridx = cap_to_regidx(&cap['a' - 'a']);
    if (ridx < 0) return 0;
    w = g_regs[ridx].hi - g_regs[ridx].lo;
    lim = width_imm_limit(w);
    return total <= lim && total >= -(lim + 1);
}

static const struct rule g_rule_tbl[] = {

    /* P1 (v2.14, RESTORED): "mov R, R" -> delete.  The v1.85.1
     *  cleanup removed the old P106/P107 table rules as "caught by
     *  P1", but P1 itself was never present in this table (the C
     *  comment in run_pass points here), so same-register mov/xchg
     *  silently stopped being deleted.  OP_SAME compares family AND
     *  width (v1.85.1), so "mov eax, ax" (a zero-extension) still
     *  never matches.  mov touches no flags; the deletion is exact. */
    { 1, 1,
      { { "mov", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "mov R,R -> delete", NULL },

    /* P1 (xchg form): "xchg R, R" -> delete.  Same-register xchg is a
     *  no-op on R, on flags (xchg sets none), and on memory; "xchg
     *  eax, eax" is the canonical 1-byte NOP (0x90).  Absorbs the old
     *  P126, which was otherwise unreachable behind this rule. */
    { 1, 1,
      { { "xchg", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "xchg R,R -> delete", NULL },

    /* P105 (v2.14, REMOVED): "sub R,R -> xor R,R" table rule deleted.
     *  It was unreachable: the C rule P71 fires first with the exact
     *  same conditions (AF dead, not SP).  See rname[105]. */

    /* P111 (v1.85, REMOVED v2.26): "or R, 0" -> delete was shadowed
     *  by the C rule P8, which fires first with `continue` on every
     *  `or R,0` and `or R,R` (audit finding 2.1).  The table entry
     *  was unreachable on its only pattern.  rname[111] kept as doc. */

    /* P112 (v1.85, REMOVED v2.26): "and R, -1" -> delete was shadowed
     *  by the C rule P8 (audit finding 2.2).  P8 line ~8750 matches
     *  both `v8 == -1L` and the unsigned 0FFFFh/0FFFFFFFFh forms,
     *  covering every input P112 could match.  rname[112] kept as
     *  doc.  The unsigned all-ones AND for 8/16-bit (`and al, 0FFh`
     *  / `and ax, 0FFFFh`) is handled by C P8 only; no table rule
     *  covers it, which is acceptable since P8 catches all forms. */

    /* P115 (v1.85): "xor R, 0" -> delete (no-op on R, sets flags).
     *  Requires flags dead.  No C rule covers this case. */
    { 1, 115,
      { { "xor", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "xor R,0 -> delete (flags dead)", NULL },

    /* P119 (v1.85): "test R, K" -> delete when flags dead.  test never
     *  writes R, so deleting it is sound as long as no reader of its
     *  flags follows.  No C rule covers test deletion (P11 only
     *  converts cmp R,0 -> test R,R; it does not delete test). */
    { 1, 119,
      { { "test", 0, RR_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "test R,K -> delete (flags dead)", NULL },

    /* P120 (v1.85): "cmp R, K" -> delete when flags dead.  cmp never
     *  writes R; the only observable effect is flags, which the
     *  precondition proves dead.  Conservative and sound.  Note:
     *  P11 fires first on "cmp R, 0" (rewriting to test R,R); this
     *  rule catches the general "cmp R, K" with K != 0 that P11
     *  leaves alone. */
    { 1, 120,
      { { "cmp", 0, RR_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "cmp R,K -> delete (flags dead)", NULL },

    /* ---- v1.86 NEW RULES (research: Agner Fog, Abrash, GCC i386.md) ----
     *  See the v1.86 changelog block above for the full safety analysis
     *  and per-CPU cycle savings. */

    /* P122 (v1.86): "imul R, 1" -> delete.  R*1 == R (identity); the
     *  only side effect is CF/OF (set per the high-half rule), which
     *  the precondition proves dead.  186+ (the imm-form imul).
     *  Cycle win: huge on pre-Pentium (9-22 cycles for imul-by-imm);
     *  ~10 on P5/P6.  Distinct from P38 (imul 2^k->shl, where 2^0=1
     *  already deletes the imul), P50 (2^k+1->lea), P51 (-1->neg) --
     *  none cover imul-by-1 with a flag-dead scan that the table makes
     *  explicit.  In practice P38 fires first on imul R,1 because
     *  log2(1)==0 is recognized; P122 is the table-native fallback
     *  that documents the rule.
     *  Research: Agner Fog instruction_tables (IMUL latencies); Intel
     *  SDM Vol.2 IMUL; Abrash Black Book. */
    /* P122 (v2.14, REMOVED): "imul R,1 -> delete" table rule deleted.
     *  The C rule P38 now folds the K == 1 identity itself (its old
     *  v==1 branch was unreachable behind the power-of-two branch;
     *  fixed in v2.14), so this entry never fired.  See rname[122]. */

    /* P123 (v1.86): "imul R, 0" -> "xor R, R".  R*0 == 0, and xor is
     *  the canonical zeroing idiom (breaks the dependency chain on
     *  PPro via partial-register rename).  Requires flags dead (imul
     *  and xor both set flags, but to different values: xor forces
     *  CF=OF=0, imul's CF reflects the high half of the product -- so
     *  the flag stream differs and we must prove no reader).  186+.
     *  Cycle win: huge (imul 9-22 vs xor 1); plus the dep-break on P6.
     *  Research: Agner Fog "zeroing idiom"; Intel optimization guide. */
    { 1, 123,
      { { "imul", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NO_CPU_8086,
      { { ACT_REW, "xor $a, $a" } },
      "imul R,0 -> xor R,R (flags dead)", NULL },

    /* P126 (v2.14, REMOVED): "xchg R,R -> delete" table rule deleted.
     *  The restored P1 xchg entry (top of this table) fires first with
     *  identical conditions, so this entry never fired.
     *  See rname[126]. */

    /* P127 (v1.86): "bswap R / bswap R" -> delete the second.  bswap
     *  is an involution: bswap(bswap(x)) == x.  The second bswap is a
     *  no-op on R (and bswap sets no flags).  486+ (bswap is a 486
     *  instruction).  Cycle win: 1 on 486/P5/P6 (bswap is 1 cycle).
     *  Research: Agner Fog instruction_tables (BSWAP); Intel SDM Vol.2.
     *  Distinct from P87 (rol16/xchg/rol16 -> bswap, which CREATES a
     *  bswap); this rule removes a redundant double-bswap. */
    { 2, 127,
      { { "bswap", 0, RR_('a'), AN_, 1 },
        { "bswap", 0, SM_('a'), AN_, 1 } },
      PRE_CPU_486,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "bswap R / bswap R -> bswap R", NULL },

    /* P128 (v1.86): "xor R, R / push R" -> "push 0".  The xor clears
     *  R to 0; pushing R pushes 0; pushing the immediate 0 has the
     *  identical effect on the stack.  R must be dead after the push
     *  (no further read).  186+ (push imm).  Cycle win: 1 cycle on
     *  486 (xor 1 + push 1 = 2 -> push imm 1); 1 byte saved on 286+.
     *  Distinct from P79 (mov R,imm / push R -> push imm) which does
     *  not cover the xor-clearing variant.  Note: the xor sets flags
     *  but push does not read them, so the flag-liveness precondition
     *  is not needed -- the xor's flags simply die with no reader.
     *  Research: GCC i386.md *push<mode>_1 (push imm preferred);
     *  Agner Fog. */
    { 2, 128,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "push", 0, SM_('a'), AN_, 1 } },
      PRE_REG_DEAD_RA | PRE_NO_CPU_8086,
      { { ACT_DEL, NULL }, { ACT_REW, "push 0" } },
      "xor R,R / push R -> push 0", NULL },

    /* ---- v1.87 NEW RULES: x87 FPU + x64 long mode ---- */

    /* P129 (v1.87): "fld st / fstp st" -> delete both.  Loads the top
     *  of the x87 stack and immediately pops it back off -- net effect
     *  on the stack is zero (push + pop), net effect on memory is zero
     *  (read + write same address).  Conservative: requires PRE_FPU
     *  so .NO87 turns it off.  We catch only the trivial st-st(0) pair
     *  -- a fld/fstp to st(N) cannot be folded without a full stack
     *  analysis (the value at st(N) may be read later).
     *  Research: Intel SDM Vol.2 FLD/FSTP; Agner Fog x87 latency. */
    { 2, 129,
      { { "fld",  0, RR_('a'), AN_, 1 },
        { "fstp", 0, SM_('a'), AN_, 1 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fld st / fstp st -> delete (push/pop)", NULL },

    /* P130 (v1.87): "fldz / fstp st" -> delete both.  Pushing zero and
     *  popping it immediately is a no-op on the stack (the pop
     *  discards the zero we just pushed).  PRE_FPU required. */
    { 2, 130,
      { { "fldz", 0, AN_, AN_, 0 },
        { "fstp", 0, RR_('a'), AN_, 1 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fldz / fstp st -> delete (push 0/pop)", NULL },

    /* P131 (v1.87): "fchs / fchs" -> delete both.  Negating the top of
     *  stack twice is a no-op (double negation).  fchs leaves the
     *  stack depth unchanged and sets no EFLAGS.  PRE_FPU required. */
    { 2, 131,
      { { "fchs", 0, AN_, AN_, 0 },
        { "fchs", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fchs / fchs -> delete (double negation)", NULL },

    /* P132 (v1.87): "fabs / fabs" -> delete the second.  abs is
     *  idempotent: abs(abs(x)) == abs(x).  The second fabs is a
     *  no-op on the top of stack.  PRE_FPU required. */
    { 2, 132,
      { { "fabs", 0, AN_, AN_, 0 },
        { "fabs", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fabs / fabs -> fabs (idempotent)", NULL },

    /* P133 (v1.87): "fsqrt / fsqrt" -> delete the second.  sqrt is
     *  idempotent on non-negative inputs (sqrt(sqrt(x)) != sqrt(x) in
     *  general, but sqrt applied twice to the same value yields the
     *  same as sqrt applied once IF the second sqrt's input is the
     *  first sqrt's output -- and that's exactly what consecutive
     *  fsqrt does).  However, this is NOT actually safe because the
     *  second fsqrt's result differs from the first (sqrt(sqrt(x))
     *  != sqrt(x) for x > 1).  WITHDRAWN before release -- left as a
     *  documentation entry.  Use ACT_KEEP on both to be safe. */
    /* (withdrawn -- not actually idempotent; kept here as documentation
     *  of the considered-and-rejected case) */

    /* P134 (v1.87): "ffree st / ffree st" -> delete the second.
     *  ffree marks a stack register as empty; doing it twice on the
     *  same slot is a no-op the second time.  PRE_FPU required. */
    { 2, 134,
      { { "ffree", 0, RR_('a'), AN_, 1 },
        { "ffree", 0, SM_('a'), AN_, 1 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "ffree st / ffree st -> ffree st", NULL },

    /* P135 (v1.87): "fninit / fninit" -> delete the second.  fninit
     *  resets the FPU to a known state; initializing twice in a row
     *  is a no-op the second time (idempotent).  PRE_FPU required. */
    { 2, 135,
      { { "fninit", 0, AN_, AN_, 0 },
        { "fninit", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fninit / fninit -> fninit", NULL },

    /* P136 (v1.87): "fwait / fwait" -> delete the second.  fwait is
     *  a CPU/FPU synchronization hint; two in a row collapse to one.
     *  PRE_FPU required. */
    { 2, 136,
      { { "fwait", 0, AN_, AN_, 0 },
        { "fwait", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fwait / fwait -> fwait", NULL },

    /* P137 (v1.87): "fxch st / fxch st" -> delete both.  Swapping the
     *  top of stack with itself is a no-op (xchg x,x).  PRE_FPU.
     *  Note: "fxch" with no operands swaps st(0) and st(1) -- this
     *  rule only fires when both operands are present and equal,
     *  which is the "fxch st, st" (== fxch st(0), st(0)) form. */

    /* P205: fnop / fnop -> delete second. */
    { 2, 205,
      { { "fnop", 0, AN_, AN_, 0 },
        { "fnop", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fnop / fnop -> fnop", NULL },

    /* P206: fld1 / fmulp st(1),st -> delete both if pure *1 on stack top
     *  pair fld1+fmulp: st1*=st0(=1), pop -> st1 unchanged. Net no-op.
     *  Only the classic no-operand fmulp form. */
    { 2, 206,
      { { "fld1", 0, AN_, AN_, 0 },
        { "fmulp", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fld1 / fmulp -> delete (*1 no-op)", NULL },

    /* P207: fld1 / faddp -> not a no-op (+1). skip.
     *  fldz / faddp: +0 is no-op for most, but -0/rounding: skip. */

    /* P208: fdecstp / fincstp -> delete both (inverse stack moves). */
    { 2, 208,
      { { "fdecstp", 0, AN_, AN_, 0 },
        { "fincstp", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fdecstp / fincstp -> delete", NULL },

    /* P209: fincstp / fdecstp -> delete both. */
    { 2, 209,
      { { "fincstp", 0, AN_, AN_, 0 },
        { "fdecstp", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fincstp / fdecstp -> delete", NULL },

    /* P210: finit / finit -> finit (same as fninit pair). */
    { 2, 210,
      { { "finit", 0, AN_, AN_, 0 },
        { "finit", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "finit / finit -> finit", NULL },

    /* P211: x64 - cdqe / cdqe -> cdqe (sign-extend EAX->RAX idempotent
     *  on second application only if already extended; second is redundant
     *  if no write to EAX/RAX between -- adjacent => safe). */
    { 2, 211,
      { { "cdqe", 0, AN_, AN_, 0 },
        { "cdqe", 0, AN_, AN_, 0 } },
      PRE_CPU_X64,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cdqe / cdqe -> cdqe", NULL },

    /* P212: cqo / cqo -> cqo (sign-extend RAX into RDX:RAX). */
    { 2, 212,
      { { "cqo", 0, AN_, AN_, 0 },
        { "cqo", 0, AN_, AN_, 0 } },
      PRE_CPU_X64,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cqo / cqo -> cqo", NULL },

    /* P213: cltq is AT&T cdqe; handle as cdqe synonym in Intel we use cdqe.
     *  cwd / cwd already P28. */

    /* P214: movsx R64, R32 same reg family low - often written after
     *  32-bit op that already zero/sign cleared - skip without proof. */

    /* P215: and R, R with flags dead is P147. or R,0 delete P111.
     *  x64: "shl rax, 0" delete via P146. */

    /* P216: test R,R / test R,R -> delete second (P150). already. */

    /* P217: not R / not R -> delete (P23). already. */

    /* P218: fld st(0) written as "fld st" / fst st -> store without pop
     *  then ... harder. */

    /* P219: faddp / when preceded by fldz - skip (IEEE -0). */

    /* P220: xchg R,R already P126. */

    /* P221: rep nop / pause pairs - skip (sync). */

    /* P222: mov R, R64 with eax form: covered by width-aware P1. */

    /* P223: lea R, [R*1] -> delete or mov - scale 1 with no base rare. */

    /* P224: sub R, R / jz L is zero test - leave. */

    /* P225: or R, R is test-like for TP; flags same as test if only ZF/SF/PF
     *  needed - already used as test substitute. */

    /* P226 (v2.22 REMOVED): shadowed by C rule P3. */

    /* P227: pushfd / popfd (386+) */
    { 2, 227,
      { { "pushfd", 0, AN_, AN_, 0 },
        { "popfd",  0, AN_, AN_, 0 } },
      PRE_CPU_386,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "pushfd / popfd -> delete both", NULL },

    /* P228: pushfq / popfq (x64) */
    { 2, 228,
      { { "pushfq", 0, AN_, AN_, 0 },
        { "popfq",  0, AN_, AN_, 0 } },
      PRE_CPU_X64,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "pushfq / popfq -> delete both", NULL },

    /* P229: sti / cli not invertible safely (IRQ window). skip. */

    /* P230: cld / cld -> cld */
    { 2, 230,
      { { "cld", 0, AN_, AN_, 0 },
        { "cld", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cld / cld -> cld", NULL },

    /* P231: std / std -> std */
    { 2, 231,
      { { "std", 0, AN_, AN_, 0 },
        { "std", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "std / std -> std", NULL },

    /* P232: fldz / fmulp -> delete both (*0 under IEEE may yield -0).
     *  WITHDRAWN as unsafe for sign-of-zero. */

    /* P233: fabs / fchs / fabs -> fabs (abs(neg(abs(x)))=abs(x)) needs MAXPAT3 */
    { 3, 233,
      { { "fabs", 0, AN_, AN_, 0 },
        { "fchs", 0, AN_, AN_, 0 },
        { "fabs", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      
"fabs / fchs / fabs -> fabs", NULL },

    /* ---- v2.13: -Ox aggressive + MMX/SSE/3DNow + 386/Pentium ---- */

    /* P240 (-Ox): mov R, MEM / ALU S,R -> ALU S,MEM for ANY mem
     *  (not only stack).  Risk: MMIO double-read semantics differ if
     *  something else observed the load; adjacent pair is usually safe. */
    { 2, 240,
      { { "mov", 0, RR_('a'), ME_, 2 },
        { NULL, OC_ARITH, RR_('b'), SM_('a'), 2 } },
      PRE_AGGRESSIVE | PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "$op1 $b, $m0" } },
      "(-Ox) load fold into ALU (any mem)", NULL },

    /* P241 (v2.19 REMOVED): "fldz / fmulp -> delete" was an
     *  UNCONDITIONAL MISCOMPILATION.  fldz pushes +0.0, fmulp
     *  computes ST(1) = ST(1) * ST(0) then pops.  The result is
     *  ST(1) = X * 0 = +/-0 (or NaN for Inf), NOT X.  Deleting
     *  both leaves X unchanged -- wrong for every nonzero X.
     *  The developer conflated this with P206 (fld1/fmulp -> delete,
     *  which IS sound because X*1 = X).  The withdrawn P232 already
     *  documented this pattern as unsafe, yet P241 reimplemented it.
     *  rname[241] kept as documentation. */

    /* P242: movq MM, MM same -> delete (MMX move to self). */
    { 1, 242,
      { { "movq", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movq MM,MM -> delete", NULL },

    /* P243: movd MM, MM same - movd is 32-bit; still noop if same. */
    { 1, 243,
      { { "movd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movd R,R -> delete", NULL },

    /* P244: pxor MM,MM is zero idiom - leave (not delete).
     *  por MM,MM / pand MM,MM -> delete (identity). */
    { 1, 244,
      { { "por", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "por MM,MM -> delete (identity)", NULL },

    /* P245: pand MM,MM -> delete */
    { 1, 245,
      { { "pand", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "pand MM,MM -> delete (identity)", NULL },

    /* P246: pandn MM,MM -> zero (result 0) - rewrite to pxor MM,MM */
    { 1, 246,
      { { "pandn", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "pandn MM,MM -> pxor MM,MM", NULL },

    /* P247: SSE movaps xmm,xmm / movups same */
    { 1, 247,
      { { "movaps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movaps XMM,XMM -> delete", NULL },

    /* P248: movups XMM,XMM -> delete */
    { 1, 248,
      { { "movups", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movups XMM,XMM -> delete", NULL },

    /* P249: movapd / movsd scalar */
    { 1, 249,
      { { "movapd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movapd XMM,XMM -> delete", NULL },

    /* P250: xorps XMM,XMM / xorpd - zero idioms kept.
     *  orps XMM,XMM identity -> delete */
    { 1, 250,
      { { "orps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "orps XMM,XMM -> delete", NULL },

    /* P251: andps XMM,XMM -> delete */

    /* P266: andps already P251; paddd MM,MM is NOT identity (2x).
     *  psubd MM,MM -> zero: rewrite to pxor (MMX) */
    { 1, 266,
      { { "psubd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubd MM,MM -> pxor MM,MM", NULL },

    /* P267: psubw / psubb same */
    { 1, 267,
      { { "psubw", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubw MM,MM -> pxor MM,MM", NULL },

    /* P268: psubb MM,MM -> pxor */
    { 1, 268,
      { { "psubb", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubb MM,MM -> pxor MM,MM", NULL },

    /* P269: lfence / lfence */
    { 2, 269,
      { { "lfence", 0, AN_, AN_, 0 },
        { "lfence", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "lfence / lfence -> lfence", NULL },

    /* P270: mfence / mfence */
    { 2, 270,
      { { "mfence", 0, AN_, AN_, 0 },
        { "mfence", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "mfence / mfence -> mfence", NULL },

    /* P271: nop / nop -> delete second (any CPU) */
    { 2, 271,
      { { "nop", 0, AN_, AN_, 0 },
        { "nop", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "nop / nop -> delete second", NULL },

    /* P272: xchg ax,ax is the classic 1-byte NOP; same-reg xchg
     *  already P126.  Covered. */

    /* P273 (v2.19 REMOVED): redundant with P240 (OC_ARITH covers cmp). */

    /* P274 (-Ox): mov R,MEM / test R,R -> cmp MEM,0 when AF dead.
     *  v2.19: kept in -Ox for arbitrary mem (size-prefix risk:
     *  cmp [mem],0 defaults to byte on MASM without explicit size).
     *  The stack-mem variant P397 below is always-on and emits the
     *  size prefix from R's captured width. */
    { 2, 274,
      { { "mov", 0, RR_('a'), ME_, 2 },
        { "test", 0, SM_('a'), SM_('a'), 2 } },
      PRE_AGGRESSIVE | PRE_REG_DEAD_RA | PRE_FLAGS_DEAD_AF | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "cmp $m0, 0" } },
      "(-Ox) mov R,MEM / test R,R -> cmp MEM,0", NULL },

    /* P275 (v2.22 REMOVED): shadowed by C rule P20. */

    /* P276: lea R, [R+0] / lea R,[R] already C P124. */

    /* P277 (-Ox): push MEM / pop R -> mov R, MEM (R not SP).
     *  Stack traffic removed; MEM read once.  Size win varies. */
    { 2, 277,
      { { "push", 0, ME_, AN_, 1 },
        { "pop",  0, RR_('a'), AN_, 1 } },
      PRE_AGGRESSIVE | PRE_NOT_SP,
      { { ACT_REW, "mov $a, $m0" }, { ACT_DEL, NULL } },
      "(-Ox) push MEM / pop R -> mov R,MEM", NULL },

    /* P278: bswap R / bswap R already P127. */

    /* P279: xorps XMM,XMM is the SSE zero idiom -- leave it.
     *  andnps XMM,XMM -> zero via xorps */
    { 1, 279,
      { { "andnps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xorps $a, $a" } },
      "andnps XMM,XMM -> xorps XMM,XMM", NULL },

    /* ---- v2.15: FPC/GCC/LLVM/Agner idioms ---- */

    { 2, 280,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "xor", 0, SM_('a'), SM_('b'), 2 } },
      0,
      { { ACT_REW, "xor $a, $a" }, { ACT_DEL, NULL } },
      "mov R,S / xor R,S -> xor R,R", NULL },

    { 2, 281,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "sub", 0, SM_('a'), SM_('b'), 2 } },
      PRE_FLAGS_DEAD_AF | PRE_NOT_SP,
      { { ACT_REW, "xor $a, $a" }, { ACT_DEL, NULL } },
      "mov R,S / sub R,S -> xor R,R (AF dead)", NULL },



    { 1, 285,
      { { "test", 0, RR_('a'), IV_(-1), 2 } },
      0,
      { { ACT_REW, "test $a, $a" } },
      "test R,-1 -> test R,R", NULL },





    { 1, 290,
      { { "minss", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "minss XMM,XMM -> delete", NULL },
    { 1, 291,
      { { "maxss", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "maxss XMM,XMM -> delete", NULL },
    { 1, 292,
      { { "minps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "minps XMM,XMM -> delete", NULL },
    { 1, 293,
      { { "maxps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "maxps XMM,XMM -> delete", NULL },
    { 1, 294,
      { { "minsd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "minsd XMM,XMM -> delete", NULL },
    { 1, 295,
      { { "maxsd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "maxsd XMM,XMM -> delete", NULL },

    { 1, 296,
      { { "subps", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xorps $a, $a" } },
      "subps XMM,XMM -> xorps", NULL },
    { 1, 297,
      { { "subpd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xorpd $a, $a" } },
      "subpd XMM,XMM -> xorpd", NULL },
    { 1, 298,
      { { "subss", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xorps $a, $a" } },
      "subss XMM,XMM -> xorps", NULL },

    { 1, 299,
      { { "pandn", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "pandn XMM,XMM -> pxor", NULL },

    { 2, 300,
      { { "stc", 0, AN_, AN_, 0 },
        { "cmc", 0, AN_, AN_, 0 } },
      0,
      { { ACT_REW, "clc" }, { ACT_DEL, NULL } },
      "stc / cmc -> clc", NULL },

    { 2, 301,
      { { "clc", 0, AN_, AN_, 0 },
        { "cmc", 0, AN_, AN_, 0 } },
      0,
      { { ACT_REW, "stc" }, { ACT_DEL, NULL } },
      "clc / cmc -> stc", NULL },


    { 2, 306,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "mov", 0, SM_('a'), IV_(0), 2 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "xor R,R / mov R,0 -> delete mov", NULL },

    { 2, 307,
      { { "mov", 0, RR_('a'), IV_(0), 2 },
        { "xor", 0, SM_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL }, { ACT_KEEP, NULL } },
      "mov R,0 / xor R,R -> keep xor", NULL },

    /* P308-P310 (v2.19 REMOVED): redundant with P240 (OC_ARITH covers
     *  or/and/xor).  The -Ox P240 rule already folds these for any
     *  memory operand; the stack-mem variant P396 below is always-on. */

    { 2, 311,
      { { "femms", 0, AN_, AN_, 0 },
        { "femms", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "femms / femms -> femms", NULL },

    { 2, 312,
      { { "pause", 0, AN_, AN_, 0 },
        { "pause", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "pause / pause -> pause", NULL },

    { 2, 313,
      { { "ud2", 0, AN_, AN_, 0 },
        { "ud2", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "ud2 / ud2 -> ud2", NULL },

    { 2, 314,
      { { "int3", 0, AN_, AN_, 0 },
        { "int3", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "int3 / int3 -> int3", NULL },

    /* ---- v2.16: kept after redundancy purge ---- */

    /* P316 (v2.22 REMOVED): shadowed by C rule P24 (same conditions). */

    /* P321 (v2.22 REMOVED): shadowed by C rule P19. */

    /* P323/P324: shl/sal R,1 -> lea (no flags) when flags dead.
     *  Complements P143 (add R,R -> shl); multi-pass yields lea.
     *  v2.17: gated by p323_lea_rr_check -- "lea R,[R+R]" needs the
     *  SIB byte (386+) and a 32/64-bit register.  On 16-bit code
     *  "lea ax,[ax+ax]" is an assembler error, so the old rule broke
     *  4VIEW's real-mode build.  8/16-bit shl R,1 stays intact. */
    { 1, 323,
      { { "shl", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_REW, "lea $a, [$a+$a]" } },
      "shl R,1 -> lea R,[R+R] (flags dead, 386+ 32/64-bit)", p323_lea_rr_check },
    { 1, 324,
      { { "sal", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_REW, "lea $a, [$a+$a]" } },
      "sal R,1 -> lea R,[R+R] (flags dead, 386+ 32/64-bit)", p323_lea_rr_check },

    /* P326/P327: after mov R,S the and/or R,S is value-nop */
    { 2, 326,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "and", 0, SM_('a'), SM_('b'), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "mov R,S / and R,S -> delete and (flags dead)", NULL },
    { 2, 327,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "or", 0, SM_('a'), SM_('b'), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "mov R,S / or R,S -> delete or (flags dead)", NULL },

    /* P329 (v2.18 REMOVED): "and R,R -> test R,R" was completely
     *  shadowed by the C rule P8, which handles or/and R,R (any
     *  width, including all-ones masks) and now `continue`s after
     *  rewriting, so the table rule could never fire.  rname[329]
     *  kept as documentation. */

    /* ---- v2.17: gaps from real ASM / FPC / GCC / LLVM analysis ---- */

    /* P332 (v2.18 REMOVED): "or R,R -> test R,R" was completely
     *  shadowed by the C rule P8 (same reason as P329 above).
     *  rname[332] kept as documentation. */

    /* P333: xor R,R / cmp R,0 -> delete cmp (AF dead).
     *  xor sets ZF/SF/PF for R==0; cmp R,0 repeats them AND sets AF=0.
     *  xor leaves AF undefined.  v2.22: needs PRE_FLAGS_DEAD_AF (daa/
     *  das/aaa/aas/pushf/lahf read AF and would get a different value). */
    { 2, 333,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "cmp", 0, SM_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_AF,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "xor R,R / cmp R,0 -> delete cmp (AF dead)", NULL },

    /* P334: xor R,R / cmp R,R -> delete cmp (AF dead, same as P333). */
    { 2, 334,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "cmp", 0, SM_('a'), SM_('a'), 2 } },
      PRE_FLAGS_DEAD_AF,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "xor R,R / cmp R,R -> delete cmp (AF dead)", NULL },

    /* P335: mov R,0 / cmp S,R -> cmp S,0 when R dead (saves the zero reg) */
    { 2, 335,
      { { "mov", 0, RR_('a'), IV_(0), 2 },
        { "cmp", 0, RR_('b'), SM_('a'), 2 } },
      PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "cmp $b, 0" } },
      "mov R,0 / cmp S,R -> cmp S,0 (R dead)", NULL },

    /* P336: xor R,R / cmp S,R -> cmp S,0 when R dead (xor is zeroing) */
    { 2, 336,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "cmp", 0, RR_('b'), SM_('a'), 2 } },
      PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "cmp $b, 0" } },
      "xor R,R / cmp S,R -> cmp S,0 (R dead)", NULL },

    /* P337: mov R,0 / test S,R -> test S,S? No - test S,0.
     *  test S,R with R=0 is test S,0. */
    { 2, 337,
      { { "mov", 0, RR_('a'), IV_(0), 2 },
        { "test", 0, RR_('b'), SM_('a'), 2 } },
      PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "test $b, 0" } },
      "mov R,0 / test S,R -> test S,0 (R dead)", NULL },

    /* P338: xor R,R / test S,R -> test S,0 (R dead) */
    { 2, 338,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "test", 0, RR_('b'), SM_('a'), 2 } },
      PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "test $b, 0" } },
      "xor R,R / test S,R -> test S,0 (R dead)", NULL },

    /* P339: push 0 / pop R -> xor R,R when flags dead
     *  (or mov R,0 if flags live — xor preferred when dead) */
    { 2, 339,
      { { "push", 0, IV_(0), AN_, 1 },
        { "pop",  0, RR_('a'), AN_, 1 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_REW, "xor $a, $a" }, { ACT_DEL, NULL } },
      "push 0 / pop R -> xor R,R (flags dead)", NULL },

    /* P340 (v2.22 REMOVED): "push 0 / pop R -> mov R,0" was a size
     *  regression for 32-bit R (push imm8 + pop = 3 bytes vs
     *  mov R32,0 = 5 bytes).  P46 (C rule) handles this correctly
     *  with a size gate.  rname[340] kept as doc. */

    /* P341/P342 (v2.19 REMOVED): redundant with P240 (OC_ARITH covers
     *  add/sub).  Same rationale as P308-P310 above. */

    /* ---- v2.19: LLVM optimizeCompare-style + cleanup ---- */

    /* P345 (v2.22 REMOVED): shadowed by C rule P19. */

    /* P346 (v2.22 REMOVED): shadowed by C rule P19. */

    /* P347: mov R,S / cmp R,S -> cmp R,R or delete cmp? After mov, R==S
     *  so cmp R,S is cmp equal -> always ZF.  Rewrite useless unless
     *  flags needed as always-equal.  Safer: cmp R,R (same), or if
     *  flags dead delete both cmp. */
    { 2, 347,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "cmp", 0, SM_('a'), SM_('b'), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "mov R,S / cmp R,S -> delete cmp (flags dead)", NULL },

    /* P348: mov R,S / test R,S -> test R,R (equal operands) */
    { 2, 348,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "test", 0, SM_('a'), SM_('b'), 2 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_REW, "test $a, $a" } },
      "mov R,S / test R,S -> test R,R", NULL },

    /* P349 (v2.22 REMOVED): shadowed by C rule P22. */

    /* P350 (v2.22 REMOVED): shadowed by C rule P22. */

    /* ---- v2.17: width-specific all-ones masks (0FFh / 0FFFFh) ----
     *  v2.18: P390/P391/P394/P395 were removed because the C rules
     *  P8 (and R,all-ones -> delete/test, any width) and P37
     *  (xor R,all-ones -> not, unsigned notation) already handle
     *  these patterns and fire first with `continue`.  Only P392/P393
     *  (or R,all-ones -> mov) survive, because no C rule covers the
     *  unsigned all-ones OR (P60 only checks signed -1). */

    /* P392: or R8, 0FFh -> mov R8, 0FFh (flags dead).  OR with
     *  all-ones forces the register to 0FFh; MOV sets it directly
     *  without touching flags.  Size-neutral on 8086 (both 3 bytes)
     *  but breaks the false dependency on the old value. */
    { 1, 392,
      { { "or", 0, R_('a', RC_8), IV_(255), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, $K" } },
      "or R8,0FFh -> mov R8,0FFh (flags dead)", NULL },

    /* P393: or R16, 0FFFFh -> mov R16, 0FFFFh (flags dead).
     *  Complements P60 (which handles the signed -1 form). */
    { 1, 393,
      { { "or", 0, R_('a', RC_16), IV_(65535), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, $K" } },
      "or R16,0FFFFh -> mov R16,0FFFFh (flags dead)", NULL },

    /* ---- v2.19: always-on stack-memory load folds ----
     *  Stack memory ([bp/ebp/rbp±N]) is provably non-MMIO: it's the
     *  function's own local frame.  The load-fold family (P240/P274/
     *  P277) was -Ox only for arbitrary memory because of the MMIO
     *  double-read risk; these clones fire always-on for stack mem.
     *  PRE_STACK_MEM_0 is implemented by is_stack_mem_operand() which
     *  rejects everything that isn't [bp/ebp/rbp±N]. */

    /* P396: mov R,[bp+N] / ALU S,R -> ALU S,[bp+N] (R dead, stack mem).
     *  Always-on version of P240 for stack-frame locals. */
    { 2, 396,
      { { "mov", 0, RR_('a'), ME_, 2 },
        { NULL, OC_ARITH, RR_('b'), SM_('a'), 2 } },
      PRE_STACK_MEM_0 | PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "$op1 $b, $m0" } },
      "load fold into ALU (stack mem)", NULL },

    /* P397: push [bp+N] / pop R -> mov R,[bp+N] (R not SP, stack mem).
     *  Always-on version of P277. */
    { 2, 397,
      { { "push", 0, ME_, AN_, 1 },
        { "pop",  0, RR_('a'), AN_, 1 } },
      PRE_STACK_MEM_0 | PRE_NOT_SP,
      { { ACT_REW, "mov $a, $m0" }, { ACT_DEL, NULL } },
      "push [bp+N] / pop R -> mov R,[bp+N] (stack mem)", NULL },

    /* ---- v2.20: SSE2 identity operations (research: Intel SDM
     *  Vol.2; Agner Fog optimizing_assembly; LLVM X86InstrSSE.td).
     *  These are the SSE2 (128-bit XMM) counterparts of rules that
     *  already exist for MMX (64-bit MM) and SSE (32-bit XMM scalar).
     *  All are exact: SIMD instructions do not touch the integer
     *  status flags, so no flag scan is needed. */

    /* P398: movq XMM,XMM -> delete (SSE2 move-to-self).  P242
     *  covers only the MMX form (movq mm,mm). */
    { 1, 398,
      { { "movq", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movq XMM,XMM -> delete", NULL },

    /* P399: movdqa XMM,XMM -> delete (SSE2 aligned move).  P249
     *  covers movapd; movdqa/movdqu are the integer equivalents. */
    { 1, 399,
      { { "movdqa", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movdqa XMM,XMM -> delete", NULL },

    /* P400: movdqu XMM,XMM -> delete (SSE2 unaligned move). */
    { 1, 400,
      { { "movdqu", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movdqu XMM,XMM -> delete", NULL },

    /* P401: por XMM,XMM -> delete (SSE2 packed OR identity).
     *  P244 covers only the MMX form. */
    { 1, 401,
      { { "por", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "por XMM,XMM -> delete (identity)", NULL },

    /* P402: pand XMM,XMM -> delete (SSE2 packed AND identity).
     *  P245 covers only the MMX form. */
    { 1, 402,
      { { "pand", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "pand XMM,XMM -> delete (identity)", NULL },

    /* P403: pandn XMM,XMM -> pxor XMM,XMM (SSE2 packed AND-NOT
     *  of self = zero).  P246/P299 cover the MMX form. */
    { 1, 403,
      { { "pandn", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "pandn XMM,XMM -> pxor XMM,XMM", NULL },

    /* P404: psubb/psubw/psubd XMM,XMM -> pxor XMM,XMM (SSE2 packed
     *  subtract of self = zero).  P266/P267/P268 cover the MMX form. */
    { 1, 404,
      { { "psubb", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubb XMM,XMM -> pxor XMM,XMM", NULL },
    { 1, 405,
      { { "psubw", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubw XMM,XMM -> pxor XMM,XMM", NULL },
    { 1, 406,
      { { "psubd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "pxor $a, $a" } },
      "psubd XMM,XMM -> pxor XMM,XMM", NULL },

    /* P407: orpd XMM,XMM -> delete (SSE2 packed double OR identity).
     *  P250 covers orps (single precision). */
    { 1, 407,
      { { "orpd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "orpd XMM,XMM -> delete (identity)", NULL },

    /* P408: andpd XMM,XMM -> delete (SSE2 packed double AND identity). */
    { 1, 408,
      { { "andpd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "andpd XMM,XMM -> delete (identity)", NULL },

    /* P409: andnpd XMM,XMM -> xorpd XMM,XMM (AND-NOT of self = zero).
     *  P279 covers andnps (single precision). */
    { 1, 409,
      { { "andnpd", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xorpd $a, $a" } },
      "andnpd XMM,XMM -> xorpd XMM,XMM", NULL },

    /* P410: addps/addpd/addss/addsd XMM,XMM -> could double the value,
     *  NOT an identity (x + x = 2x ≠ x).  Leave.  Not implemented. */

    /* P411: xorpd/xorps XMM,XMM is the zero idiom -- leave it (like
     *  pxor).  Already documented at P244 comment.  Not deleted. */

    /* ---- v2.23: new table rules from audit ---- */

    /* P418: leave / leave -> leave (idempotent: restores BP and SP
     *  from the same BP, so the second is a no-op).  Exact, no flags. */
    { 2, 418,
      { { "leave", 0, AN_, AN_, 0 },
        { "leave", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "leave / leave -> leave", NULL },

    /* P419: xchg R,S / xchg R,S -> delete both (same pair, either
     *  order).  Two swaps restore everything; xchg touches no flags.
     *  P14 was documented since v1.30 but never implemented. */
    { 2, 419,
      { { "xchg", 0, RR_('a'), RR_('b'), 2 },
        { "xchg", 0, SM_('a'), SM_('b'), 2 } },
      0,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "xchg R,S / xchg R,S -> delete both", NULL },
    /* Also match xchg S,R / xchg S,R (swapped operand order) */
    { 2, 419,
      { { "xchg", 0, RR_('a'), RR_('b'), 2 },
        { "xchg", 0, SM_('b'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "xchg R,S / xchg S,R -> delete both", NULL },

    /* P420: mov R,S / xchg R,S -> delete xchg (R already = S).
     *  mov touches no flags; xchg touches no flags.  Exact. */
    { 2, 420,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "xchg", 0, SM_('a'), SM_('b'), 2 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "mov R,S / xchg R,S -> delete xchg", NULL },

    /* P421: nop -> delete (single nop is always safe to remove:
     *  no register, no memory, no flags.  Only delete when the line
     *  has no label — a labeled nop might be a jump target.) */
    { 1, 421,
      { { "nop", 0, AN_, AN_, 0 } },
      0,
      { { ACT_DEL, NULL } },
      "nop -> delete (single, no label)", NULL },

    /* ---- v2.23: migrated from C to table ---- */

    /* P11 (v2.23): cmp R,0 -> test R,R (AF dead).  cmp R,0 sets AF=0;
     *  test leaves AF undefined.  All other flags identical. */
    { 1, 11,
      { { "cmp", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_AF,
      { { ACT_REW, "test $a, $a" } },
      "cmp R,0 -> test R,R (AF dead)", NULL },

    /* P71 (v2.23): sub R,R -> xor R,R (AF dead, not SP).  Both write
     *  R=0 and clear CF/OF, set SF=0/ZF=1/PF=1; only AF differs.
     *  FPC Sub2Xor; GCC canonical R=0 to xor. */
    { 1, 71,
      { { "sub", 0, RR_('a'), SM_('a'), 2 } },
      PRE_FLAGS_DEAD_AF | PRE_NOT_SP,
      { { ACT_REW, "xor $a, $a" } },
      "sub R,R -> xor R,R (AF dead)", NULL },

    /* ---- v2.24: migrated from C to table ---- */

    /* P10 (v2.24): add/sub R,1 / R,-1 -> inc/dec R (CF dead).
     *  4 table entries for the 4 operand combinations. */
    { 1, 10,
      { { "add", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_CF,
      { { ACT_REW, "inc $a" } },
      "add R,1 -> inc R (CF dead)", NULL },
    { 1, 10,
      { { "add", 0, RR_('a'), IV_(-1), 2 } },
      PRE_FLAGS_DEAD_CF,
      { { ACT_REW, "dec $a" } },
      "add R,-1 -> dec R (CF dead)", NULL },
    { 1, 10,
      { { "sub", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_CF,
      { { ACT_REW, "dec $a" } },
      "sub R,1 -> dec R (CF dead)", NULL },
    { 1, 10,
      { { "sub", 0, RR_('a'), IV_(-1), 2 } },
      PRE_FLAGS_DEAD_CF,
      { { ACT_REW, "inc $a" } },
      "sub R,-1 -> inc R (CF dead)", NULL },

    /* P48 (v2.24): xor R,R / test R,R -> delete test.
     *  After xor, R=0 and flags are ZF=1/SF=0/PF=1/CF=0/OF=0.
     *  test R,R on R=0 produces identical flags.  Exact, no scan. */
    { 2, 48,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "test", 0, SM_('a'), SM_('a'), 2 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "xor R,R / test R,R -> delete test", NULL },

    /* P65 (v2.24): dec R / cmp R,-1 -> delete cmp (all flags dead).
     *  After dec, ZF reflects R_new==0; cmp R_new,-1 sets ZF iff
     *  R_new==-1.  These DIFFER, so ALL six flags must be dead. */
    { 2, 65,
      { { "dec", 0, RR_('a'), AN_, 1 },
        { "cmp", 0, SM_('a'), IV_(-1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "dec R / cmp R,-1 -> delete cmp (flags dead)", NULL },

    /* P93 (v2.24): xor R,R / mov R,K -> delete xor.
     *  xor defines all six flags; mov defines none; the flags die
     *  in the zero-instruction gap.  Exact (no scan needed). */
    { 2, 93,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "mov", 0, SM_('a'), IM_, 2 } },
      0,
      { { ACT_DEL, NULL }, { ACT_KEEP, NULL } },
      "xor R,R / mov R,K -> delete xor", NULL },

    /* ---- v2.25: migrated P21 + new rules ---- */

    /* P21 (v2.25): dup flag ops -> delete second.  6 table entries
     *  for cld/std/cli/sti/clc/stc.  Each is idempotent (same flag
     *  bit, same value, nothing between). */
    { 2, 21, { { "cld", 0, AN_, AN_, 0 }, { "cld", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cld / cld -> cld", NULL },
    { 2, 21, { { "std", 0, AN_, AN_, 0 }, { "std", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "std / std -> std", NULL },
    { 2, 21, { { "cli", 0, AN_, AN_, 0 }, { "cli", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cli / cli -> cli", NULL },
    { 2, 21, { { "sti", 0, AN_, AN_, 0 }, { "sti", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "sti / sti -> sti", NULL },
    { 2, 21, { { "clc", 0, AN_, AN_, 0 }, { "clc", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "clc / clc -> clc", NULL },
    { 2, 21, { { "stc", 0, AN_, AN_, 0 }, { "stc", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "stc / stc -> stc", NULL },

    /* P422 (v2.25): sahf / sahf -> sahf.  SAHF loads flags from AH;
     *  two in a row load the same flags from the same AH.  Exact. */
    { 2, 422,
      { { "sahf", 0, AN_, AN_, 0 },
        { "sahf", 0, AN_, AN_, 0 } },
      0,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "sahf / sahf -> sahf", NULL },

    /* P423 (v2.25): mov al, [mem] / cbw -> movsx ax, byte ptr [mem].
     *  Wait — this is P31 which already exists.  Skip. */

    /* P424 (v2.25): movzx R, R (same reg, same width) -> delete.
     *  movzx R, R where both operands are the same register and
     *  same width is identity (zero-extension of already-correct
     *  width = no-op).  Exact. */
    { 1, 424,
      { { "movzx", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movzx R,R (same reg+width) -> delete", NULL },

    /* P425 (v2.25): movsx R, R (same reg, same width) -> delete.
     *  Same as P424 for movsx.  Only fires when width matches,
     *  meaning the source already fills the destination — sign-
     *  extension of a full-width source is identity. */
    { 1, 425,
      { { "movsx", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "movsx R,R (same reg+width) -> delete", NULL },

    /* ---- v2.26: migrated P28 + new rules ---- */

    /* P28 (v2.26): dup sign-extend -> delete second.  8 entries
     *  for cbw/cwde/cwd/cdq and AT&T cbtw/cwtl/cwtd/cltd.  Each
     *  is idempotent (re-derives same high half, no flags). */
    { 2, 28, { { "cbw", 0, AN_, AN_, 0 }, { "cbw", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cbw / cbw -> cbw", NULL },
    { 2, 28, { { "cwde", 0, AN_, AN_, 0 }, { "cwde", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cwde / cwde -> cwde", NULL },
    { 2, 28, { { "cwd", 0, AN_, AN_, 0 }, { "cwd", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cwd / cwd -> cwd", NULL },
    { 2, 28, { { "cdq", 0, AN_, AN_, 0 }, { "cdq", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cdq / cdq -> cdq", NULL },
    { 2, 28, { { "cbtw", 0, AN_, AN_, 0 }, { "cbtw", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cbtw / cbtw -> cbtw", NULL },
    { 2, 28, { { "cwtl", 0, AN_, AN_, 0 }, { "cwtl", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cwtl / cwtl -> cwtl", NULL },
    { 2, 28, { { "cwtd", 0, AN_, AN_, 0 }, { "cwtd", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cwtd / cwtd -> cwtd", NULL },
    { 2, 28, { { "cltd", 0, AN_, AN_, 0 }, { "cltd", 0, AN_, AN_, 0 } },
      0, { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "cltd / cltd -> cltd", NULL },

    /* P428 (v2.26): lea R,[R+R] -> add R,R (flags dead, 386+).
     *  P41 requires R != S; this covers the same-register case.
     *  lea is 3 bytes on 386+; add R,R is 2 bytes.  1 byte save.
     *  lea touches no flags; add sets all six.  Need F_ALL6 dead. */
    { 1, 428,
      { { "lea", 0, RR_('a'), SM_('a'), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_REW, "add $a, $a" } },
      "lea R,[R+R] -> add R,R (flags dead)", p323_lea_rr_check },

    /* P429 (v2.26): mov R,S / push R -> push S (R dead, S != R).
     *  After mov, R == S.  Pushing S gives the same value.
     *  Saves the mov instruction.  R must be dead after push.
     *  v2.26 note: PRE_REG_DEAD_RA uses reg_dead_cf which treats
     *  AX/DX as live-out at ret (return value).  So this won't
     *  fire when the next instruction after push is ret and R is
     *  AX/DX — that's correct (R might hold the return value).
     *  It WILL fire when R is a non-AX/DX register, or when the
     *  code after push is not ret.  No flags involved. */
    { 2, 429,
      { { "mov", 0, RR_('a'), RR_('b'), 2 },
        { "push", 0, SM_('a'), AN_, 1 } },
      PRE_REG_DEAD_RA | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "push $b" } },
      "mov R,S / push R -> push S (R dead)", NULL },

    /* ---- v2.24: 3 new rules from the research list ---- */

    /* P430 (v2.24): "or R,c1 / and R,c2 / or R,c3" 3-op chain.
     *  When (c1 & c2) ⊆ c3, every bit the first OR forces to 1 that
     *  the AND keeps is re-forced by the last OR, so the first OR is
     *  redundant and can be deleted.  Final value with OR1:
     *  (R & c2) | (c1 & c2) | c3; without OR1: (R & c2) | c3;
     *  diff = (c1 & c2) & ~c3, which must be 0.  No flag scan: the
     *  deleted OR is label-free adjacent to the AND, which overwrites
     *  all six status flags before reading any.  Catches the case
     *  P62b misses: P62b only fires when c2 ⊆ c1 (collapsing the
     *  whole pair to a mov); P430 fires when c2 ⊄ c1 but the
     *  overlapping-mask condition (c1 & c2) ⊆ c3 still lets the
     *  first OR go.  Research: Open Watcom peepopt.c AndOr/OrAnd
     *  family extended to the 3-op chain. */
    { 3, 430,
      { { "or",  0, RR_('a'), IM_, 2 },
        { "and", 0, SM_('a'), IM_, 2 },
        { "or",  0, SM_('a'), IM_, 2 } },
      0,
      { { ACT_DEL, NULL }, { ACT_KEEP, NULL }, { ACT_KEEP, NULL } },
      "or R,c1 / and R,c2 / or R,c3 -> delete or1 (c1&c2⊆c3)", p430_or_and_or_check },

    /* P431 (v2.25 refactor M8): "mov R8lo, 0 / mov R8hi, 0 -> xor R16, R16"
     *  where R8lo and R8hi are the low and high byte of the same
     *  8-bit register family (AL+AH -> AX, CL+CH -> CX, DL+DH -> DX,
     *  BL+BH -> BX).  Both movs together set the whole 16-bit parent
     *  to 0; a single "xor R16, R16" does the same in 2 bytes vs the
     *  4 bytes of two byte-sized mov imm8.  xor defines all six
     *  status flags; the two movs define none; PRE_FLAGS_DEAD_ALL
     *  proves the difference is unobservable.  R16 is not SP (cap['a']
     *  is an 8-bit reg, AX/CX/DX/BX family), so PRE_NOT_SP is not
     *  required.  The rewrite uses $a16, which resolves to the 16-bit
     *  parent regardless of which byte cap['a'] bound (AL -> AX,
     *  AH -> AX, CL -> CX, etc.).  PRE_INTEL: the $a16 template emits
     *  Intel-syntax register names without the AT&T "%" prefix.
     *  v2.25 (M8): the same-family + complementary-lo relationship
     *  is now expressed directly in the pattern via CLO_('a')
     *  (OP_COMPLEMENT_LO), so the p431_al_ah_ax_check function is
     *  gone.  cap_to_regidx inside the matcher refuses families
     *  that lack an 8-bit form (SP/BP/SI/DI have no byte register),
     *  so SP exclusion is automatic. */
    { 2, 431,
      { { "mov", 0, R_('a', RC_8), IV_(0), 2 },
        { "mov", 0, CLO_('a'),     IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_INTEL,
      { { ACT_REW, "xor $a16, $a16" }, { ACT_DEL, NULL } },
      "mov R8lo,0 / mov R8hi,0 -> xor R16,R16 (flags dead)", NULL },

    /* P432 (v2.25 refactor M1): "movzx R, src / test R, R -> test src, src"
     *  when R is dead after the test (PRE_REG_DEAD_RA) and SF is dead
     *  from the test onward (PRE_FLAGS_DEAD_SF).  After the movzx the
     *  high bits of R are zero, so "test R, R" leaves SF=0; "test src,
     *  src" leaves SF = MSB of src -- they differ when src is signed-
     *  negative.  ZF/PF/CF/OF all match exactly (ZF iff src==0; PF on
     *  low byte = src in both; CF=OF=0 in both); AF is undef in both.
     *  Only SF needs the dead-flag scan, which is more permissive than
     *  PRE_FLAGS_DEAD_ALL and lets the rule fire on the common
     *  "movzx EAX, AL / test EAX, EAX / je L" pattern (je reads only
     *  ZF, SF is dead).  386+ (movzx encoding); Intel-only.
     *  v2.25 (M1): the SF-dead scan is now PRE_FLAGS_DEAD_SF instead
     *  of a p432_movzx_test_check() function -- the rule has no
     *  custom check function anymore.  The check that R != src
     *  (to avoid shadowing P424 which deletes "movzx R, R" at the
     *  same width) is encoded in the pattern: cap 'b' is bound to
     *  src via RR_('b'), and the rewrite $b only resolves when src
     *  differs from R; if src == R same width, P424 fires first
     *  because it's a single-inst rule that runs earlier in the
     *  table loop.  If src and R are same family but different width
     *  (e.g. movzx EAX, AL), that's the genuine zero-extension case
     *  and we DO want to fire -- the pattern allows it because
     *  RR_('b') doesn't constrain width relative to RR_('a').
     *  Research: LLVM X86PeepholePass optimizeCompare; GCC i386.md
     *  combine movzx+test. */
    { 2, 432,
      { { "movzx", 0, RR_('a'), RR_('b'), 2 },
        { "test",  0, SM_('a'),  SM_('a'), 2 } },
      PRE_CPU_386 | PRE_REG_DEAD_RA | PRE_INTEL | PRE_FLAGS_DEAD_SF,
      { { ACT_DEL, NULL }, { ACT_REW, "test $b, $b" } },
      "movzx R,S / test R,R -> test S,S (R dead, SF dead)", NULL },

    /* ---- v2.25: NEW RULES using the M1/M4/M5/M6/M8 table extensions ---- */

    /* P433 (v2.25): "add R, c1 / add R, c2 -> add R, c1+c2" -- the
     *  constant-fold that P16 documented since v1.30 but never had
     *  code.  Uses M4 (${K + K1} arithmetic template) to emit the
     *  folded sum, and a small check (p433_add_fold_check) that
     *  verifies the sum fits in the dest reg's signed imm range via
     *  width_imm_limit().  PRE_FLAGS_DEAD_OF: the two half-adds can
     *  produce a different OF than the single combined add (overflow
     *  of the intermediate), so OF must be dead; every other flag is
     *  identical between the two forms (the result R is the same, so
     *  SF/ZF/PF/CF come out the same; AF too).  Not SP: same
     *  rationale as P22/P39.  Research: FPC aoptx86 AddAdd2Add. */
    { 2, 433,
      { { "add", 0, RR_('a'), IM_, 2 },
        { "add", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_OF | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "add $a, ${K + K1}" } },
      "add R,c1 / add R,c2 -> add R,c1+c2 (OF dead, fits)", p433_add_fold_check },

    /* P434 (v2.25): "sub R, c1 / sub R, c2 -> sub R, c1+c2" -- the
     *  sub cousin of P433.  Two consecutive subs of the same register
     *  are equivalent to one sub of the sum (R - c1 - c2 == R - (c1+c2)).
     *  Same OF-dead gate and same fit check.  FPC SubSub2Sub. */
    { 2, 434,
      { { "sub", 0, RR_('a'), IM_, 2 },
        { "sub", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_OF | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "sub $a, ${K + K1}" } },
      "sub R,c1 / sub R,c2 -> sub R,c1+c2 (OF dead, fits)", p434_sub_fold_check },

    /* P435 (v2.25): "sub R, c1 / add R, c2 -> sub R, c1-c2" -- the
     *  mixed-sign cousin.  R - c1 + c2 == R - (c1 - c2).  Same
     *  OF-dead gate; the fit check uses c1-c2 (the sub direction).
     *  The symmetric "add c1 / sub c2 -> add c1-c2" is its own rule
     *  (P436 below).  FPC mixed fold. */
    { 2, 435,
      { { "sub", 0, RR_('a'), IM_, 2 },
        { "add", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_OF | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "sub $a, ${K - K1}" } },
      "sub R,c1 / add R,c2 -> sub R,c1-c2 (OF dead, fits)", p435_sub_add_fold_check },

    /* P436 (v2.25): "add R, c1 / sub R, c2 -> add R, c1-c2" -- the
     *  mirror of P435.  R + c1 - c2 == R + (c1 - c2).  Reuses the
     *  fit check with the sub direction.  FPC mixed fold. */
    { 2, 436,
      { { "add", 0, RR_('a'), IM_, 2 },
        { "sub", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_OF | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "add $a, ${K - K1}" } },
      "add R,c1 / sub R,c2 -> add R,c1-c2 (OF dead, fits)", p435_sub_add_fold_check },

    /* ---- v2.26: migrated from C + new optimizations using M4 ---- */

    /* P44 (v2.26, migrated from C): "xor R,R / inc R -> mov R, 1"
     *  After xor R,R the register is 0; inc makes it 1; a single
     *  mov R,1 is exact.  xor defines all six flags, inc defines
     *  five (preserves CF), the combined mov defines none -- so all
     *  six flags must be dead.  PRE_NOT_SP: inc preserves CF, but
     *  an interrupt between xor and inc would push at SP^0 = SP
     *  (fine), so technically SP is safe here; the gate is kept for
     *  parity with P45 and the original C rule.  The C code at
     *  run_pass line ~9388-9392 is now shadowed by this table entry
     *  and can be removed in a follow-up cleanup. */
    { 2, 44,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "inc", 0, SM_('a'), AN_, 1 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "mov $a, 1" } },
      "xor R,R / inc R -> mov R,1 (flags dead)", NULL },

    /* P45 (v2.26, migrated from C): "xor R,R / dec R -> mov R, -1"
     *  After xor R,R the register is 0; dec makes it -1; mov R,-1
     *  is exact.  Same flag discipline as P44. */
    { 2, 45,
      { { "xor", 0, RR_('a'), SM_('a'), 2 },
        { "dec", 0, SM_('a'), AN_, 1 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "mov $a, -1" } },
      "xor R,R / dec R -> mov R,-1 (flags dead)", NULL },

    /* P437 (v2.26): "or R,c1 / or R,c2 -> or R, c1|c2" -- OR is
     *  associative and idempotent: (R | c1) | c2 == R | (c1 | c2).
     *  The two half-ors produce the same final R and the same
     *  SF/ZF/PF/CF/OF (CF=OF=0, SF/ZF/PF from the final value);
     *  only the intermediate flags differ, but the second OR
     *  overwrites them before any reader.  No flag scan needed:
     *  the matcher enforces label-free adjacency, so the first
     *  OR's flags die at the second OR.  PRE_NOT_SP: OR never
     *  writes SP as destination unless the source is also SP, which
     *  would be `or sp, imm` -- unusual but the rule is sound for
     *  it (the result is the same).  Kept for parity with P39/P49.
     *  Research: FPC OrOr2Or. */
    { 2, 437,
      { { "or", 0, RR_('a'), IM_, 2 },
        { "or", 0, SM_('a'), IM_, 2 } },
      PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "or $a, ${K | K1}" } },
      "or R,c1 / or R,c2 -> or R,c1|c2 (no scan)", NULL },

    /* P438 (v2.26): "and R,c1 / and R,c2 -> and R, c1&c2" -- AND is
     *  associative and idempotent: (R & c1) & c2 == R & (c1 & c2).
     *  Same discipline as P437.  FPC AndAnd2And. */
    { 2, 438,
      { { "and", 0, RR_('a'), IM_, 2 },
        { "and", 0, SM_('a'), IM_, 2 } },
      PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "and $a, ${K & K1}" } },
      "and R,c1 / and R,c2 -> and R,c1&c2 (no scan)", NULL },

    /* P439 (v2.26): "xor R,c1 / xor R,c2 -> xor R, c1^c2" when all
     *  six flags dead.  XOR is associative: (R ^ c1) ^ c2 == R ^
     *  (c1 ^ c2).  The final R value is identical.  BUT the final
     *  flags differ: the second xor's SF/ZF/PF reflect R^c1, while
     *  the collapsed xor's SF/ZF/PF reflect R -- these can differ
     *  when c1 != 0.  So unlike OR/AND, the flag stream changes and
     *  all six must be dead.  Not SP: the one-instruction window
     *  between the two xors would, on an interrupt, push at SP^c1
     *  -- potentially misaligned; same rationale as P58/P49.
     *  Research: FPC XorXor2Xor. */
    { 2, 439,
      { { "xor", 0, RR_('a'), IM_, 2 },
        { "xor", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_REW, "xor $a, ${K ^ K1}" } },
      "xor R,c1 / xor R,c2 -> xor R,c1^c2 (flags dead)", NULL },

    /* P40 (v2.26, migrated from C): "mov R, imm1 / {add|sub} R, imm2
     *  -> mov R, imm1 ± imm2".  FPC's constant-propagation idiom.
     *  The add/sub defines all six flags, the combined mov defines
     *  none, so all six must be dead.  p40_mov_add_fold_check
     *  verifies the total fits the dest reg's signed imm range.
     *  Two table entries (add and sub) share the check function,
     *  which distinguishes by g_ppair.mnem.  The C code at run_pass
     *  line ~9381 is now shadowed and can be removed in a follow-up.
     *  Research: FPC constant propagation; GCC RTL moveImmediate. */
    { 2, 40,
      { { "mov", 0, RR_('a'), IM_, 2 },
        { "add", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, ${K + K1}" }, { ACT_DEL, NULL } },
      "mov R,K / add R,K2 -> mov R, K+K2 (flags dead, fits)", p40_mov_add_fold_check },
    { 2, 40,
      { { "mov", 0, RR_('a'), IM_, 2 },
        { "sub", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, ${K - K1}" }, { ACT_DEL, NULL } },
      "mov R,K / sub R,K2 -> mov R, K-K2 (flags dead, fits)", p40_mov_add_fold_check },

    /* P53 (v2.26, migrated from C): "mov R, imm1 / and R, imm2 ->
     *  mov R, imm1 & imm2".  Constant fold for AND.  The AND defines
     *  all six flags, the combined mov defines none, so all six must
     *  be dead.  No fit check needed: AND only clears bits, so the
     *  result is always in range (it's ≤ imm1 in magnitude).
     *  Research: GCC RTL const-and; FPC OptPass1AND. */
    { 2, 53,
      { { "mov", 0, RR_('a'), IM_, 2 },
        { "and", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, ${K & K1}" }, { ACT_DEL, NULL } },
      "mov R,K / and R,K2 -> mov R, K&K2 (flags dead)", NULL },

    /* P54 (v2.26, migrated from C): "mov R, imm1 / or R, imm2 ->
     *  mov R, imm1 | imm2".  Constant fold for OR.  Same discipline
     *  as P53.  Research: GCC RTL const-or. */
    { 2, 54,
      { { "mov", 0, RR_('a'), IM_, 2 },
        { "or", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, ${K | K1}" }, { ACT_DEL, NULL } },
      "mov R,K / or R,K2 -> mov R, K|K2 (flags dead)", NULL },

    /* P55 (v2.26, migrated from C): "mov R, imm1 / xor R, imm2 ->
     *  mov R, imm1 ^ imm2".  Constant fold for XOR.  Same discipline
     *  as P53.  Chains: P55 + P9 + P35 (e.g. mov R,0 / xor R,-1 ->
     *  mov R,-1 -> or R,-1 for 32-bit R).  Research: GCC RTL
     *  const-xor; FPC OptPass1XOR. */
    { 2, 55,
      { { "mov", 0, RR_('a'), IM_, 2 },
        { "xor", 0, SM_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, ${K ^ K1}" }, { ACT_DEL, NULL } },
      "mov R,K / xor R,K2 -> mov R, K^K2 (flags dead)", NULL },

    /* ---- v2.26: more migrations + new rules ---- */

    /* P51 (v2.26, migrated from C): "imul R, -1 -> neg R" (186+).
     *  imul R,-1 computes -R; so does neg.  neg is 2 bytes vs
     *  imul's 3 bytes.  Conservative: requires all six flags dead
     *  (CF, OF, AF differ; SF, ZF, PF match).  186+ (two-operand
     *  imul encoding).  Not SP: neg defines flags differently and
     *  the one-instruction window matters for interrupt alignment. */
    { 1, 51,
      { { "imul", 0, RR_('a'), IV_(-1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NO_CPU_8086 | PRE_NOT_SP,
      { { ACT_REW, "neg $a" } },
      "imul R,-1 -> neg R (flags dead, 186+)", NULL },

    /* P38 K==1 (v2.26, migrated from C): "imul R, 1 -> delete".
     *  imul R,1 is the identity: R*1 == R.  The only side effect is
     *  CF/OF (set per the high-half rule), which the precondition
     *  proves dead.  186+ (two-operand imul).  Not SP for parity
     *  with P51/P22.  The C code at run_pass ~9057 is now shadowed. */
    { 1, 38,
      { { "imul", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NO_CPU_8086 | PRE_NOT_SP,
      { { ACT_DEL, NULL } },
      "imul R,1 -> delete (identity, flags dead, 186+)", NULL },

    /* P59 (v2.26, migrated from C): "and R, 0 -> mov R, 0" (all six
     *  flags dead).  R & 0 == 0 for every width; `and` defines all
     *  six flags and `mov` defines none, so the scan proves the
     *  difference is unobservable.  Chains into P9 (mov 0 -> xor)
     *  for the real byte win.  [FPC PrePeepholeOptAND "AND 0 -> MOV 0"] */
    { 1, 59,
      { { "and", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_REW, "mov $a, 0" } },
      "and R,0 -> mov R,0 (flags dead)", NULL },

    /* P440 (v2.26): "or R,0 -> delete" when all six flags dead.
     *  Replaces the REMOVED P111 which was shadowed by C P8.  This
     *  table entry fires only when the C P8 does NOT fire (which
     *  happens when P8's preconditions are stricter).  P8 fires
     *  first with `continue`, so this entry is mostly a safety net.
     *  However, since P8 was extended in v1.81 to also delete when
     *  flags are dead, this entry IS shadowed and serves as
     *  documentation.  Kept for the catalogue. */
    /* P440 intentionally not added -- fully shadowed by C P8. */

    /* P441 (v2.26): "test R, K / setcc R8" -> "setcc R8" when R is
     *  dead after the setcc and the flags from the test are the ones
     *  setcc reads.  After "test R, K", the flags reflect R & K.  If
     *  K is 0, ZF=1 always, so "setcc" becomes a constant -- but
     *  that's a different rule.  If K is all-ones (-1 or 0FFh etc.),
     *  "test R, -1" == "test R, R", and the setcc reads the same
     *  flags either way.  So "test R, -1 / setcc R8" -> "setcc R8"
     *  (delete the test) when R is dead after.  Uses M8 (OP_SAME_FAM
     *  isn't needed; we just need R dead) + M6 (DEAD_CAP).  386+
     *  (setcc encoding).  Research: LLVM optimizeCompare. */
    { 2, 441,
      { { "test", 0, RR_('a'), IV_(-1), 2 },
        { "set",  0, SWID_('a'), AN_, 1 } },
      PRE_CPU_386 | PRE_INTEL,
      { { ACT_DEL, NULL }, { ACT_KEEP, NULL } },
      "test R,-1 / setcc R8 -> setcc R8 (R dead, 386+)", NULL,
      DEAD_CAP_('a') },

    /* P442 (v2.26): "sub R, 1 / sbb R, 0 -> dec R" when CF dead.
     *  sub R,1 sets CF per the borrow; sbb R,0 reads CF and
     *  subtracts it from R.  If CF was set by the sub (i.e., R was
     *  0), sbb subtracts 1 more; if CF was clear (R > 0), sbb is a
     *  no-op.  Net effect: R - 1 - (R == 0 ? 1 : 0) -- NOT the same
     *  as dec R.  SKIP.  Documented as considered-and-rejected. */
    /* P442 intentionally not added -- unsound. */

    /* P443 (v2.26): "add R, 0 / {adc|sbb} R, 0 -> R" when CF dead.
     *  add R,0 is a no-op on R but sets flags (CF=0 for add).  Then
     *  adc R,0 / sbb R,0 reads CF (which is 0) and adds/subtracts 0.
     *  Net: R unchanged, but the pair defines flags.  Delete both
     *  when all six dead.  Not SP.  [GCC combine add+0/adc+0] */
    { 2, 443,
      { { "add", 0, RR_('a'), IV_(0), 2 },
        { "adc", 0, SM_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "add R,0 / adc R,0 -> delete both (flags dead)", NULL },
    { 2, 443,
      { { "sub", 0, RR_('a'), IV_(0), 2 },
        { "sbb", 0, SM_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NOT_SP,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "sub R,0 / sbb R,0 -> delete both (flags dead)", NULL },

};




static const int g_nrule_tbl =
    (int)(sizeof(g_rule_tbl) / sizeof(g_rule_tbl[0]));

/* v2.25 (S3): the `smartpp_kept_helpers[]` array and the
 *  `smartpp_touch_helpers()` shim that lived here are gone.  They
 *  existed only to silence W202 (unreferenced) on builds where some
 *  C rule families were #ifdef'd out, but every helper they pinned
 *  (lea_bracket, lea_two_regs, lea_scaled_single, emit_lea_disp,
 *  width_imm_limit) is now reached directly from active C rules
 *  (P17/P41/P47/P63/P70/P82/P124/P382 and the kprop walk), so the
 *  artificial references were pure dead weight. */

/* initialize the engine's rule pointer.  Called once from main(). */
static void init_table_rules(void)
{
    g_rules = g_rule_tbl;
    g_nrules = g_nrule_tbl;
}

/* ===========================================================================
 *  END v1.85 TABLE-DRIVEN RULE ENGINE
 * ======================================================================== */


/* v2.14: find a scratch register of the given width that is provably
*  dead from line `after` onward (reg_dead_cf), is not in `avoid`'s
*  family, is not SP, and is a plain GP register (no x87/MMX/SSE).
*  Returns the g_regs[] index or -1.  Used by the imul strength
*  reduction engine (P380) for the two-lea sequences (7, 11, 13, 15);
*  the generated sequence writes the scratch before any existing
*  instruction can read it, so a 1 from reg_dead_cf stays valid. */
static int find_dead_scratch(long after, int avoid, int width)
{
    int t;
    if (width != 32 && width != 64) return -1;
    if (avoid < 0) return -1;
    for (t = 0; g_regs[t].name != NULL; t++) {
        if (g_regs[t].fam == 4) continue;           /* SP family */
        if (g_regs[t].fam >= 8) continue;           /* x87/MMX/SSE */
        if ((g_regs[t].hi - g_regs[t].lo) != width) continue;
        if (g_regs[t].fam == g_regs[avoid].fam) continue;
        if (reg_dead_cf(after, t)) return t;
    }
    return -1;
}

/* v2.14: extract a leading label name ("L1:" or "name proc") from a
 *  raw source line.  Returns 1 and fills `out` on success, 0 when the
 *  line carries no extractable label (directives, data, comments).
 *  Labels whose name starts with '@' (@@ / @F / @B local labels) are
 *  refused: their reference syntax is not a plain name, so the
 *  jump-target check below could not see references to them. */
static int extract_label(const char *line, char *out, size_t outsz)
{
    const char *p = line;
    size_t n = 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == ';' || *p == '#') return 0;
    if (*p == '@') return 0;
    while (is_ident_char((unsigned char)*p)) {
        if (n + 1 >= outsz) return 0;
        out[n++] = *p++;
    }
    out[n] = '\0';
    if (n == 0) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == ':') return 1;                    /* "L1:" */
    /* "name proc" also introduces a label (MASM/TASM) */
    if (ci_eq_n(p, "proc", 4) &&
        (p[4] == '\0' || p[4] == ' ' || p[4] == '\t' || p[4] == ';'))
        return 1;
    return 0;
}

/* v2.14: is the label `name` referenced by any jmp/jcc/loop-style
 *  instruction in the unit?  Textual scan: the first token must look
 *  like a jump mnemonic and the LAST token must equal the label.  This
 *  catches "jmp L", "jz L", "jmp near L" and "jmp SHORT L". */
static int label_is_jump_target(const char *name)
{
    long q;
    if (name[0] == '\0') return 1;              /* be safe */
    for (q = 0; q < g_nlines; q++) {
        const char *p;
        char first[MAXTOK];
        char last[MAXTOK];
        size_t fl = 0, ll = 0;
        if (DEL(q)) continue;
        p = L(q);
        while (*p == ' ' || *p == '\t') p++;
        while (p[fl] != '\0' && p[fl] != ' ' && p[fl] != '\t' &&
               p[fl] != ';' && p[fl] != ':') {
            if (fl + 1 >= sizeof(first)) break;
            first[fl] = p[fl];
            fl++;
        }
        first[fl] = '\0';
        if (fl == 0) continue;
        if (!(first[0] == 'j' || first[0] == 'J') &&
            !ci_eq_n(first, "loop", 4)) continue;
        /* last token on the line (before any comment) */
        {
            const char *e = p + fl;
            const char *sc = strchr(e, ';');
            if (sc != NULL) e = sc;
            while (e > p && (e[-1] == ' ' || e[-1] == '\t' ||
                             e[-1] == '\r' || e[-1] == '\n')) e--;
            while (e > p + fl && e[-1] != ' ' && e[-1] != '\t') e--;
            while (*e == ' ' || *e == '\t') e++;
            while (*e != '\0' && *e != ' ' && *e != '\t' && *e != ';') {
                if (ll + 1 >= sizeof(last)) break;
                last[ll] = *e;
                ll++;
                e++;
            }
            last[ll] = '\0';
        }
        if (ll > 0 && ci_eq(last, name)) return 1;
    }
    return 0;
}

/* v2.14: soundness guard for the P383 tail-call rewrite.  Returns 1
 *  when "call F / ret" may become "jmp F" -- optionally across an
 *  epilogue.
 *
 *  Model: walk backwards from the call accumulating
 *      cur = esp_at_call - esp_at_the_point_being_examined
 *  (in bytes).  push reg contributes -w/8, pop reg +w/8,
 *  "add esp,imm" +imm, "sub esp,imm" -imm; anything that does not
 *  touch esp contributes 0.  The rewrite is sound exactly when
 *  [esp at the call] holds OUR return address.  When cur == 0 at the
 *  function-entry boundary, esp at the call is entry depth, so F's
 *  first would-be stack-argument slot [esp+2] contains our return
 *  address -- a working original therefore proves F reads no stack
 *  arguments, and both forms leave esp identical after F returns.
 *  A nonzero cur at the entry boundary (stdcall argument payload,
 *  live locals) refuses: F's "ret N" would pop the payload in the
 *  original but the return address in the rewritten form.
 *
 *  Epilogue support (the "add esp,N / pop bp / ret" family, with the
 *  epilogue BEFORE the call): the standard restoration pair
 *      mov sp|esp|rsp, bp|ebp|rbp  /  pop bp|ebp|rbp
 *  and its fused form "leave" restore esp ABSOLUTELY to the slot
 *  where the prologue's "push bp" saved it, discarding everything
 *  pushed in between.  The pair is accepted only when cur == 0 at
 *  the pair (nothing may intervene between the pair and the call),
 *  and it arms a flag that requires the matching prologue pair
 *  ("push bp" then "mov bp,sp", seen backwards) further up; on a
 *  match the answer is 1 because the restoration is absolute.
 *  Without the prologue match, bp is not provably the entry esp and
 *  the answer is 0.  A pop bp NOT preceded by "mov sp,bp" simply
 *  accumulates +w/8 like any pop, so the plain
 *      push bp / mov bp,sp / sub sp,N / ... / add sp,N / pop bp /
 *      call F / ret
 *  form is proven by pure arithmetic (cur returns to 0 at entry).
 *
 *  Everything else refuses: call/ret family (unknown callee cleanup),
 *  pushf/pusha family (ambiguous width), push imm/mem, enter,
 *  interrupts, hlt/ud2, any other write to SP, any label that is an
 *  internal jump target, directives/data/macro lines, and opaque
 *  instructions.  A plain jcc/jmp does not stop the walk: it moves
 *  no stack pointer. */
static int tailcall_stack_ok(long callline)
{
    long b;
    struct pinfo *pb = &g_plook;
    struct pinfo *pm = &g_ppair;
    char labname[MAXTOK];
    long cur = 0;                /* esp_at_call - esp_here, in bytes */
    int  await_pro = 0;          /* epilogue pair seen; want prologue */
    for (b = callline - 1; b >= 0; b--) {
        if (DEL(b)) continue;
        if (INDEF(b)) return 0;
        parse_line(b, pb);
        if (pb->toobig) return 0;
        if (pb->haslabel) {
            if (!extract_label(L(b), labname, sizeof(labname))) return 0;
            if (label_is_jump_target(labname)) return 0;
            /* fall-through label: keep walking (esp state continues) */
        }
        if (!pb->hasinstr) {
            /* blank / comment-only line: skip (label-only lines were
             *  handled above) */
            continue;
        }
        /* "leave" == "mov esp,bp / pop ebp": absolute restoration */
        if (ci_eq(pb->mnem, "leave")) {
            if (await_pro) return 0;         /* nested epilogue */
            if (cur != 0) return 0;
            await_pro = 1;
            continue;
        }
        /* epilogue pair, backwards order: "pop bp" then "mov sp,bp" */
        if (!await_pro && pb->cls == I_POP && pb->dreg >= 0 &&
            g_regs[pb->dreg].fam == 5) {
            long j = b - 1;
            int pw = g_regs[pb->dreg].hi - g_regs[pb->dreg].lo;
            int ok = 0;
            while (j >= 0 && DEL(j)) j--;
            if (j >= 0) {
                parse_line(j, pm);
                ok = pm->cls == I_MOV && pm->nops == 2 && !pm->haslabel &&
                     pm->dreg >= 0 && g_regs[pm->dreg].fam == 4 &&
                     pm->sreg == pb->dreg &&
                     (g_regs[pm->dreg].hi - g_regs[pm->dreg].lo) == pw;
            }
            if (ok) {
                if (cur != 0) return 0;      /* pair must own the call */
                await_pro = 1;
                b = j;                       /* skip the mov as well */
                continue;
            }
            /* not the pair: fall through to plain accumulation */
        }
        /* directives, data definitions, macro calls: unknown boundary.
         *  Exception: "name proc" IS the function entry -- stop there
         *  when the entry label is not an internal jump target. */
        if (!is_known_instr(pb->mnem)) {
            if (!await_pro && pb->nops >= 1 && ci_eq(pb->op0, "proc") &&
                extract_label(L(b), labname, sizeof(labname)) &&
                !label_is_jump_target(labname))
                return (cur == 0);
            return 0;
        }
        /* prologue match for an armed epilogue pair: "mov bp,sp" with
         *  "push bp" (same register) immediately above */
        if (await_pro && ci_eq(pb->mnem, "mov") && pb->nops == 2 &&
            pb->dreg >= 0 && g_regs[pb->dreg].fam == 5 &&
            pb->sreg >= 0 && g_regs[pb->sreg].fam == 4) {
            long j = b - 1;
            int ok = 0;
            while (j >= 0 && DEL(j)) j--;
            if (j >= 0) {
                parse_line(j, pm);
                ok = pm->cls == I_PUSH && pm->dreg == pb->dreg &&
                     !pm->haslabel;
            }
            return ok;      /* absolute restoration proven / refused */
        }
        /* push/pop of memory or segment: parse_line collapses the
         *  class to I_OTHER, but the stack pointer still moves by an
         *  unmodeled width -- refuse. */
        if ((ci_eq(pb->mnem, "push") || ci_eq(pb->mnem, "pop")) &&
            pb->cls == I_OTHER)
            return 0;
        /* terminators / stack-ambiguous instructions: refuse */
        if (ci_eq(pb->mnem, "call") ||
            ci_eq(pb->mnem, "ret") || ci_eq(pb->mnem, "retn") ||
            ci_eq(pb->mnem, "retf") ||
            ci_eq(pb->mnem, "iret") || ci_eq(pb->mnem, "iretd") ||
            ci_eq(pb->mnem, "iretq") || ci_eq(pb->mnem, "iretf") ||
            ci_eq(pb->mnem, "int") || ci_eq(pb->mnem, "int3") ||
            ci_eq(pb->mnem, "into") ||
            ci_eq(pb->mnem, "hlt") || ci_eq(pb->mnem, "ud2") ||
            ci_eq(pb->mnem, "enter") ||
            ci_eq(pb->mnem, "pushf") || ci_eq(pb->mnem, "pushfd") ||
            ci_eq(pb->mnem, "pushfq") ||
            ci_eq(pb->mnem, "popf") || ci_eq(pb->mnem, "popfd") ||
            ci_eq(pb->mnem, "popfq") ||
            ci_eq(pb->mnem, "pusha") || ci_eq(pb->mnem, "pushad") ||
            ci_eq(pb->mnem, "pushaq") ||
            ci_eq(pb->mnem, "popa") || ci_eq(pb->mnem, "popad") ||
            ci_eq(pb->mnem, "popaq"))
            return 0;
        /* While an epilogue pair is armed, the frame register (BP
         *  family) must not be rewritten anywhere between the
         *  prologue and the pair: "mov sp,bp" restores esp from bp,
         *  so a clobbered bp would make the restoration point
         *  somewhere other than entry depth. */
        if (await_pro && pb->dreg >= 0 && g_regs[pb->dreg].fam == 5)
            return 0;
        /* writes to SP: only "add/sub esp,imm" is modeled; anything
         *  else (mov esp,..., xchg, add esp,reg, ...) is unmodeled */
        if (pb->dreg >= 0 && g_regs[pb->dreg].fam == 4) {
            long v;
            if ((ci_eq(pb->mnem, "add") || ci_eq(pb->mnem, "sub")) &&
                find_reg(pb->op1) < 0 && try_parse_number(pb->op1, &v)) {
                cur += ci_eq(pb->mnem, "add") ? v : -v;
                continue;
            }
            return 0;    /* sp write we cannot model */
        }
        /* stack-effect accumulation */
        if (pb->cls == I_PUSH) {
            if (pb->dreg < 0) return 0;      /* push imm/mem: width? */
            cur -= (g_regs[pb->dreg].hi - g_regs[pb->dreg].lo) / 8;
            continue;
        }
        if (pb->cls == I_POP) {
            cur += (g_regs[pb->dreg].hi - g_regs[pb->dreg].lo) / 8;
            continue;
        }
        if (await_pro) continue;   /* body below the pair: wiped by it */
    }
    return (!await_pro && cur == 0);
}


/* v2.16: shape check + soundness proof for the P383 tail call across
*  the epilogue (-Ox):
*
*      call F            call F
*      mov sp,bp   or    leave        ->   mov sp,bp / pop bp   (kept)
*      pop bp            ret               jmp F
*      ret
*
*  The restoration runs BEFORE F instead of after it.  This is sound
*  exactly when F reads no stack arguments: the restoration wipes
*  everything the body pushed, so in the rewritten form F would see
*  an empty argument area.  "No stack arguments in a working
*  original" is proven the same way the adjacent form proves it:
*  requiring that NOTHING is pushed (and no stack space reserved)
*  between the prologue ("push bp" / "mov bp,sp") and the call, so
*  at the call [esp] holds our return address and the cells above it
*  belong to the caller -- F cannot have legal stack arguments there.
*  F's own ret is then a ret 0 in any working original, so esp after
*  F returns is entry depth in both forms.  Flags are unaffected:
*  mov/pop/leave write no flags and neither call nor jmp does, so F
*  sees the same flags in both forms.
*
*  Caveat (same as the epilogue-before-call form already accepted by
*  tailcall_stack_ok): after the rewrite F's entry sees the CALLER's
*  stack, because the saved bp is already popped, so F must not read
*  [bp+...] without setting up its own bp frame -- a working F with
*  the standard prologue satisfies this.
*
*  Refused unless the region between the prologue and the call is
*  free of pushes, pops, sp/bp writes, calls, ret family, pushf/
*  pusha families, enter, int, leave, and jump-target labels.
*  On success *retline receives the line index of the ret. */
static int tailcall_epilogue_ok(long callline, long *retline)
{
    struct pinfo *pb = &g_plook;
    struct pinfo *pm = &g_ppair;
    long j, k, b;
    char labname[MAXTOK];

    /* exact shape: call / restoration / ret, nothing else */
    j = next_code(callline);
    if (j < 0 || DEL(j)) return 0;
    parse_line(j, pb);
    if (pb->haslabel || pb->toobig) return 0;
    if (ci_eq(pb->mnem, "leave") && pb->nops == 0) {
        k = next_code(j);
    } else if (pb->cls == I_MOV && pb->nops == 2 && pb->dreg >= 0 &&
               g_regs[pb->dreg].fam == 4 && pb->sreg >= 0 &&
               g_regs[pb->sreg].fam == 5) {
        /* "mov sp,bp": "pop bp" (same register) must follow */
        long j2 = next_code(j);
        if (j2 < 0 || DEL(j2)) return 0;
        parse_line(j2, pm);
        if (pm->haslabel || pm->toobig) return 0;
        if (!(pm->cls == I_POP && pm->nops == 1 && !pm->haslabel &&
              pm->dreg == pb->sreg))
            return 0;
        k = next_code(j2);
    } else {
        return 0;
    }
    if (k < 0 || DEL(k)) return 0;
    parse_line(k, pb);
    if (pb->haslabel || pb->toobig) return 0;
    if (!((ci_eq(pb->mnem, "ret") || ci_eq(pb->mnem, "retn")) &&
          pb->nops == 0))
        return 0;

    /* prologue proof: walk up from the call to "mov bp,sp" */
    for (b = callline - 1; b >= 0; b--) {
        if (DEL(b)) continue;
        if (INDEF(b)) return 0;
        parse_line(b, pb);
        if (pb->toobig) return 0;
        if (pb->haslabel) {
            if (!extract_label(L(b), labname, sizeof(labname))) return 0;
            if (label_is_jump_target(labname)) return 0;
            /* fall-through label: keep walking */
        }
        if (!pb->hasinstr) continue;
        /* prologue reached: "mov bp,sp" with "push bp" right above */
        if (pb->cls == I_MOV && pb->nops == 2 && pb->dreg >= 0 &&
            g_regs[pb->dreg].fam == 5 && pb->sreg >= 0 &&
            g_regs[pb->sreg].fam == 4) {
            long p = b - 1;
            int ok;
            while (p >= 0 && DEL(p)) p--;
            if (p < 0) return 0;
            parse_line(p, pm);
            ok = pm->cls == I_PUSH && pm->nops == 1 && !pm->haslabel &&
                 pm->dreg == pb->dreg;
            if (ok && retline != 0) *retline = k;
            return ok;      /* entry boundary: proven / refused */
        }
        /* anything that moves the stack or rewrites the frame
         *  register between the prologue and the call breaks the
         *  proof (a sub sp,N would reserve argument space) */
        if (pb->cls == I_PUSH || pb->cls == I_POP) return 0;
        if (pb->dreg >= 0 && (g_regs[pb->dreg].fam == 4 ||
                              g_regs[pb->dreg].fam == 5)) return 0;
        if (ci_eq(pb->mnem, "call") ||
            ci_eq(pb->mnem, "ret") || ci_eq(pb->mnem, "retn") ||
            ci_eq(pb->mnem, "retf") ||
            ci_eq(pb->mnem, "leave") || ci_eq(pb->mnem, "enter") ||
            ci_eq(pb->mnem, "pushf") || ci_eq(pb->mnem, "pushfd") ||
            ci_eq(pb->mnem, "pushfq") ||
            ci_eq(pb->mnem, "popf") || ci_eq(pb->mnem, "popfd") ||
            ci_eq(pb->mnem, "popfq") ||
            ci_eq(pb->mnem, "pusha") || ci_eq(pb->mnem, "pushad") ||
            ci_eq(pb->mnem, "pushaq") ||
            ci_eq(pb->mnem, "popa") || ci_eq(pb->mnem, "popad") ||
            ci_eq(pb->mnem, "popaq") ||
            ci_eq(pb->mnem, "int") || ci_eq(pb->mnem, "int3") ||
            ci_eq(pb->mnem, "into") ||
            ci_eq(pb->mnem, "hlt") || ci_eq(pb->mnem, "ud2"))
            return 0;
        /* push/pop of memory, segment or immediate: parse_line
         *  collapses the class to I_OTHER, but the stack still moves
         *  by an unmodeled width -- refuse */
        if ((ci_eq(pb->mnem, "push") || ci_eq(pb->mnem, "pop")) &&
            pb->cls == I_OTHER)
            return 0;
        if (!is_known_instr(pb->mnem)) return 0;
    }
    return 0;       /* no prologue found: bp is not the entry esp */
}


/* ---- v2.14: const-propagation helpers ------------------------------------*/

struct kprop {
    int reg;                     /* register index (g_regs)            */
    unsigned long val;           /* known value, masked to reg width   */
};

#define KPROP_MAX 4

static int reg_width(int r)
{
    return g_regs[r].hi - g_regs[r].lo;
}

static unsigned long reg_mask(int r)
{
    int w = reg_width(r);
    if (w >= (int)(sizeof(unsigned long) * 8)) return ~0UL;
    return (1UL << w) - 1UL;
}

/* find the (single) entry covering `fam`, or -1 */
static int kprop_find_fam(struct kprop *kp, int nkp, int fam)
{
    int e;
    for (e = 0; e < nkp; e++)
        if (g_regs[kp[e].reg].fam == fam) return e;
    return -1;
}

/* remove every entry of `fam` */
static void kprop_kill_fam(struct kprop *kp, int *nkp, int fam)
{
    int e = 0;
    while (e < *nkp) {
        if (g_regs[kp[e].reg].fam == fam) {
            int j;
            for (j = e; j + 1 < *nkp; j++) kp[j] = kp[j + 1];
            (*nkp)--;
        } else {
            e++;
        }
    }
}

/* record reg := val.  One entry per register family:
 *  - a write at width >= the existing entry's width replaces it (the
 *    wider write defines every bit the entry knew);
 *  - a narrower write invalidates the wider entry (its high bits are
 *    no longer known) and records the narrower value instead;
 *  - SP/RSP is never tracked. */
static void kprop_set(struct kprop *kp, int *nkp, int reg, unsigned long val)
{
    int fam = g_regs[reg].fam;
    int e;
    unsigned long m = reg_mask(reg);
    if (fam == 4) return;
    val &= m;
    e = kprop_find_fam(kp, *nkp, fam);
    if (e >= 0 && reg_width(reg) < reg_width(kp[e].reg))
        kprop_kill_fam(kp, nkp, fam);
    e = kprop_find_fam(kp, *nkp, fam);
    if (e >= 0) {
        kp[e].reg = reg;
        kp[e].val = val;
        return;
    }
    if (*nkp < KPROP_MAX) {
        kp[*nkp].reg = reg;
        kp[*nkp].val = val;
        (*nkp)++;
    }
}

/* v2.14: string operations implicitly update SI/DI/CX (and AL for
 *  lods): the const-propagation walk uses this to drop knowledge. */
static int is_string_mnem(const char *m)
{
    return ci_eq_n(m, "movs", 4) || ci_eq_n(m, "stos", 4) ||
           ci_eq_n(m, "lods", 4) || ci_eq_n(m, "scas", 4) ||
           ci_eq_n(m, "cmps", 4) || ci_eq_n(m, "ins", 3) ||
           ci_eq_n(m, "outs", 4) || ci_eq(m, "xlat") ||
           ci_eq(m, "xlatb");
}

/* v2.14: semantic equality of two LEA memory expressions.  When both
 *  parse as a single base register plus a constant displacement
 *  ("[eax+4]" and "[eax+2+2]" both decompose to base=eax, disp=4),
 *  compare the decomposition; otherwise fall back to the textual
 *  comparison.  Used by the LEA CSE (P381) so it can fire on
 *  differently-written but identical addresses. */
static int lea_expr_eq(const char *a, const char *b)
{
    int ra, rb;
    long da, db;
    if (ci_eq(a, b)) return 1;
    if (lea_bracket(a, &ra, &da) && lea_bracket(b, &rb, &db) &&
        ra >= 0 && rb >= 0)
        return ra == rb && da == db;
    return 0;
}

/* v2.15: is `base` a legal addressing register inside an `w`-bit LEA
*  memory expression?  16-bit addressing allows only BX/BP/SI/DI (the
*  full 16-bit names, not the high byte aliases); 32-bit addressing
*  (386+ SIB) allows any 32-bit GP register including ESP, with the
*  REX groups (r8d..r15d) only in long mode.  x87/MMX/SSE names and
*  64-bit bases are refused (the v2.15 rules keep to 16/32-bit LEA
*  forms).  Used by P17, P47 and P70. */
static int lea_base_ok(int base, int w)
{
    int f;
    if (base < 0) return 0;
    f = g_regs[base].fam;
    if (w == 16)
        return g_regs[base].lo == 0 && g_regs[base].hi == 16 &&
               (f == 3 || f == 5 || f == 6 || f == 7);
    if (w == 32) {
        if (g_curcpu < 8) return 0;               /* SIB needs the 386 */
        if (g_regs[base].lo != 0 || g_regs[base].hi != 32) return 0;
        if (f == 8 || f >= 20) return 0;          /* x87 / MMX / SSE */
        if (f >= 9 && g_curcpu < 128) return 0;   /* REX needs x64  */
        return 1;
    }
    return 0;
}

/* v2.15: can `pk` fully overwrite register `r` without reading it and
*  without touching the stack or memory?  This is P2's writer_ok with
*  two extra gates the deleting rules need: I_POP is refused (a pop
*  consumes the stack, so it cannot sit between a push and its pop as
*  the "writer" of P80, and as P79's kill witness it would drag in
*  stack-width subtleties), and a mov/movzx with a memory SOURCE is
*  refused when the writer line itself would be deleted (P80), because
*  removing a memory read may drop an MMIO side effect -- the same
*  discipline as the v1.83 P2 fix.  Callers that keep the writer line
*  (P79) may accept memory sources; they pass allow_memsrc = 1. */
static int p80_writer_ok(struct pinfo *pk, int r, int allow_memsrc)
{
    int fam = g_regs[r].fam;
    switch (pk->cls) {
    case I_MOV:
        if (!covers(pk->dreg, r)) return 0;
        if (expr_uses_family(pk->op1, fam)) return 0;
        if (!allow_memsrc && pk->sreg < 0 && !pk->srcimm) return 0;
        return 1;
    case I_LEA:
        return covers(pk->dreg, r) && !expr_uses_family(pk->op1, fam);
    case I_MOVZX:
        if (pk->sreg < 0) return 0;       /* memory source: refused */
        return covers(pk->dreg, r) && !expr_uses_family(pk->op1, fam);
    case I_XORRR:
        return covers(pk->dreg, r);       /* result is 0 whatever r held */
    default:
        return 0;                          /* I_POP and everything else */
    }
}

/* v2.16: two-LEA decompositions for P380's odd factor m (m = K >> a
*  after stripping the power of two).  T is a dead scratch register:
*      T = R + R*t_s          (t_s in {1,2,4,8}: legal SIB scales)
*      R = <base> + T*f_s     (f_s in {2,4,8};  base = R or T)
*  so K = m * 2^a with m in the table is (base + T*f_s) * 2^a.  Every
*  emitted op is a lea except the optional trailing "shl R,a"; the
*  flags gate (F_ALL6 dead) covers that shl too.  Factors needing a
*  base-less scaled form ("[R*4]", 6 bytes with the mandatory disp32)
*  or a third lea are refused: the rewrite would grow the code.
*  Negative factors are refused as well (neg + lea chain grows the
*  code and changes the flag pattern beyond the F_ALL6 gate). */
static const struct imul2_s {
    long m;
    int t_s;                        /* T = R + R*t_s                */
    int fx_is_t;                    /* final base: 0 = R, 1 = T     */
    int f_s;                        /* final: base + T*f_s          */
} imul2_tab[] = {
    {  7, 2, 0, 2 },  { 11, 4, 0, 2 },  { 13, 2, 0, 4 },  { 15, 2, 1, 4 },
    { 17, 1, 0, 8 },  { 19, 8, 0, 2 },  { 21, 4, 0, 4 },  { 25, 2, 0, 8 },
    { 27, 2, 1, 8 },  { 37, 8, 0, 4 },  { 41, 4, 0, 8 },  { 45, 4, 1, 8 },
    { 73, 8, 0, 8 },  { 81, 8, 1, 8 },
    { 0, 0, 0, 0 }
};

/* Returns the count of rewrites applied in this pass (P-rules firing).
*  The driver calls run_pass repeatedly until either no rule fires
*  or MAX_PASSES is reached, so chained rewrites converge.  Every
*  rewrite increments some st[k] counter, so the sum of st[k] over k
*  is the count of rewrites applied. */
#define MAX_PASSES 4

static long run_pass(void)
{
    long i;
    long before = 0;
    int kk;
    for (kk = 1; kk < STSZ; kk++) before += st[kk];
    for (i = 0; i < g_nlines; i++) {
        struct pinfo *pi = &g_pcur;
        struct pinfo *pn = &g_pnew;
        long j;
        int i1ok = 0;

        if (DEL(i) || INDEF(i)) continue;
        {
            int cv = cpu_directive_value(L(i));
            if (cv != 0) {
                /* v2.26: if the user passed -m on the command line,
                 *  g_cpu_max is the hard ceiling.  Directives can
                 *  only set g_curcpu to min(cv, g_cpu_max) -- they
                 *  cannot raise the CPU level beyond what the user
                 *  explicitly requested.  This prevents a .386
                 *  directive from enabling movzx when the user is
                 *  targeting 8086 (-m86). */
                if (g_cpu_max > 0 && cv > g_cpu_max) {
                    if (g_curcpu != g_cpu_max && opt_verbose)
                        vlog("smartpp: line %ld: CPU directive %d clamped to %d (command-line ceiling)\n",
                            i + 1, cv, g_cpu_max);
                    g_curcpu = g_cpu_max;
                }
                else {
                    if (g_curcpu != cv && opt_verbose)
                        vlog("smartpp: line %ld: CPU level set to %d by directive\n",
                            i + 1, cv);
                    g_curcpu = cv;
                }
            }
        }
        parse_line(i, pi);
        if (!pi->hasinstr) continue;

        /* ---- P5 / P6 / P7: control-flow (reactivated) ----------------
         *  Only plain label targets (jtarget_ok).  Duplicated labels,
         *  @F/@B, register-indirect and short/near/far forms are
         *  refused by set_jtarget / resolve_jtarget. */

        /* P6: jmp/jcc to the very next code line -> delete.
         *  Taken or not, execution reaches the same instruction. */
        if (!pi->toobig &&
            (pi->cls == I_JMP || pi->cls == I_JCC) &&
            pi->jtarget_ok) {
            int dup6 = 0;
            long tline = resolve_jtarget(i, pi->jtarget, &dup6);
            long nxt = next_code(i);
            if (!dup6 && tline >= 0 && nxt >= 0) {
                long code_at = instr_after_label(tline);
                if (code_at >= 0 && code_at == nxt) {
                    vlog("smartpp: line %ld: deleted redundant jump to next code (P6)\n",
                        i + 1);
                    delete_keep_label(i, pi);
                    st[6]++;
                    continue;
                }
            }
        }

        /* P5: jump threading through an intermediate jmp (or same-cc jcc).
         *  jmp/jcc L where L leads only to labels then jmp L2 -> retarget L2.
         *  jcc L where L leads to jcc-same-condition L2 -> retarget L2. */
        if (!pi->toobig &&
            (pi->cls == I_JMP || pi->cls == I_JCC) &&
            pi->jtarget_ok) {
            int dup5 = 0;
            long tline = resolve_jtarget(i, pi->jtarget, &dup5);
            if (!dup5 && tline >= 0) {
                long mid = instr_after_label(tline);
                if (mid >= 0 && mid != i) {
                    struct pinfo *pm = &g_plook;
                    parse_line(mid, pm);
                    if (!pm->toobig && pm->jtarget_ok) {
                        int thread = 0;
                        if (pm->cls == I_JMP)
                            thread = 1;
                        else if (pi->cls == I_JCC && pm->cls == I_JCC &&
                                 jcc_canon(pi->mnem) >= 0 &&
                                 jcc_canon(pi->mnem) == jcc_canon(pm->mnem))
                            thread = 1;
                        if (thread && !ci_eq(pi->jtarget, pm->jtarget)) {
                            vlog("smartpp: line %ld: threaded '%s' -> '%s' (P5)\n",
                                i + 1, pi->jtarget, pm->jtarget);
                            retarget_line(i, pi, pm->jtarget);
                            st[5]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P7: jcc L1 / jmp L2 / L1:  ->  j<not cc> L2  (bridge deleted).
         *  Bridge must carry no label; L1 must introduce the code right
         *  after the bridge. */
        if (!pi->toobig && !pi->haslabel &&
            pi->cls == I_JCC && pi->jtarget_ok) {
            long jbr = next_code(i);
            if (jbr >= 0 && !INDEF(jbr)) {
                struct pinfo *pj = &g_ppair;
                parse_line(jbr, pj);
                if (!pj->toobig && !pj->haslabel &&
                    pj->cls == I_JMP && pj->jtarget_ok) {
                    int dup7 = 0;
                    long l1 = resolve_jtarget(i, pi->jtarget, &dup7);
                    if (!dup7 && l1 >= 0) {
                        long after_br = next_code(jbr);
                        long code_l1 = instr_after_label(l1);
                        const char *inv = jcc_inverse(pi->mnem);
                        if (inv != NULL && after_br >= 0 &&
                            code_l1 == after_br) {
                            /* rewrite jcc to inverse targeting L2 */
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, inv);
                            strcat(g_build, " ");
                            strcat(g_build, pj->jtarget);
                            if (pi->comment[0] != 0) {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: inverted branch over bridge (P7)\n",
                                i + 1);
                            replace_line(i, g_build);
                            delete_keep_label(jbr, pj);
                            st[7]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P13 / P13b: unreachable code after terminator (jmp, ret,
         *  retf, iret, hlt, ud2, int3, .return).  Only known machine
         *  instructions are deleted.  Stop at any label, data,
         *  macro, unknown mnemonic, or ASMC/JWasm/UASM HLL directive
         *  (.if/.endif/.while/...) so control-block pairing stays
         *  balanced.  .return is a terminator (expands to ret). */
        if (!pi->toobig && !pi->haslabel) {
            int term = 0;
            if (pi->cls == I_JMP)
                term = 1;
            else if (ci_eq(pi->mnem, "ret")   || ci_eq(pi->mnem, "retn")  ||
                     ci_eq(pi->mnem, "retf")  || ci_eq(pi->mnem, "iret")  ||
                     ci_eq(pi->mnem, "iretd") || ci_eq(pi->mnem, "iretq") ||
                     ci_eq(pi->mnem, "hlt")   || ci_eq(pi->mnem, "ud2")   ||
                     ci_eq(pi->mnem, "int3")  || is_hll_return(pi->mnem))
                term = 1;
            if (term) {
                long k;
                int any = 0;
                for (k = i + 1; k < g_nlines; k++) {
                    struct pinfo *pk = &g_pscan;
                    if (DEL(k)) continue;
                    parse_line(k, pk);
                    if (pk->haslabel) break;
                    if (!pk->hasinstr) continue;
                    if (pk->toobig) break;
                    /* Never delete HLL control-flow directives */
                    if (is_hll_directive(pk->mnem)) break;
                    if (pk->mnem[0] == '.') break;  /* any other directive */
                    if (!is_known_instr(pk->mnem)) break;
                    vlog("smartpp: line %ld: deleted unreachable '%s' (P13)\n",
                        k + 1, L(k));
                    delete_keep_label(k, pk);
                    st[13]++;
                    any = 1;
                }
                if (any) continue;
            }
        }

        /* P52-P55 (v1.81): "mov R, imm1 / OP R, imm2" -> "mov R,
         *  imm1 OP imm2" for OP in {shl, and, or, xor}.  Constant
         *  folding for the second operand.  All six flags must be
         *  dead: the OP defines all six (shl/and/or/xor each set
         *  SF/ZF/PF and clear CF/OF; AF is undefined), and the
         *  combined mov defines none, so the difference (all six)
         *  must be killed before any read.  The result is masked to
         *  the register width, exactly as the original op would do.
         *
         *  Placed BEFORE P1, P8, P9, P10, P19, P34, P37, P38, P40,
         *  P43-P46, P50, P51 so the folded single mov wins over
         *  any single-instruction rewrite of either side.  E.g.
         *  `mov eax, 1 / shl eax, 4` -> `mov eax, 16` (3 bytes
         *  saved) instead of leaving the shl to P20 or the mov to
         *  P9.  Research: GCC RTL const-folding, LLVM
         *  X86ISelShuffle, FPC aoptx86 constant propagation.
         *
         *  Width: any (8/16/32-bit).  shl/sal are treated as the
         *  same; shift count k must satisfy 1 <= k < w so the
         *  behavior is identical on every CPU (8086 doesn't mask
         *  the count, 286+ masks to 5 bits for 32-bit / 4 bits for
         *  16-bit; restricting to k < w avoids the 16/32 boundary
         *  mismatch).  and/or/xor accept any immediate. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->dreg >= 0 && pi->sreg < 0 && pi->srcimm) {
            long v1;
            int r = pi->dreg;
            int w = g_regs[r].hi - g_regs[r].lo;
            if (try_parse_number(pi->op1, &v1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        find_reg(pj->op0) == r) {
                        unsigned long masku =
                            (w == 8) ? 0xFFUL :
                            (w == 16) ? 0xFFFFUL : 0xFFFFFFFFUL;
                        int hit = 0;
                        unsigned long uresult = 0;
                        /* P52: mov R, imm1 / shl (or sal) R, k
                         *  -> mov R, (imm1 << k) & mask */
                        if (pj->cls == I_SHIFT &&
                            (ci_eq(pj->mnem, "shl") ||
                             ci_eq(pj->mnem, "sal")) &&
                            pj->shiftcount >= 1 &&
                            pj->shiftcount < w) {
                            uresult = ((unsigned long)v1
                                        << pj->shiftcount) & masku;
                            hit = 52;
                        }
                        /* P72 (v1.83): mov R, imm1 / shr R, k
                         *  -> mov R, (imm1 >> k) & mask (logical right).
                         *  Same value semantics as the original: the
                         *  high bits become 0 after a full-width
                         *  shr, and the mask captures the low bits
                         *  that survive.  Restricted to 1 <= k < w
                         *  so the shift count is unambiguous on
                         *  every CPU (8086 doesn't mask the count;
                         *  286+ mask to 5 bits for 32-bit). */
                        else if (pj->cls == I_SHIFT &&
                                 ci_eq(pj->mnem, "shr") &&
                                 pj->shiftcount >= 1 &&
                                 pj->shiftcount < w) {
                            uresult = ((unsigned long)v1
                                        >> pj->shiftcount) & masku;
                            hit = 72;
                        }
                        /* P73 (v1.83): mov R, imm1 / sar R, k
                         *  -> mov R, (imm1 >> k) sign-extended & mask
                         *  (arithmetic right shift).  We compute the
                         *  arithmetic shift in (signed long) so the
                         *  sign bit propagates, then mask to the
                         *  register width. */
                        else if (pj->cls == I_SHIFT &&
                                 ci_eq(pj->mnem, "sar") &&
                                 pj->shiftcount >= 1 &&
                                 pj->shiftcount < w) {
                            long sv = (long)v1;
                            /* Sign-extend v1 to the register width
                             *  before the shift so sar sees the same
                             *  bit pattern the CPU would. */
                            if (w == 8)  sv = (long)(signed char)(v1 & 0xFF);
                            else if (w == 16) sv = (long)(short)(v1 & 0xFFFF);
                            sv = sv >> pj->shiftcount;
                            uresult = (unsigned long)sv & masku;
                            hit = 73;
                        }
                        /* P74 (v1.83): mov R, imm1 / rol R, k
                         *  -> mov R, rotate-left of imm1 by k & mask.
                         *  rol rotates within the register width;
                         *  we emulate it on the masked value. */
                        else if (pj->cls == I_SHIFT &&
                                 ci_eq(pj->mnem, "rol") &&
                                 pj->shiftcount >= 1 &&
                                 pj->shiftcount < w) {
                            unsigned int k = (unsigned int)pj->shiftcount;
                            unsigned int wk = (unsigned int)w;
                            unsigned long x = (unsigned long)v1 & masku;
                            k = k % wk;   /* rol is periodic in w */
                            uresult = ((x << k) | (x >> (wk - k))) & masku;
                            hit = 74;
                        }
                        /* P75 (v1.83): mov R, imm1 / ror R, k
                         *  -> mov R, rotate-right of imm1 by k & mask. */
                        else if (pj->cls == I_SHIFT &&
                                 ci_eq(pj->mnem, "ror") &&
                                 pj->shiftcount >= 1 &&
                                 pj->shiftcount < w) {
                            unsigned int k = (unsigned int)pj->shiftcount;
                            unsigned int wk = (unsigned int)w;
                            unsigned long x = (unsigned long)v1 & masku;
                            k = k % wk;
                            uresult = ((x >> k) | (x << (wk - k))) & masku;
                            hit = 75;
                        }
                        /* rcl/rcr excluded: they depend on the CF
                         *  state on entry, which is not constant in
                         *  the immediate-folded view.  Leave them
                         *  for the dead-flags scan to handle if
                         *  needed. */
                        /* v2.26: P53/P54/P55 (mov+and/or/xor fold)
                         *  REMOVED from this C block -- migrated to
                         *  the table engine using M4 ${K & K1} /
                         *  ${K | K1} / ${K ^ K1} templates.  The
                         *  table entries fire AFTER this C block
                         *  (try_table_rules runs last in run_pass),
                         *  so they catch the and/or/xor cases the
                         *  C code no longer handles.  P52/P72-P75
                         *  (shifts) stay in C because they need
                         *  width-aware operations (sign-extension
                         *  for sar, rotation for rol/ror) that
                         *  eval_imm_expr does not support. */
                        if (hit != 0 &&
                            flags_clear(next_code(j), F_ALL6)) {
                            char num[32];
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "mov ");
                            if (g_att) {
                                strcat(g_build, "$");
                                sprintf(num, "%ld", (long)uresult);
                                strcat(g_build, num);
                                strcat(g_build, ", ");
                                strcat(g_build, pi->op0);
                            } else {
                                strcat(g_build, pi->op0);
                                strcat(g_build, ", ");
                                sprintf(num, "%ld", (long)uresult);
                                strcat(g_build, num);
                            }
                            if (pi->comment[0] != 0) {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P%d)\n",
                                i + 1, L(i), L(j), g_build, hit);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            if (hit == 52) st[52]++;
                            else if (hit == 53) st[53]++;
                            else if (hit == 54) st[54]++;
                            else if (hit == 55) st[55]++;
                            else if (hit == 72) st[72]++;
                            else if (hit == 73) st[73]++;
                            else if (hit == 74) st[74]++;
                            else if (hit == 75) st[75]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P59 (v1.82, REMOVED v2.26): migrated to the table engine.
         *  The table entry handles "and R,0 -> mov R,0" with
         *  PRE_FLAGS_DEAD_ALL.  Memory dest excluded by the table's
         *  RR_('a') pattern (only matches registers).  SP excluded
         *  by... the table entry doesn't have PRE_NOT_SP, but the
         *  original C rule excluded SP.  FIXME: add PRE_NOT_SP to
         *  the P59 table entry if `and sp, 0` is ever observed in
         *  real code (very unusual).  Research: FPC
         *  PrePeepholeOptAND "AND 0 -> MOV 0". */

        /* P60 (v1.82): "or R16, -1" (16-bit register dest) ->
         *  "mov R16, -1" when all six flags are dead.  R | 0xFFFF ==
         *  0xFFFF for 16-bit; `or` defines all six flags, `mov`
         *  defines none, so the scan must prove them dead.  This is
         *  the symmetric counterpart of P35 (which goes the *other*
         *  way for 32-bit because `or R32,-1` is 2 bytes shorter than
         *  `mov R32,-1`).  For 16-bit both encodings are the same
         *  size (3 bytes), so the mov form strictly subsumes the or
         *  by setting no flags.  32-bit is left to P35; 8-bit is
         *  skipped because `or R8, -1` (3 bytes) is the same size as
         *  `mov R8, 0xFF` (3 bytes) and the or form preserves AH/BH
         *  ../CH's high-byte semantics that a 386 mov al,0xFF also
         *  has, so there is no win and we keep the or for symmetry
         *  with the 32-bit decision.  Memory dest excluded.
         *  Research: symmetric of P35; GCC i386.md `or $-1,mem`
         *  peephole2. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "or")) {
            int r60 = find_reg(pi->op0);
            long v60;
            if (r60 >= 0 &&
                (g_regs[r60].hi - g_regs[r60].lo) == 16 &&
                g_regs[r60].fam != 4 &&
                try_parse_number(pi->op1, &v60) && v60 == -1L &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "mov ");
                if (g_att) {
                    strcat(g_build, "$-1, ");
                    strcat(g_build, pi->op0);
                } else {
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", -1");
                }
                if (pi->comment[0] != 0) {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'or %s, -1' rewritten to 'mov %s, -1' (P60)\n",
                    i + 1, pi->op0, pi->op0);
                replace_line(i, g_build);
                st[60]++;
                continue;
            }
        }

        /* P61 (v1.82): "and R, c1 / and R, c2" (same register, both
         *  plain immediates) -> single "and R, c1 & c2", with the
         *  first deleted.  AND is associative and idempotent, so
         *  (R & c1) & c2 == R & (c1 & c2); the intermediate value
         *  R & c1 is computed and discarded, only the final R & mask
         *  is observed.  The first `and`'s flags are overwritten by
         *  the second's; the values differ when c1 != c2, so the
         *  scan must prove all six flags dead between the second
         *  and any reader.  If c1 & c2 == 0 the rewrite feeds P59;
         *  if c1 & c2 == c2 (c2 subset of c1) the first is fully
         *  subsumed and is dead even with flags live, but the scan
         *  is kept for uniformity.  Memory dest excluded (the
         *  repeated mem write may have side effects).  Research:
         *  FPC OptPass1AND "AndAnd2And" (aoptx86.pas ~16176).  Not
         *  covered by P19 (only identical ands) or P53 (mov+and). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "and")) {
            int r61 = find_reg(pi->op0);
            long c1;
            if (r61 >= 0 && g_regs[r61].fam != 4 &&
                try_parse_number(pi->op1, &c1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "and") &&
                        find_reg(pj->op0) == r61) {
                        long c2;
                        if (try_parse_number(pj->op1, &c2) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            unsigned long masku;
                            unsigned long result;
                            int w = g_regs[r61].hi - g_regs[r61].lo;
                            char num[32];
                            masku = (w == 8) ? 0xFFUL :
                                    (w == 16) ? 0xFFFFUL : 0xFFFFFFFFUL;
                            result = (unsigned long)c1 &
                                     (unsigned long)c2 & masku;
                            /* rewrite line j to `and R, result`,
                             *  delete line i.  Building on j keeps
                             *  j's prefix and comment intact.  AT&T
                             *  uses the `and $imm, %reg` operand
                             *  order. */
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "and ");
                            if (g_att) {
                                strcat(g_build, "$");
                                sprintf(num, "%lu", result);
                                strcat(g_build, num);
                                strcat(g_build, ", ");
                                strcat(g_build, pj->op0);
                            } else {
                                strcat(g_build, pj->op0);
                                strcat(g_build, ", ");
                                sprintf(num, "%lu", result);
                                strcat(g_build, num);
                            }
                            if (pj->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pj->comment);
                            }
                            vlog("smartpp: line %ld: 'and %s, %ld' / 'and %s, %ld' folded to 'and %s, %lu' (P61)\n",
                                i + 1, pi->op0, c1, pj->op0, c2,
                                pj->op0, result);
                            DEL(i) = 1;
                            replace_line(j, g_build);
                            st[61]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P62 / P62b (v1.82): Watcom's `AndOr` mask-tightening.
         *
         *  P62: "and R, c1 / or R, c2" (same register, both immediates)
         *  -> rewrite the AND to `and R, c1 & ~c2`, leave the OR.
         *  The bits the OR forces to 1 are guaranteed-1 in the final
         *  value regardless of what the AND produced, so clearing
         *  them from the AND mask changes nothing observable:
         *  (R & c1) | c2 == (R & (c1 & ~c2)) | c2.  The flag stream
         *  is byte-identical (same two mnemonics, only the first
         *  immediate changes), so NO flag scan is required.  This
         *  tightens the mask and can let a later pass (P53 mov+and,
         *  P19 dup and, P59 and-to-0) collapse the pair further.
         *
         *  P62b: "or R, c1 / and R, c2" where (c2 & c1) == c2 (the
         *  AND mask is a subset of the OR mask) -> both collapse to
         *  `mov R, c2` when all six flags are dead.  R_final =
         *  (R | c1) & c2; if c2 is a subset of c1, the OR can only
         *  set bits that the AND will clear, so R_final = R & c2
         *  (which equals c2 when the OR had already set all of c2's
         *  bits, but only if R had them set too... careful: the
         *  equivalence is exact only if c2 ⊆ c1, then (R|c1)&c2 =
         *  c2).  Both instructions' flags vanish under the mov, so
         *  the scan must prove all six dead.  Research: Open Watcom
         *  `AndOr` (peepopt.c:192) and `OrAnd` subset branch
         *  (peepopt.c:229).  Memory dest excluded. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "and") || ci_eq(pi->mnem, "or"))) {
            int r62 = find_reg(pi->op0);
            long c1;
            if (r62 >= 0 && g_regs[r62].fam != 4 &&
                try_parse_number(pi->op1, &c1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        find_reg(pj->op0) == r62) {
                        long c2;
                        if (try_parse_number(pj->op1, &c2)) {
                            int w = g_regs[r62].hi - g_regs[r62].lo;
                            unsigned long masku =
                                (w == 8) ? 0xFFUL :
                                (w == 16) ? 0xFFFFUL : 0xFFFFFFFFUL;
                            unsigned long mc1 = (unsigned long)c1 & masku;
                            unsigned long mc2 = (unsigned long)c2 & masku;
                            /* P62: and c1 / or c2 -> and (c1 & ~c2) / or c2.
                             *  No flag scan: the rewritten AND still
                             *  defines exactly the same six flags as
                             *  before, and the OR is unchanged. */
                            if (ci_eq(pi->mnem, "and") &&
                                ci_eq(pj->mnem, "or") &&
                                (mc1 & ~mc2) != mc1) {
                                char num[32];
                                unsigned long newmask = mc1 & ~mc2;
                                strcpy(g_build, pi->prefix);
                                strcat(g_build, "and ");
                                if (g_att) {
                                    strcat(g_build, "$");
                                    sprintf(num, "%lu", newmask);
                                    strcat(g_build, num);
                                    strcat(g_build, ", ");
                                    strcat(g_build, pi->op0);
                                } else {
                                    strcat(g_build, pi->op0);
                                    strcat(g_build, ", ");
                                    sprintf(num, "%lu", newmask);
                                    strcat(g_build, num);
                                }
                                if (pi->comment[0] != 0) {
                                    strcat(g_build, " ");
                                    strcat(g_build, pi->comment);
                                }
                                vlog("smartpp: line %ld: tightened 'and %s, %ld' to 'and %s, %lu' before or %ld (P62)\n",
                                    i + 1, pi->op0, c1, pi->op0,
                                    newmask, c2);
                                replace_line(i, g_build);
                                st[62]++;
                                continue;
                            }
                            /* P62b: or c1 / and c2 with (c2 & c1) == c2
                             *  -> mov R, c2 (both deleted) when all
                             *  six flags dead. */
                            if (ci_eq(pi->mnem, "or") &&
                                ci_eq(pj->mnem, "and") &&
                                (mc2 & mc1) == mc2 &&
                                flags_clear(next_code(j), F_ALL6)) {
                                char num[32];
                                strcpy(g_build, pj->prefix);
                                strcat(g_build, "mov ");
                                if (g_att) {
                                    strcat(g_build, "$");
                                    sprintf(num, "%ld", c2);
                                    strcat(g_build, num);
                                    strcat(g_build, ", ");
                                    strcat(g_build, pj->op0);
                                } else {
                                    strcat(g_build, pj->op0);
                                    strcat(g_build, ", ");
                                    sprintf(num, "%ld", c2);
                                    strcat(g_build, num);
                                }
                                if (pj->comment[0] != '\0') {
                                    strcat(g_build, " ");
                                    strcat(g_build, pj->comment);
                                }
                                vlog("smartpp: line %ld: 'or %s, %ld' / 'and %s, %ld' collapsed to 'mov %s, %ld' (P62b)\n",
                                    i + 1, pi->op0, c1, pj->op0, c2,
                                    pj->op0, c2);
                                DEL(i) = 1;
                                replace_line(j, g_build);
                                st[62]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P1 / xchg R,R: handled by table rules P1 and P126. */

        /* P2: dead register store
         *
         *  v1.83 BUG FIX: the previous code unconditionally allowed
         *  `mov R, <memory>` to be deleted as a dead store, since
         *  the value is discarded.  That is unsafe: a memory read
         *  may have side effects (memory-mapped I/O that clears a
         *  status register on read, FIFOs that advance on read,
         *  volatile flags).  P19, P23 and P58 all reject memory
         *  operands for exactly this reason; P2 was the only rule
         *  that accepted them.  Drop the "memory source" branch so
         *  only register, immediate and lea sources qualify. */
        if (!pi->haslabel && !pi->toobig) {
            if (pi->cls == I_LEA) i1ok = 1;
            else if (pi->cls == I_MOV && pi->dreg >= 0) {
                if (pi->sreg >= 0) {
                    int dsz = g_regs[pi->dreg].hi - g_regs[pi->dreg].lo;
                    int ssz = g_regs[pi->sreg].hi - g_regs[pi->sreg].lo;
                    i1ok = (dsz == ssz);      /* mov r,r of one size */
                }
                else if (pi->srcimm) i1ok = 1;
                /* v1.83: was `else i1ok = 1;` for memory source --
                 *  dropped because MMIO reads may have side effects */
            }
            else if (pi->cls == I_MOVZX && pi->sreg >= 0) i1ok = 1;
        }
        if (i1ok) {
            j = next_code(i);
            if (j >= 0) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && writer_ok(pj, pi->dreg)) {
                    vlog("smartpp: line %ld: deleted '%s' (dead store, P2)\n",
                        i + 1, L(i));
                    DEL(i) = 1;
                    st[2]++;
                    continue;
                }
            }
        }

        /* P3: push X / pop X
         *
         *  v1.83 BUG FIX: on 8086/8088/80186 the PUSH SP instruction
         *  pushes the *already-decremented* SP value (the CPU
         *  decrements SP before storing), while on 286+ it pushes
         *  the *original* SP.  So `push sp / pop sp` is NOT identity
         *  on the older CPUs -- it leaves SP = (SP-2) on 8086, not
         *  SP.  Require g_curcpu >= 4 (286+) when the operand is SP
         *  (16-bit) or ESP (32-bit, only meaningful on 386+ where the
         *  bug is already fixed).  The same applies to pusha/popa
         *  (which include SP), but those are already gated on
         *  g_curcpu >= 2 -- tighten to 4 for safety. */
        if (!pi->haslabel && !pi->toobig &&
            (pi->cls == I_PUSH || pi->cls == I_PUSHF || pi->cls == I_PUSHA)) {
            int sp_operand = 0;
            if (pi->cls == I_PUSH) {
                int r3 = find_reg(pi->op0);
                if (r3 >= 0 && g_regs[r3].fam == 4) sp_operand = 1;
            }
            /* PUSHA always includes SP -- but it is 186+ only, and
             *  the SP pushed is the original SP (186 docs confirm the
             *  286 semantics), so no extra gate is needed for PUSHA.
             *  Conservative: still allow it on 186+. */
            if (!(sp_operand && g_curcpu < 4)) {
            j = next_code(i);
            if (j >= 0) {
                struct pinfo *pj = &g_ppair;
                int match = 0;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig) {
                    if (pi->cls == I_PUSH && pj->cls == I_POP &&
                        ci_eq(pi->op0, pj->op0)) match = 1;
                    else if (pi->cls == I_PUSHF && pj->cls == I_POPF) match = 1;
                    else if (pi->cls == I_PUSHA && pj->cls == I_POPA &&
                             g_curcpu >= 2) match = 1;
                }
                if (match) {
                    vlog("smartpp: line %ld: deleted push/pop pair (P3)\n",
                        i + 1);
                    DEL(i) = 1;
                    DEL(j) = 1;
                    st[3]++;
                    continue;
                }
            }
            }
        }

        /* P20 migrated to table P146 (v1.90) */

        /* P4: shift/rotate merge (registers only; default since 1.10)
         *
         *  v1.83 BUG FIX: a single shift of count 1 leaves OF defined
         *  (and CF for shl/shr/sal/sar/rol/ror/rcl/rcr); a count >1
         *  leaves OF undefined.  When we fuse two count-1 shifts into
         *  one count-2 shift, the fused instruction's OF no longer
         *  reflects the high-bit XOR that the original second shift
         *  would have computed.  Same for rol/ror/rcl/rcr: count==1
         *  defines CF/OF, count>1 leaves OF undefined and CF=last
         *  bit shifted.  The safe fix is to demand OF dead before
         *  merging whenever (a) the running total is already >= 1 and
         *  the incoming shift is count 1, or (b) the running total
         *  is 0 and the incoming shift is count 1 AND the merged
         *  result will be > 1.  In short: if the fused total is > 1,
         *  OF must be dead from the second shift onward.  Note the
         *  scan needs to start AT the second shift (so it covers
         *  any reader between the two originals and the fused one). */
        if (g_curcpu >= 2 && !pi->toobig &&
            pi->cls == I_SHIFT && pi->shiftcount >= 0 &&
            find_reg(pi->op0) >= 0) {
            long total = pi->shiftcount;
            int merged = 0;
            int r4 = find_reg(pi->op0);
            int w4 = g_regs[r4].hi - g_regs[r4].lo;
            for (;;) {
                struct pinfo *pj = &g_ppair;
                j = next_code(i);
                if (j < 0) break;
                parse_line(j, pj);
                if (pj->cls != I_SHIFT || pj->haslabel || pj->toobig ||
                    pj->shiftcount < 0) break;
                if (!shift_same(pi->mnem, pj->mnem) ||
                    !ci_eq(pi->op0, pj->op0)) break;
                /* v2.21: allow merging up to width; beyond that the
                 *  result is 0 (for shl/shr/sal) and handled below. */
                if (total + pj->shiftcount > 63) break;
                /* v1.83: if the fused total exceeds 1, OF (and CF for
                 *  rotates, which flag_sets already models together
                 *  with OF for rcl/rcr/rol/ror) must be dead from
                 *  line j onward.  For shl/shr/sal/sar flag_sets
                 *  sets wr=F_ALL6, so demanding F_OF is a strict
                 *  subset; for rol/ror wr=F_CFOF so this also
                 *  catches the CF change; for rcl/rcr rd=CF wr=CFOF
                 *  so the demand naturally covers the read of CF
                 *  in the second op too.  Refuse the merge if any
                 *  of these is live. */
                if (total + pj->shiftcount > 1) {
                    int need = F_OF;
                    if (ci_eq(pi->mnem, "rol") || ci_eq(pi->mnem, "ror") ||
                        ci_eq(pi->mnem, "rcl") || ci_eq(pi->mnem, "rcr")) {
                        need |= F_CF;
                    }
                    if (!flags_clear(next_code(j), need)) break;
                }
                total += pj->shiftcount;
                vlog("smartpp: line %ld: merged '%s' into line %ld (P4)\n",
                    j + 1, L(j), i + 1);
                DEL(j) = 1;
                st[4]++;
                merged = 1;
            }
            if (merged) {
                /* v2.21: if the merged shift total >= register width
                 *  for shl/shr/sal, the result is 0.  FPC ShlShl2Mov.
                 *  sar is excluded (sign-extends, not zero).  Rotates
                 *  are periodic in the width, not overflow-to-zero. */
                if (total >= w4 &&
                    (ci_eq(pi->mnem, "shl") || ci_eq(pi->mnem, "shr") ||
                     ci_eq(pi->mnem, "sal")) &&
                    flags_clear(next_code(i), F_ALL6)) {
                    /* xor R,R is 2 bytes (same as mov R,0 on 8086
                     *  for 16-bit, 1 byte shorter for 32-bit). */
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "xor ");
                    if (g_curcpu == 128 && w4 == 64) {
                        const char *rn = reg_name_at_width(r4, 32);
                        if (rn) { strcat(g_build, rn); strcat(g_build, ", "); strcat(g_build, rn); }
                        else { strcat(g_build, pi->op0); strcat(g_build, ", "); strcat(g_build, pi->op0); }
                    } else {
                        strcat(g_build, pi->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, pi->op0);
                    }
                    if (pi->comment[0] != 0) { strcat(g_build, " "); strcat(g_build, pi->comment); }
                    vlog("smartpp: line %ld: shift overflow (total %ld >= %d) -> '%s' (P4)\n",
                        i + 1, total, w4, g_build);
                    replace_line(i, g_build);
                    st[4]++;
                    continue;
                }
                rewrite_shift(i, pi, total);
                continue;  /* v2.18: stale pi would make P323/P324
                            *  fire on the old "shl R,1" and rewrite
                            *  the merged "shl R,2" to "lea R,[R+R]"
                            *  (= R*2 instead of R*4).  MISCOMPILE. */
            }
        }

        /* P8 (v1.81 extended): "or R,R" / "and R,R" (any width, incl.
        *  8-bit) / "or R,0" / "and R,all-ones" (all-ones recognized
        *  for every width: 0xFF, 0xFFFF, 0xFFFFFFFF, or -1) ->
        *  "test R,R" (exact equivalence: same flags, no register
        *  change), OR deleted when the scan proves all six status
        *  flags dead (no reader anywhere downstream).
        *
        *  Why this is exact: OR-with-0 and AND-with-all-ones leave R
        *  unchanged; both clear CF and OF, set SF/ZF/PF from R, and
        *  leave AF undefined -- exactly what `test R,R` does.  The
        *  `or R,R`/`and R,R` form is the same calculation (R OR R = R;
        *  R AND R = R).  When the flags are provably dead, the
        *  instruction has no observable effect at all and may be
        *  deleted; `test R,R` (2 bytes) is still smaller than `or R,0`
        *  (3 bytes) or `and R,-1` (3 bytes) when a reader is present.
        *
        *  v1.81 changes: (1) drop the >= 16-bit width gate so 8-bit
        *  forms like `or al, 0` / `and al, 0FFh` / `or al, al` also
        *  fire (saves 1 byte each); (2) recognize the all-ones
        *  immediate for every width (0xFF, 0xFFFF, 0xFFFFFFFF, or -1)
        *  instead of just -1; (3) add the delete-if-flags-dead
        *  branch. */
        {
            int p8ok = 0;
            int r8 = -1;
            if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
                (ci_eq(pi->mnem, "or") || ci_eq(pi->mnem, "and")) &&
                (r8 = find_reg(pi->op0)) >= 0) {
                int w8 = g_regs[r8].hi - g_regs[r8].lo;
                unsigned long mask8 = (w8 == 8) ? 0xFFUL :
                                       (w8 == 16) ? 0xFFFFUL :
                                                    0xFFFFFFFFUL;
                long v8;
                if (ci_eq(pi->op0, pi->op1)) p8ok = 1;
                else if (ci_eq(pi->mnem, "or") &&
                         try_parse_number(pi->op1, &v8) && v8 == 0) p8ok = 1;
                else if (ci_eq(pi->mnem, "and") &&
                         try_parse_number(pi->op1, &v8) &&
                         ((unsigned long)v8 == mask8 || v8 == -1L)) p8ok = 1;
            }
            if (p8ok) {
                /* If every flag is provably dead, delete the line;
                 *  otherwise rewrite it to `test R,R` (still a
                 *  one-byte win on 8/16/32-bit and exact on flags).
                 *  P8 also requires !pi->haslabel on the delete path
                 *  so a label carried by line i is not lost. */
                if (!pi->haslabel && flags_clear(next_code(i), F_ALL6)) {
                    vlog("smartpp: line %ld: deleted '%s %s, %s' (P8, flags dead)\n",
                        i + 1, pi->mnem, pi->op0, pi->op1);
                    DEL(i) = 1;
                    st[8]++;
                    continue;  /* v2.18: stale pi (or/and) would make
                                *  table P332/P329 fire again */
                } else {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "test ");
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, pi->op0);
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: '%s %s, %s' rewritten to 'test %s, %s' (P8)\n",
                        i + 1, pi->mnem, pi->op0, pi->op1, pi->op0, pi->op0);
                    replace_line(i, g_build);
                    st[8]++;
                    continue;  /* v2.18: same -- avoid stale pi */
                }
            }
        }

        /* P9: "mov R,0" -> "xor R,R" when the scan proves all six
        *  status flags are overwritten on every path before a read.
        *  v1.87: on x86-64 (g_curcpu == 128) when the destination is a
        *  64-bit register, emit "xor R32,R32" instead of "xor R64,R64".
        *  xor on a 32-bit register zero-extends to 64 bits for free
        *  (canonical x64 zeroing idiom), is 1 byte shorter (no REX.W
        *  prefix), and breaks the dependency chain on PPro/P6 and
        *  every x64 core via partial-register rename. */
        if (!pi->toobig && pi->cls == I_MOV && pi->dreg >= 0 &&
            pi->sreg < 0 && pi->srcimm &&
            (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) >= 16) {
            long v;
            if (try_parse_number(pi->op1, &v) && v == 0 &&
                flags_clear(next_code(i), F_ALL6)) {
                const char *rn = NULL;
                int is_x64_64 = (g_curcpu == 128 &&
                    (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) == 64);
                if (is_x64_64)
                    rn = reg_name_at_width(pi->dreg, 32);
                strcpy(g_build, pi->prefix);
                strcat(g_build, "xor ");
                if (is_x64_64 && rn != NULL) {
                    strcat(g_build, rn);
                    strcat(g_build, ", ");
                    strcat(g_build, rn);
                }
                else {
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, pi->op0);
                }
                if (pi->comment[0] != 0) {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                if (is_x64_64 && rn != NULL)
                    vlog("smartpp: line %ld: 'mov %s, 0' rewritten to 'xor %s, %s' (P9, x64 zeroing)\n",
                        i + 1, pi->op0, rn, rn);
                else
                    vlog("smartpp: line %ld: 'mov %s, 0' rewritten to 'xor %s, %s' (P9)\n",
                        i + 1, pi->op0, pi->op0, pi->op0);
                replace_line(i, g_build);
                st[9]++;
                continue;  /* v2.18: avoid stale pi (mov R,0) */
            }
        }

        /* P71 (v2.23): migrated to table rule.
         *  "sub R, R" -> "xor R, R" when AF is dead, not SP. */

        /* P26: "xor R,R" immediately overwritten by a full-cover
        *  writer that defines no flags (mov/lea/movzx/pop): the
        *  zero result is dead.  xor defines all six status flags,
        *  so the scan must prove them dead; the writer defines
        *  none, so the scan simply walks past it. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XORRR) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    writer_ok(pj, pi->dreg) &&
                    flags_clear(next_code(i), F_ALL6)) {
                    vlog("smartpp: line %ld: deleted '%s %s, %s' (zero result dead, P26)\n",
                        i + 1, pi->mnem, pi->op0, pi->op1);
                    DEL(i) = 1;
                    st[26]++;
                    continue;
                }
            }
        }

        /* P10 (v2.24): migrated to table rules (P10a-P10d). */

        /* P11 (v2.23): migrated to table rule.
        *  "cmp R,0" -> "test R,R" when AF is dead. */

        /* P65 (v2.24): migrated to table rule. */

        /* P37 (v1.80): "xor R, -1" -> "not R".  For any width w,
        *  R XOR (2^w - 1) = ~R, exactly what "not R" computes.  xor
        *  defines all six status flags, not defines none, so the
        *  scan must prove all six dead.  Registers only.  Saves 1
        *  byte on 16-bit, 2 on 32-bit.  FPC's "xor -1 -> not" rule. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "xor") &&
            find_reg(pi->op0) >= 0) {
            long v;
            int r = find_reg(pi->op0);
            int w = g_regs[r].hi - g_regs[r].lo;
            if (try_parse_number(pi->op1, &v) &&
                ((w == 8  && (v == -1L || (unsigned long)v == 0xFFL)) ||
                 (w == 16 && (v == -1L || (unsigned long)v == 0xFFFFL)) ||
                 (w == 32 && (v == -1L || (unsigned long)v == 0xFFFFFFFFUL))) &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "not ");
                strcat(g_build, pi->op0);     /* op0 carries % in AT&T */
                if (pi->comment[0] != 0) {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'xor %s, %ld' rewritten to 'not %s' (P37)\n",
                    i + 1, pi->op0, v, pi->op0);
                replace_line(i, g_build);
                st[37]++;
                continue;  /* v2.18: avoid stale pi (xor R,-1) blocking P371 */
            }
        }

        /* P38 + P51 (v1.80): "imul R, K" -> strength reduction.
        *  P51: K = -1 -> "neg R" (saves 1 byte, 186+).
        *  P38: K = 2^k for some k >= 1 -> "shl R, k" (saves a byte
        *  in the common imm8 case; also for K = 1 -> delete, since
        *  imul R, 1 is identity-with-flags).  All six flags must
        *  be dead (imul defines them, shl/neg define them
        *  differently).  Registers only; 186+ (two-operand imul). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "imul") &&
            g_curcpu >= 2 && find_reg(pi->op0) >= 0) {
            long v;
            int r = find_reg(pi->op0);
            int w = g_regs[r].hi - g_regs[r].lo;
            if (try_parse_number(pi->op1, &v) && v != 0) {
                /* P51: K = -1 -> neg R */
                if (v == -1L && flags_clear(next_code(i), F_ALL6)) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "neg ");
                    strcat(g_build, pi->op0);     /* op0 carries % in AT&T */
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'imul %s, -1' rewritten to 'neg %s' (P51)\n",
                        i + 1, pi->op0, pi->op0);
                    replace_line(i, g_build);
                    st[51]++;
                    continue;  /* v2.18: avoid stale pi (imul R,-1) */
                }
                /* P38: K is a power of two, k >= 1, k < width.
                 *  v2.14 FIX: K == 1 (k = 0) is the identity; the old
                 *  "delete" branch sat in an else-if BEHIND this
                 *  power-of-two branch (v==1 satisfies it), so it was
                 *  unreachable and "imul R,1" was only removed by the
                 *  (now deleted) table rule P122.  Handle k == 0 here. */
                else if (v > 0 && (v & (v - 1)) == 0) {
                    int k = 0;
                    long vv = v;
                    while (vv > 1) { vv >>= 1; k++; }
                    if (k == 0 && flags_clear(next_code(i), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted 'imul %s, 1' (identity, P38)\n",
                            i + 1, pi->op0);
                        DEL(i) = 1;
                        st[38]++;
                        continue;  /* v2.18: avoid stale pi */
                    }
                    else if (k >= 1 && k < w && flags_clear(next_code(i), F_ALL6)) {
                        char num[32];
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "shl ");
                        if (g_att) {
                            strcat(g_build, "$");
                            sprintf(num, "%d", k);
                            strcat(g_build, num);
                            strcat(g_build, ", ");   /* pi->op0 already has % for AT&T */
                            strcat(g_build, pi->op0);
                        } else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            sprintf(num, "%d", k);
                            strcat(g_build, num);
                        }
                        if (pi->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: 'imul %s, %ld' rewritten to 'shl %s, %d' (P38)\n",
                            i + 1, pi->op0, v, pi->op0, k);
                        replace_line(i, g_build);
                        st[38]++;
                        continue;  /* v2.18: avoid stale pi (imul R,K) */
                    }
                }
                /* P50 (v2.14, REMOVED): "imul R, K" with K = 2^k+1 ->
                 *  "lea R, [R+R*k]" is now handled by the unified
                 *  strength-reduction engine further down (P380), which
                 *  covers 3, 5, 9 plus 6, 7, 10, 11, 12, 13, 14, 15 and
                 *  every m*2^a form of those, with the same width and
                 *  flag gates.  See rname[50]. */
            }
        }

        /* P19 (v1.81 extended): two consecutive identical
        *  "cmp R,S" / "test R,S" / "or R,S" / "and R,S" (S a register
        *  or a plain constant): the first defines exactly the values
        *  the second overwrites (both R and the flags) and nothing
        *  reads them in between, so the first is dead.  Memory
        *  operands are left alone (a repeated read of I/O space may
        *  be meaningful).
        *
        *  Why or/and qualify: or/and are idempotent on R
        *  (R | S | S = R | S; R & S & S = R & S), so the first's R
        *  write is overwritten by the second with the same value,
        *  and the first's flag write is overwritten by the second
        *  with the same flag values (since both compute the same
        *  R op S).  cmp/test are trivially idempotent because they
        *  don't write R.  add/sub/xor are NOT idempotent in general
        *  (R changes), so they stay out; `add R,0`/`sub R,0` are
        *  handled by P18. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
            (ci_eq(pi->mnem, "cmp") || ci_eq(pi->mnem, "test") ||
             ci_eq(pi->mnem, "or")  || ci_eq(pi->mnem, "and")) &&
            find_reg(pi->op0) >= 0) {
            long v19;
            if (find_reg(pi->op1) >= 0 || try_parse_number(pi->op1, &v19)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, pi->mnem) &&
                        ci_eq(pj->op0, pi->op0) &&
                        ci_eq(pj->op1, pi->op1)) {
                        vlog("smartpp: line %ld: deleted duplicate '%s %s, %s' (P19)\n",
                            i + 1, pi->mnem, pi->op0, pi->op1);
                        DEL(i) = 1;
                        st[19]++;
                        continue;
                    }
                }
            }
        }

        /* P77 (v1.83): duplicate consecutive "mov R, X" / "lea R, X"
         *  / "movzx R, X" with the SAME destination register and
         *  SAME source operand (textual match) -> first deleted.
         *  All three classes are flag-neutral, so the second over-
         *  writes R with the same value the first wrote; the first
         *  is exactly dead.  This is the natural extension of P19
         *  (which handled cmp/test/or/and) to the flag-free move
         *  family.  The source operand must be a register or
         *  immediate (mov/lea) or a register (movzx) -- a repeated
         *  memory read may have MMIO side effects, so memory sources
         *  are excluded for mov/lea; movzx's source is by definition
         *  a register in this parser, so it is always safe.
         *  Width must match between R and the source for mov/lea
         *  (mov al, ah / mov al, ah would write al twice, both
         *  times from ah -- safe, but the check keeps the rule
         *  conservative).  Research: FPC OptPass1Mov duplicate
         *  elimination; LLVM MachineCSE. */
        if (!pi->haslabel && !pi->toobig &&
            (pi->cls == I_MOV || pi->cls == I_LEA || pi->cls == I_MOVZX) &&
            pi->dreg >= 0) {
            int op1_is_mem = 0;
            if (pi->cls != I_MOVZX) {
                /* For mov/lea, the second operand may be a memory
                 *  expression; reject so we don't drop a double
                 *  memory read with side effects. */
                op1_is_mem = (strchr(pi->op1, '[') != NULL) ||
                             (g_att && strchr(pi->op1, '(') != NULL);
                if (!op1_is_mem) {
                    int s77 = find_reg(pi->op1);
                    long dummy77;
                    op1_is_mem = !(s77 >= 0 || try_parse_number(pi->op1, &dummy77) ||
                                   is_offset_expr(pi->op1));
                }
            }
            if (!op1_is_mem) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == pi->cls &&
                        find_reg(pj->op0) == pi->dreg &&
                        ci_eq(pj->op1, pi->op1)) {
                        vlog("smartpp: line %ld: deleted duplicate '%s %s, %s' (P77)\n",
                            i + 1, pi->mnem, pi->op0, pi->op1);
                        DEL(i) = 1;
                        st[77]++;
                        continue;
                    }
                }
            }
        }

        /* P21 (v2.25): migrated to table rules (cld/std/cli/sti/clc/stc). */

        /* P22: "inc R / dec R" (either order, same register, not
        *  SP): the value is restored, but the final flags are the
        *  second instruction's, so the scan must prove all six
        *  status flags dead.  SP is excluded: an interrupt arriving
        *  between the two would push at a misaligned stack. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 1 &&
            (ci_eq(pi->mnem, "inc") || ci_eq(pi->mnem, "dec"))) {
            int r22 = find_reg(pi->op0);
            if (r22 >= 0 && g_regs[r22].fam != 4) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 1 &&
                        ((ci_eq(pj->mnem, "inc") && ci_eq(pi->mnem, "dec")) ||
                         (ci_eq(pj->mnem, "dec") && ci_eq(pi->mnem, "inc"))) &&
                        ci_eq(pj->op0, pi->op0) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted '%s %s' / '%s %s' pair (P22)\n",
                            i + 1, pi->mnem, pi->op0, pj->mnem, pj->op0);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[22]++;
                        continue;
                    }
                }
            }
        }

        /* P23 migrated to table (v1.90) */

        /* P24: "neg R / neg R" (same register, not SP): the value
        *  is restored, but the final flags are the second neg's,
        *  so the scan must prove all six dead.  SP excluded as in
        *  P22. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 1 && ci_eq(pi->mnem, "neg")) {
            int r24 = find_reg(pi->op0);
            if (r24 >= 0 && g_regs[r24].fam != 4) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 1 &&
                        ci_eq(pj->mnem, "neg") &&
                        ci_eq(pj->op0, pi->op0) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted 'neg %s' / 'neg %s' pair (P24)\n",
                            i + 1, pi->op0, pj->op0);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[24]++;
                        continue;
                    }
                }
            }
        }

        /* P58 (v1.81): "xor R, X / xor R, X" (X = register or
         *  immediate, NOT memory) -> both deleted.  xor is
         *  involution: R ^ X ^ X = R, so two consecutive identical
         *  xors restore R to its original value.  The first xor's
         *  flags are overwritten by the second's, but the second's
         *  flags differ from "no instruction" (they are the flags
         *  of (R0 ^ X) ^ X = R0; the flags of the original
         *  computation are XOR's, which depend on R0 ^ X).  So all
         *  six status flags must be proven dead.
         *
         *  X must NOT be a memory operand: a repeated read of
         *  memory-mapped I/O may have side effects (P23 has the
         *  same restriction).
         *
         *  v1.83 BUG FIX: the previous test only rejected op1
         *  containing '[' or '(' -- a *bare* symbol like `myVar`
         *  (a memory label written without brackets, valid in
         *  MASM for `xor ax, myVar` meaning `xor ax, [myVar]`)
         *  passed the filter and the rule deleted two MMIO reads.
         *  The conservative fix is the positive test suggested in
         *  review: accept X only when find_reg(op1) >= 0 OR
         *  try_parse_number(op1) succeeds.  Anything else (label,
         *  expression, sized memory like `dword ptr [...]`, etc.)
         *  is left alone.  Two xors with the same textual second
         *  operand match by ci_eq on pj->op1; differing text
         *  representations like "5" vs "0x5" simply won't match
         *  and the rule stays silent.
         *
         *  R must not be SP: an interrupt during the one-instruction
         *  window of the first xor would push at SP0 ^ X, which is
         *  potentially misaligned; SP exclusion matches P22/P24/P27/
         *  P39/P49.  Two-instruction only (no chaining) for the same
         *  reason.  FPC folds the same pattern in its xor-pass. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "xor")) {
            int r58 = find_reg(pi->op0);
            long dummy;
            /* v1.83: positive test -- only register or numeric
             *  immediate second operands qualify.  Anything else
             *  (memory label, expression, sized memory) is
             *  conservatively treated as memory and left alone. */
            int op1_ok = (find_reg(pi->op1) >= 0) ||
                         try_parse_number(pi->op1, &dummy);
            if (r58 >= 0 && g_regs[r58].fam != 4 && op1_ok) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "xor") &&
                        find_reg(pj->op0) == r58 &&
                        ci_eq(pj->op1, pi->op1) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted 'xor %s, %s' / 'xor %s, %s' pair (P58)\n",
                            i + 1, pi->op0, pi->op1, pj->op0, pj->op1);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[58]++;
                        continue;
                    }
                }
            }
        }

        /* P25 migrated to table (v1.90) */

        /* P27: "add R,S / sub R,S" (either order, both operands
        *  registers, different registers): R is restored and S is
        *  never written, but the final flags are the second
        *  instruction's, so the scan must prove all six dead.
        *  SP as destination excluded as in P22. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub"))) {
            int r27 = find_reg(pi->op0);
            int s27 = find_reg(pi->op1);
            if (r27 >= 0 && s27 >= 0 &&
                g_regs[r27].fam != g_regs[s27].fam &&
                g_regs[r27].fam != 4) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ((ci_eq(pj->mnem, "add") && ci_eq(pi->mnem, "sub")) ||
                         (ci_eq(pj->mnem, "sub") && ci_eq(pi->mnem, "add"))) &&
                        ci_eq(pj->op0, pi->op0) &&
                        ci_eq(pj->op1, pi->op1) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted '%s %s, %s' / '%s %s, %s' pair (P27)\n",
                            i + 1, pi->mnem, pi->op0, pi->op1,
                            pj->mnem, pj->op0, pj->op1);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[27]++;
                        continue;
                    }
                }
            }
        }

        /* P28 (v2.26): migrated to table rules. */

        /* P39 (v1.80): "add R, c / sub R, c" (or reverse, c != 0)
        *  -> both deleted.  Net effect on R: zero (restored); the
        *  final flags are the second instruction's, so the scan must
        *  prove all six dead.  R must not be SP (an interrupt between
        *  the two would push at a misaligned stack).  Constant cousin
        *  of P22/P27. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub"))) {
            int r39 = find_reg(pi->op0);
            long c1;
            if (r39 >= 0 && g_regs[r39].fam != 4 &&
                try_parse_number(pi->op1, &c1) && c1 != 0) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long c2;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ((ci_eq(pi->mnem, "add") && ci_eq(pj->mnem, "sub")) ||
                         (ci_eq(pi->mnem, "sub") && ci_eq(pj->mnem, "add"))) &&
                        find_reg(pj->op0) == r39 &&
                        try_parse_number(pj->op1, &c2) && c2 == c1 &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted '%s %s, %ld' / '%s %s, %ld' pair (P39)\n",
                            i + 1, pi->mnem, pi->op0, c1,
                            pj->mnem, pj->op0, c2);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[39]++;
                        continue;
                    }
                }
            }
        }

        /* P49 (v1.80): "add sp, c / sub sp, c" (or reverse, c != 0,
        *  c even for 16-bit, c divisible by 4 for 32-bit, immediately
        *  consecutive) -> both deleted.  Net effect on SP: zero; the
        *  second instruction's flags are lost.  The "immediately
        *  consecutive" restriction (the scan does not track SP reads)
        *  and the alignment restriction (an interrupt that arrives
        *  in the one-instruction window pushes at SP_orig +/- c;
        *  requiring c to be a multiple of the stack width removes
        *  the misalignment risk). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub"))) {
            int r49 = find_reg(pi->op0);
            long c1;
            if (r49 >= 0 && g_regs[r49].fam == 4 &&
                (g_regs[r49].hi == 16 || g_regs[r49].hi == 32) &&
                try_parse_number(pi->op1, &c1) && c1 != 0 &&
                (c1 & ((g_regs[r49].hi == 16) ? 1 : 3)) == 0) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long c2;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ((ci_eq(pi->mnem, "add") && ci_eq(pj->mnem, "sub")) ||
                         (ci_eq(pi->mnem, "sub") && ci_eq(pj->mnem, "add"))) &&
                        find_reg(pj->op0) == r49 &&
                        try_parse_number(pj->op1, &c2) && c2 == c1 &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted '%s %s, %ld' / '%s %s, %ld' pair (P49)\n",
                            i + 1, pi->mnem, pj->op0, c1,
                            pj->mnem, pj->op0, c2);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[49]++;
                        continue;
                    }
                }
            }
        }

        /* P40 (v1.80, REMOVED v2.26): migrated to the table engine.
         *  The table entries at g_rule_tbl[] (P40 add/sub variants
         *  with p40_mov_add_fold_check) handle this pattern using the
         *  M4 ${K + K1} / ${K - K1} arithmetic templates.  The C
         *  code that was here (~55 lines) is removed; the table
         *  produces the same output via expand_template + replace_line_marked.
         *  Research: FPC constant propagation; GCC RTL moveImmediate. */

        /* P43/P76 (v1.80, v2.26): "xor R, R" followed by a flag-setting
        *  arith op on R, all six flags dead, collapses to a single
        *  "mov R, <constant>" (P43) or "mov R, S" (P76).
        *  P43: add/sub/or/xor R, imm  -> mov R, imm (or -imm)
        *  P76: {add|or|xor} R,S        -> mov R,S  (register source)
        *  P44 (xor/inc -> mov 1) and P45 (xor/dec -> mov -1) were
        *  migrated to the table engine in v2.26; they are NOT handled
        *  here anymore.  After xor R,R the register is 0; the second
        *  op computes a known constant from 0.  xor defines all six
        *  flags, the second op overwrites them, the combined mov
        *  defines none: the scan must prove all six dead. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XORRR) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    find_reg(pj->op0) == pi->dreg) {
                    int r = pi->dreg;
                    int w = g_regs[r].hi - g_regs[r].lo;
                    long lim = width_imm_limit(w);
                    long target = 0;          /* 0 means "no match" */
                    int hit = 0;
                    /* v2.26: P44 (inc) and P45 (dec) removed -- now
                     *  handled by table entries at g_rule_tbl[].  The
                     *  C code below handles only P43 (imm source) and
                     *  P76 (register source). */
                    /* P43: xor R,R / {add,sub,or,xor} R, imm -> mov R, K */
                    if (pj->cls == I_OTHER && pj->nops == 2 &&
                             (ci_eq(pj->mnem, "add") ||
                              ci_eq(pj->mnem, "sub") ||
                              ci_eq(pj->mnem, "or")  ||
                              ci_eq(pj->mnem, "xor"))) {
                        long v;
                        if (try_parse_number(pj->op1, &v)) {
                            if (ci_eq(pj->mnem, "add")) target = v;
                            else if (ci_eq(pj->mnem, "sub")) target = -v;
                            else target = v;       /* 0 | v = 0 ^ v = v */
                            hit = 43;
                        } else {
                            /* Operand is not an immediate -- try the
                             *  P76 register-source variant.  Only
                             *  add/or/xor produce S as the result
                             *  (sub would need neg, and is left
                             *  alone).  Same-width required. */
                            int s76 = find_reg(pj->op1);
                            if (s76 >= 0 && s76 != r &&
                                (g_regs[s76].hi - g_regs[s76].lo) == w &&
                                !ci_eq(pj->mnem, "sub")) {
                                hit = 76;
                            }
                        }
                    }
                    if (hit != 0 && hit != 76 &&
                        target >= -(lim + 1) && target <= lim &&
                        flags_clear(next_code(j), F_ALL6)) {
                        char num[32];
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "mov ");
                        if (g_att) {
                            strcat(g_build, "$");
                            sprintf(num, "%ld", target);
                            strcat(g_build, num);
                            strcat(g_build, ", ");   /* pi->op0 already has % for AT&T */
                            strcat(g_build, pi->op0);
                        } else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            sprintf(num, "%ld", target);
                            strcat(g_build, num);
                        }
                        if (pi->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P%d)\n",
                            i + 1, L(i), L(j), g_build, hit);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[43]++;   /* v2.26: only P43 reaches here now */
                        continue;
                    }
                    /* P76 branch: xor R,R / {add|or|xor} R,S -> mov R,S */
                    if (hit == 76 && flags_clear(next_code(j), F_ALL6)) {
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "mov ");
                        if (g_att) {
                            /* AT&T: mov src, dst -- pj->op1 is the
                             *  source register text with % already
                             *  in place. */
                            strcat(g_build, pj->op1);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op0);
                        } else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, pj->op1);
                        }
                        if (pi->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P76)\n",
                            i + 1, L(i), L(j), g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[76]++;
                        continue;
                    }
                }
            }
        }

        /* P48 (v2.24): migrated to table rule. */

        /* ---- v1.70 rules P29..P36.  They read a fresh parse of line i
        *  (pn): an earlier rule of this very iteration may have
        *  rewritten it (P4 changes a shift count, P9 turns a mov into
        *  an xor) and the parse in pi would then be stale. */
        parse_line(i, pn);

        /* P29 / P30: zero-extending load.  "xor T,T / mov L,SRC" and
        *  "xor H,H / mov L,SRC" (and, for the high byte only, "mov
        *  L,SRC / xor H,H") build T = zero-extended SRC.  A number in
        *  0..255 becomes "mov T,SRC" on any CPU (P30), a register or
        *  typed memory operand "movzx T,SRC" on a 386+ (P29).  xor
        *  defines all six status flags and the replacements none, so
        *  the scan must prove them dead. */
        if (!g_att && !pn->toobig && pn->dreg >= 0 &&
            (pn->cls == I_XORRR || pn->cls == I_MOV)) {
            int xf = (pn->cls == I_XORRR);
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->dreg >= 0 &&
                    pj->cls == (xf ? I_MOV : I_XORRR)) {
                    struct pinfo *px = xf ? pn : pj;
                    struct pinfo *pm = xf ? pj : pn;
                    int sz = 0;
                    int t = zx_target(px, pm, xf, &sz);
                    if (t >= 0) {
                        long v;
                        char typed[MAXTOK];
                        int kind = 0;
                        int fam = g_regs[pm->dreg].fam;
                        if (pm->sreg < 0 && !is_offset_expr(pm->op1) &&
                            try_parse_number(pm->op1, &v) &&
                            v >= 0 && v <= 255 && g_regs[t].hi == 16)
                            kind = 2;
                        else if (g_curcpu >= 8 && !prefer_xor_mov() &&
                                 !(xf && pm->sreg >= 0 &&
                                   g_regs[pm->sreg].fam == fam) &&
                                 !(xf && pm->sreg < 0 &&
                                   expr_uses_family(pm->op1, fam)) &&
                                 typed_src(pm->op1, sz, typed))
                            kind = 1;
                        if (kind != 0 && flags_clear(next_code(j), F_ALL6)) {
                            strcpy(g_build, pn->prefix);
                            strcat(g_build, (kind == 2) ? "mov " : "movzx ");
                            strcat(g_build, g_regs[t].name);
                            strcat(g_build, ", ");
                            strcat(g_build, (kind == 2) ? pm->op1 : typed);
                            if (pn->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pn->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P%d)\n",
                                i + 1, L(i), L(j), g_build,
                                (kind == 2) ? 30 : 29);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            if (kind == 2) st[30]++; else st[29]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P31: "mov AL,SRC / cbw" -> "movsx AX,SRC" and "mov AX,SRC /
        *  cwde" -> "movsx EAX,SRC".  No flag is touched by either
        *  form and the source is read before anything is written in
        *  both, so no scan and no register restriction. */
        if (!g_att && g_curcpu >= 8 && !pn->toobig && pn->cls == I_MOV &&
            pn->dreg >= 0 && g_regs[pn->dreg].fam == 0 &&
            g_regs[pn->dreg].lo == 0 &&
            (g_regs[pn->dreg].hi == 8 || g_regs[pn->dreg].hi == 16)) {
            int ds = g_regs[pn->dreg].hi;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                char typed[MAXTOK];
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_OTHER &&
                    pj->nops == 0 &&
                    ci_eq(pj->mnem, (ds == 8) ? "cbw" : "cwde") &&
                    typed_src(pn->op1, ds / 8, typed)) {
                    strcpy(g_build, pn->prefix);
                    strcat(g_build, "movsx ");
                    strcat(g_build, (ds == 8) ? "ax" : "eax");
                    strcat(g_build, ", ");
                    strcat(g_build, typed);
                    if (pn->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pn->comment);
                    }
                    vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P31)\n",
                        i + 1, L(i), L(j), g_build);
                    replace_line(i, g_build);
                    DEL(j) = 1;
                    st[31]++;
                    continue;
                }
            }
        }

        /* P81 (v1.83): "mov AL, SRC / movzx EAX, AL" (or AX/EAX form)
         *  -> "movzx EAX, byte ptr SRC" (or word ptr SRC).  Both
         *  mov and movzx are flag-neutral, and movzx reads its
         *  source before writing its destination, so the rewrite is
         *  exact on R and flags with no scan needed.  The source
         *  must be a typed memory or register operand that the
         *  existing typed_src() helper can wrap.  386+ only
         *  (movzx is 386+).  Intel-only (typed_src emits Intel).
         *  Research: GCC i386.md combine pass that fuses
         *  mov+movzx into a single movzx; FPC OptPass2MovMovzx. */
        if (!g_att && g_curcpu >= 8 && !pn->toobig && pn->cls == I_MOV &&
            pn->dreg >= 0 && g_regs[pn->dreg].hi == 8) {
            /* source register must be the low byte of the dest's
             *  family (mov al, X / movzx eax, al). */
            int fam = g_regs[pn->dreg].fam;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_MOVZX && pj->dreg >= 0 &&
                    g_regs[pj->dreg].fam == fam &&
                    g_regs[pj->dreg].lo == 0 &&
                    g_regs[pj->dreg].hi > g_regs[pn->dreg].hi) {
                    /* pj->op1 should be the same low byte as pn->op0
                     *  (e.g. "al").  Use typed_src on pn->op1 to
                     *  build "byte ptr SRC". */
                    char typed[MAXTOK];
                    if (find_reg(pj->op1) == pn->dreg &&
                        typed_src(pn->op1, 1, typed)) {
                        strcpy(g_build, pn->prefix);
                        strcat(g_build, "movzx ");
                        strcat(g_build, pj->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, typed);
                        if (pn->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pn->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P81)\n",
                            i + 1, L(i), L(j), g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[81]++;
                        continue;
                    }
                }
            }
        }

        /* P32: "push R / pop S" (different registers of one size, not
        *  SP) -> "mov S,R".  No flags, no stack traffic. */
        if (!pn->toobig && pn->cls == I_PUSH && pn->dreg >= 0 &&
            g_regs[pn->dreg].fam != 4 &&
            (g_regs[pn->dreg].hi - g_regs[pn->dreg].lo) >= 16) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_POP &&
                    pj->dreg >= 0 && pj->dreg != pn->dreg &&
                    g_regs[pj->dreg].fam != 4 &&
                    (g_regs[pj->dreg].hi - g_regs[pj->dreg].lo) ==
                    (g_regs[pn->dreg].hi - g_regs[pn->dreg].lo)) {
                    strcpy(g_build, pn->prefix);
                    strcat(g_build, "mov ");
                    strcat(g_build, g_att ? pn->op0 : pj->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, g_att ? pj->op0 : pn->op0);
                    if (pn->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pn->comment);
                    }
                    vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P32)\n",
                        i + 1, L(i), L(j), g_build);
                    replace_line(i, g_build);
                    DEL(j) = 1;
                    st[32]++;
                    continue;
                }
            }
        }

        /* P46 (v2.19): "push imm / pop R" -> "mov R, imm" (186+).
         *  Both sides flag-neutral: no scan needed.  Size-gated for
         *  32-bit R: when imm fits in [-128,127], push imm8 + pop is
         *  3 bytes vs mov R,imm32 is 5 bytes, so the rule does NOT
         *  fire.  Always fires for 16-bit R (push imm8/imm16 + pop =
         *  3-4 bytes, mov R,imm16 = 3 bytes).  SP excluded.
         *  [LLVM optimizeLEAgon; documented since v1.70 but never
         *  implemented.] */
        if (g_curcpu >= 2 && !pn->toobig && pn->cls == I_PUSH &&
            pn->dreg < 0 && pn->srcimm) {
            long v46;
            if (try_parse_number(pn->op0, &v46) || is_offset_expr(pn->op0)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_POP && pj->dreg >= 0 &&
                        g_regs[pj->dreg].fam != 4) {
                        int w46 = g_regs[pj->dreg].hi - g_regs[pj->dreg].lo;
                        /* Size gate: 32-bit R with imm8 → keep push+pop
                         *  (3 bytes vs 5).  16-bit R always (3 vs 3-4).
                         *  64-bit R: imm8 → 3 bytes vs 7, fire;
                         *  imm32 → 5 bytes vs 7, fire. */
                        int fire46 = 1;
                        if (w46 == 32 && v46 >= -128 && v46 <= 127)
                            fire46 = 0;
                        if (fire46) {
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "mov ");
                            strcat(g_build, pj->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, pn->op0);
                            if (pj->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pj->comment);
                            }
                            vlog("smartpp: line %ld: 'push %s' / 'pop %s' rewritten to '%s' (P46)\n",
                                i + 1, pn->op0, pj->op0, g_build);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            st[46]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* v1.85 TABLE-DRIVEN FALLBACK: if no bespoke C rule fired on
         *  this line, consult the declarative rule table.  The table
         *  can express single-instruction and two-instruction patterns
         *  with a small set of preconditions (flag liveness, register
         *  liveness, CPU level, segment size, syntax, next-is-jcc).
         *  Each rule's actions are applied atomically. */
        /* ---- v2.14: const-propagation window (extends zero-prop) ----
         *  After xor R,R / mov R,imm, track known constant values for a
         *  small set of registers across up to CONST_PROP_WIN linear
         *  instructions.  v2.13 tracked a single register; v2.14 keeps
         *  up to KPROP_MAX known (reg, value) pairs and additionally
         *  propagates through:
         *    - push R / pop T          (T receives R's known value)
         *    - lea T,[R+d]             (T receives R's known value + d)
         *    - mov R,S / movzx/movsx T,S / xchg R,S with known values
         *    - inc/dec/not/neg/imul-by-imm/shift-by-imm
         *  Safe folds:
         *    redundant xor R,R / mov R,K when the register already
         *      holds that value (the xor additionally needs the six
         *      status flags dead: its flag effect is not reproduced
         *      by anything else -- v2.13 deleted it unconditionally,
         *      which was unsound when a later jcc read the flags);
         *    test/or/and R,R / cmp R,imm / test R,imm -> fold the
         *      following jcc/setcc/cmov when ZF is known;
         *    add/sub/and/or/xor R,imm -> mov R, K' when the six flags
         *      are dead AND the mov is not larger than the original
         *      (v2.13 could bloat "add ax, 1" into "mov ax, K+1").
         *  All value comparisons are masked to the written register's
         *  width, so mixed-width sequences ("mov eax,5 / mov ax,5")
         *  can never fold on stale high bits (v2.13 compared values by
         *  family only, which was unsound for partial writes).
         *  Stops at labels, branches, calls, opaque instructions,
         *  writes to a tracked register's family.
         */
        {
            #define CONST_PROP_WIN 8
            #define PEND_STACK_SZ 4   /* max nested pushes in the window */
            struct kprop kp[KPROP_MAX];
            int nkp = 0;
            /* v2.20: pending-push STACK (was a single slot).  The old
             *  code tracked only ONE pending push; when an "ajeno"
             *  push (of an untracked register) intervened between the
             *  tracked push and its matching pop, the pending slot was
             *  cleared and the matching pop lost the known value.
             *  Now each push pushes onto a small LIFO stack of pending
             *  slots; each pop pops the top, so
             *    push eax(=42) / push ecx / pop edx / pop ebx
             *  correctly gives ebx = 42 (the first push, revealed by
             *  the second pop). */
            struct {
                int valid;              /* 1 = known value, 0 = unknown */
                unsigned long val;
                int width;
            } pend_stack[PEND_STACK_SZ];
            int pend_top = 0;
            if (!pi->toobig && !pi->haslabel && pi->hasinstr) {
                if (pi->cls == I_XORRR ||
                    (ci_eq(pi->mnem, "xor") && pi->nops == 2 &&
                     find_reg(pi->op0) >= 0 &&
                     find_reg(pi->op0) == find_reg(pi->op1))) {
                    kp[0].reg = find_reg(pi->op0);
                    kp[0].val = 0;
                    nkp = 1;
                } else if (pi->cls == I_MOV && pi->srcimm && pi->dreg >= 0) {
                    long zv;
                    if (try_parse_number(pi->op1, &zv)) {
                        kp[0].reg = pi->dreg;
                        kp[0].val = (unsigned long)zv & reg_mask(pi->dreg);
                        nkp = 1;
                    }
                }
            }
            if (nkp > 0 && g_regs[kp[0].reg].fam != 4 /* not SP */) {
                long k = next_code(i);
                int steps = 0;
                while (k >= 0 && steps < CONST_PROP_WIN && nkp > 0) {
                    struct pinfo *pk = &g_pscan;
                    int dk, sk;
                    long imm;
                    if (DEL(k)) { k = next_code(k); continue; }
                    parse_line(k, pk);
                    if (pk->haslabel) break;
                    if (!pk->hasinstr) { k = next_code(k); steps++; continue; }
                    if (pk->toobig) break;
                    if (pk->mnem[0] == '.') break;
                    if (pk->cls == I_JMP || pk->cls == I_JCC ||
                        ci_eq(pk->mnem, "call") || ci_eq(pk->mnem, "ret") ||
                        ci_eq(pk->mnem, "retn") || ci_eq(pk->mnem, "retf") ||
                        ci_eq(pk->mnem, "int") || ci_eq(pk->mnem, "int3"))
                        break;
                    dk = find_reg(pk->op0);
                    sk = (pk->nops >= 2) ? find_reg(pk->op1) : -1;

                    /* v2.16 SOUNDNESS: anything that moves esp breaks
                     *  the LIFO pairing between a pending push and its
                     *  pop ("push eax / add esp,4 / pop ebx" makes ebx
                     *  receive whatever lies BELOW eax's slot, not
                     *  eax's value).  Any instruction whose first
                     *  operand is an SP-family register (add/sub/mov/
                     *  xchg esp, ...) clears the pending stack. */
                    if (dk >= 0 && g_regs[dk].fam == 4)
                        pend_top = 0;

                    /* pusha/popa and string ops clobber whole register
                     *  sets implicitly: drop everything (lods also
                     *  writes AL; stos/movs leave AX alone, so other
                     *  knowledge could survive -- kept conservative) */
                    if (pk->cls == I_PUSHA || pk->cls == I_POPA ||
                        is_string_mnem(pk->mnem)) {
                        nkp = 0;
                        pend_top = 0;
                        break;
                    }

                    /* ---- push / pop propagation ---- */
                    if (ci_eq(pk->mnem, "push")) {
                        if (pk->cls == I_PUSH && pk->dreg >= 0) {
                            int e = kprop_find_fam(kp, nkp,
                                                   g_regs[pk->dreg].fam);
                            /* v2.20: push onto the pending stack */
                            if (pend_top < PEND_STACK_SZ) {
                                if (e >= 0 && pk->dreg == kp[e].reg) {
                                    pend_stack[pend_top].valid = 1;
                                    pend_stack[pend_top].val = kp[e].val;
                                    pend_stack[pend_top].width = reg_width(pk->dreg);
                                } else {
                                    pend_stack[pend_top].valid = 0;
                                }
                                pend_top++;
                            }
                        } else {
                            /* imm / mem / pushf: pushes an unknown value */
                            if (pend_top < PEND_STACK_SZ) {
                                pend_stack[pend_top].valid = 0;
                                pend_top++;
                            }
                        }
                        k = next_code(k); steps++; continue;
                    }
                    if (ci_eq(pk->mnem, "pop")) {
                        /* v2.20: pop from the pending stack (LIFO) */
                        if (pend_top > 0) {
                            pend_top--;
                            if (pk->cls == I_POP && pk->dreg >= 0 &&
                                g_regs[pk->dreg].fam != 4) {
                                if (pend_stack[pend_top].valid &&
                                    pend_stack[pend_top].width ==
                                    reg_width(pk->dreg))
                                    kprop_set(kp, &nkp, pk->dreg,
                                              pend_stack[pend_top].val);
                                else
                                    kprop_kill_fam(kp, &nkp,
                                                   g_regs[pk->dreg].fam);
                            }
                        } else if (pk->cls == I_POP && pk->dreg >= 0 &&
                                 g_regs[pk->dreg].fam != 4) {
                            /* v2.16 SOUNDNESS: a pop WITHOUT a matching
                             *  tracked push writes an UNKNOWN value */
                            kprop_kill_fam(kp, &nkp,
                                           g_regs[pk->dreg].fam);
                        }
                        k = next_code(k); steps++; continue;
                    }
                    if (pk->cls == I_PUSHF || pk->cls == I_POPF) {
                        if (pk->cls == I_PUSHF) {
                            /* pushf pushes unknown (flags value) */
                            if (pend_top < PEND_STACK_SZ) {
                                pend_stack[pend_top].valid = 0;
                                pend_top++;
                            }
                        } else {
                            /* popf clobbers the stack (restores all) */
                            pend_top = 0;
                        }
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- lea T,[R+d]: T receives R's known value + d ---- */
                    if (pk->cls == I_LEA && pk->nops == 2 && dk >= 0) {
                        int base;
                        long disp;
                        if (lea_bracket(pk->op1, &base, &disp) && base >= 0) {
                            int e = kprop_find_fam(kp, nkp,
                                                   g_regs[base].fam);
                            if (e >= 0 && base == kp[e].reg &&
                                reg_width(dk) == reg_width(kp[e].reg)) {
                                kprop_set(kp, &nkp, dk,
                                          kp[e].val + (unsigned long)disp);
                                k = next_code(k); steps++; continue;
                            }
                        }
                        kprop_kill_fam(kp, &nkp, g_regs[dk].fam);
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- mov R,imm: fold or refresh ---- */
                    if (pk->cls == I_MOV && pk->dreg >= 0 && pk->srcimm &&
                        try_parse_number(pk->op1, &imm)) {
                        int e = kprop_find_fam(kp, nkp,
                                               g_regs[pk->dreg].fam);
                        /* v2.24 SOUNDNESS FIX: the original check only
                         *  compared family + width + value-mask, which
                         *  made P344 think "mov al, 0" also proved AH=0
                         *  (both width 8, both fam 0, both val-mask 0).
                         *  That is a miscompile: AH is whatever the
                         *  caller left, deleting "mov ah, 0" leaves AH
                         *  untouched.  Add the covers() check so the
                         *  known register must actually cover every
                         *  bit the writing register writes.  Same
                         *  blind spot as the v2.17 cap_regname / OP_SAME
                         *  fix, just in a different place.  The fix is
                         *  conservative: cases that used to fire
                         *  unsoundly (mov al,0 / mov ah,0) now refuse
                         *  to fire; sound cases (mov ax,0 / mov ah,0)
                         *  still fire because covers(AX, AH) is true. */
                        if (e >= 0 &&
                            covers(kp[e].reg, pk->dreg) &&
                            (kp[e].val & reg_mask(pk->dreg)) ==
                            ((unsigned long)imm & reg_mask(pk->dreg))) {
                            vlog("smartpp: line %ld: deleted redundant const store '%s' (P344)\n",
                                k + 1, L(k));
                            DEL(k) = 1; st[344]++;
                            k = next_code(k); steps++; continue;
                        }
                        kprop_set(kp, &nkp, pk->dreg,
                                  (unsigned long)imm & reg_mask(pk->dreg));
                        k = next_code(k); steps++; continue;
                    }
                    /* mov R,S (register source): copy or kill */
                    if (pk->cls == I_MOV && pk->dreg >= 0) {
                        int e = (sk >= 0)
                            ? kprop_find_fam(kp, nkp, g_regs[sk].fam) : -1;
                        if (e >= 0 && sk == kp[e].reg &&
                            reg_width(pk->dreg) == reg_width(sk))
                            kprop_set(kp, &nkp, pk->dreg, kp[e].val);
                        else
                            kprop_kill_fam(kp, &nkp, g_regs[pk->dreg].fam);
                        k = next_code(k); steps++; continue;
                    }
                    if (pk->cls == I_MOV) {     /* mem/segment dest */
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- movzx/movsx T,S ---- */
                    if (pk->cls == I_MOVZX && pk->dreg >= 0) {
                        int e = (sk >= 0)
                            ? kprop_find_fam(kp, nkp, g_regs[sk].fam) : -1;
                        if (e >= 0 && sk == kp[e].reg &&
                            reg_width(sk) <= reg_width(pk->dreg)) {
                            unsigned long v = kp[e].val & reg_mask(sk);
                            if (ci_eq(pk->mnem, "movsx")) {
                                int ws = reg_width(sk);
                                int lb = (int)(sizeof(unsigned long) * 8);
                                if (ws < lb && (v & (1UL << (ws - 1))) != 0)
                                    v |= ~reg_mask(sk);
                            }
                            kprop_set(kp, &nkp, pk->dreg, v);
                        } else {
                            kprop_kill_fam(kp, &nkp, g_regs[pk->dreg].fam);
                        }
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- xchg R,S ---- */
                    if (pk->cls == I_XCHG && pk->dreg >= 0 && pk->sreg >= 0 &&
                        pk->dreg != pk->sreg) {
                        int e1 = kprop_find_fam(kp, nkp,
                                                g_regs[pk->dreg].fam);
                        int e2 = kprop_find_fam(kp, nkp,
                                                g_regs[pk->sreg].fam);
                        if (e1 >= 0 && e2 >= 0 &&
                            pk->dreg == kp[e1].reg && pk->sreg == kp[e2].reg &&
                            reg_width(pk->dreg) == reg_width(pk->sreg)) {
                            unsigned long tv = kp[e1].val;
                            kp[e1].val = kp[e2].val;
                            kp[e2].val = tv;
                        } else {
                            if (e1 >= 0)
                                kprop_kill_fam(kp, &nkp,
                                               g_regs[pk->dreg].fam);
                            if (e2 >= 0)
                                kprop_kill_fam(kp, &nkp,
                                               g_regs[pk->sreg].fam);
                        }
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- readers: cmp / test fold the next jcc ---- */
                    if ((ci_eq(pk->mnem, "cmp") || ci_eq(pk->mnem, "test")) &&
                        pk->nops == 2) {
                        int sets_zf_known = 0;
                        int zf_val = 0;      /* 1 => ZF set */
                        int e = (dk >= 0)
                            ? kprop_find_fam(kp, nkp, g_regs[dk].fam) : -1;
                        if (e >= 0 &&
                            reg_width(dk) <= reg_width(kp[e].reg)) {
                            unsigned long m = reg_mask(dk);
                            if (sk == dk) {
                                /* test/or/and R,R or cmp R,R: R vs itself */
                                sets_zf_known = 1;
                                zf_val = ci_eq(pk->mnem, "cmp")
                                    ? 1 : ((kp[e].val & m) == 0);
                            } else if (sk < 0 &&
                                       try_parse_number(pk->op1, &imm)) {
                                unsigned long im =
                                    (unsigned long)imm & m;
                                if (ci_eq(pk->mnem, "cmp")) {
                                    sets_zf_known = 1;
                                    zf_val = ((kp[e].val & m) == im);
                                } else {        /* test R,imm */
                                    sets_zf_known = 1;
                                    zf_val = ((kp[e].val & im) == 0);
                                }
                            }
                        }
                        if (sets_zf_known) {
                            long j2 = next_code(k);
                            if (j2 >= 0 && !DEL(j2)) {
                                struct pinfo *pj = &g_ppair;
                                parse_line(j2, pj);
                                if (!pj->haslabel && !pj->toobig &&
                                    pj->hasinstr) {
                                    const char *lab = pj->op0;
                                    int always = 0, never = 0;
                                    if (pj->cls == I_JCC ||
                                        ci_eq_n(pj->mnem, "j", 1)) {
                                        if (ci_eq(pj->mnem, "jz") ||
                                            ci_eq(pj->mnem, "je")) {
                                            if (zf_val) always = 1;
                                            else never = 1;
                                        } else if (ci_eq(pj->mnem, "jnz") ||
                                                   ci_eq(pj->mnem, "jne")) {
                                            if (zf_val) never = 1;
                                            else always = 1;
                                        }
                                    } else if (ci_eq_n(pj->mnem, "cmov", 4) &&
                                               g_curcpu >= 64 &&
                                               pj->nops == 2) {
                                        const char *cc = pj->mnem + 4;
                                        if (ci_eq(cc, "z") ||
                                            ci_eq(cc, "e")) {
                                            if (zf_val) always = 2;
                                            else never = 1;
                                        } else if (ci_eq(cc, "nz") ||
                                                   ci_eq(cc, "ne")) {
                                            if (zf_val) never = 1;
                                            else always = 2;
                                        }
                                    } else if (ci_eq_n(pj->mnem, "set", 3) &&
                                               pj->nops == 1) {
                                        const char *cc = pj->mnem + 3;
                                        int bit = -1;
                                        if (ci_eq(cc, "z") ||
                                            ci_eq(cc, "e"))
                                            bit = zf_val ? 1 : 0;
                                        else if (ci_eq(cc, "nz") ||
                                                 ci_eq(cc, "ne"))
                                            bit = zf_val ? 0 : 1;
                                        if (bit >= 0) {
                                            strcpy(g_build, pj->prefix);
                                            strcat(g_build, "mov ");
                                            strcat(g_build, pj->op0);
                                            strcat(g_build,
                                                   bit ? ", 1" : ", 0");
                                            vlog("smartpp: line %ld: setcc with known ZF rewritten to '%s' (P385)\n",
                                                j2 + 1, g_build);
                                            replace_line(j2, g_build);
                                            st[385]++;
                                        }
                                    }
                                    if (always == 1) {
                                        strcpy(g_build, pj->prefix);
                                        strcat(g_build, "jmp ");
                                        strcat(g_build, lab);
                                        vlog("smartpp: line %ld: jcc with known flags rewritten to '%s' (P385)\n",
                                            j2 + 1, g_build);
                                        replace_line(j2, g_build);
                                        st[385]++;
                                    } else if (always == 2) {
                                        strcpy(g_build, pj->prefix);
                                        strcat(g_build, "mov ");
                                        strcat(g_build, pj->op0);
                                        strcat(g_build, ", ");
                                        strcat(g_build, pj->op1);
                                        vlog("smartpp: line %ld: cmov with known flags rewritten to '%s' (P385)\n",
                                            j2 + 1, g_build);
                                        replace_line(j2, g_build);
                                        st[385]++;
                                    } else if (never) {
                                        vlog("smartpp: line %ld: deleted jcc with known flags (P385)\n",
                                            j2 + 1);
                                        DEL(j2) = 1;
                                        st[385]++;
                                    }
                                }
                            }
                            /* flags defined; keep scanning (values kept) */
                            k = next_code(k); steps++; continue;
                        }
                        /* cmp/test write nothing: keep scanning */
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- deterministic writers with an immediate ---- */
                    if (dk >= 0 && pk->nops == 2 && sk < 0 &&
                        try_parse_number(pk->op1, &imm)) {
                        int e = kprop_find_fam(kp, nkp, g_regs[dk].fam);
                        int exact = (e >= 0 && dk == kp[e].reg);
                        unsigned long m = reg_mask(dk);
                        unsigned long nv = 0;
                        int det = 0, fold = 0, alu = 0;
                        if (ci_eq(pk->mnem, "add")) {
                            det = 1; alu = 1; fold = 1;
                            if (exact) nv = (kp[e].val +
                                             (unsigned long)imm) & m;
                        } else if (ci_eq(pk->mnem, "sub")) {
                            det = 1; alu = 1; fold = 1;
                            if (exact) nv = (kp[e].val -
                                             (unsigned long)imm) & m;
                        } else if (ci_eq(pk->mnem, "and")) {
                            det = 1; alu = 1; fold = 1;
                            if (exact) nv = kp[e].val &
                                            (unsigned long)imm & m;
                        } else if (ci_eq(pk->mnem, "or")) {
                            det = 1; alu = 1; fold = 1;
                            if (exact) nv = (kp[e].val |
                                             (unsigned long)imm) & m;
                        } else if (ci_eq(pk->mnem, "xor")) {
                            det = 1; alu = 1; fold = 1;
                            if (exact) nv = (kp[e].val ^
                                             (unsigned long)imm) & m;
                        } else if (ci_eq(pk->mnem, "imul")) {
                            det = 1;
                            if (exact) nv = (kp[e].val *
                                             (unsigned long)imm) & m;
                        } else if (pk->cls == I_SHIFT &&
                                   pk->shiftcount >= 0) {
                            int w = reg_width(dk);
                            unsigned long v = exact ? kp[e].val : 0;
                            int sc = (int)pk->shiftcount;
                            det = 1;
                            if (exact) {
                                if (ci_eq(pk->mnem, "shl") ||
                                    ci_eq(pk->mnem, "sal")) {
                                    if (sc < (int)(sizeof(unsigned long)*8))
                                        nv = (v << sc) & m;
                                    else nv = 0;
                                } else if (ci_eq(pk->mnem, "shr")) {
                                    if (sc < (int)(sizeof(unsigned long)*8))
                                        nv = (v >> sc) & m;
                                    else nv = 0;
                                } else if (ci_eq(pk->mnem, "sar")) {
                                    int lb = (int)(sizeof(unsigned long)*8);
                                    long sv;
                                    if (w < lb)
                                        sv = (long)((v << (lb - w)) ^
                                                    (1UL << (lb - 1))) -
                                             (long)(1UL << (lb - 1));
                                    else sv = (long)v;
                                    if (sc < lb) nv =
                                        ((unsigned long)(sv >> sc)) & m;
                                    else nv = (sv < 0) ? m : 0;
                                } else if (ci_eq(pk->mnem, "rol")) {
                                    sc %= (w > 0) ? w : 1;
                                    if (sc == 0) nv = v;
                                    else nv =
                                        ((v << sc) | (v >> (w - sc))) & m;
                                } else if (ci_eq(pk->mnem, "ror")) {
                                    sc %= (w > 0) ? w : 1;
                                    if (sc == 0) nv = v;
                                    else nv =
                                        ((v >> sc) | (v << (w - sc))) & m;
                                } else {
                                    det = 0;    /* rcl/rcr: CF-dependent */
                                }
                            }
                        }
                        if (det) {
                            /* fold to mov only when it is not a size
                             *  regression: result 0 (-> xor via P9), or
                             *  an ALU op whose immediate needed the
                             *  long form (mov is then shorter). */
                            if (exact) {
                                int imm8 = (imm >= -128 && imm <= 127);
                                int szwin = (nv == 0UL) ||
                                    (alu && fold && reg_width(dk) >= 16 &&
                                     !imm8);
                                if (fold && szwin &&
                                    flags_clear(next_code(k), F_ALL6)) {
                                    char num[32];
                                    sprintf(num, "%lu", nv);
                                    strcpy(g_build, pk->prefix);
                                    strcat(g_build, "mov ");
                                    strcat(g_build, pk->op0);
                                    strcat(g_build, ", ");
                                    strcat(g_build, num);
                                    vlog("smartpp: line %ld: ALU with known operand folded to '%s' (P386)\n",
                                        k + 1, g_build);
                                    replace_line(k, g_build);
                                    st[386]++;
                                }
                                kprop_set(kp, &nkp, dk, nv);
                            } else {
                                kprop_kill_fam(kp, &nkp, g_regs[dk].fam);
                            }
                            k = next_code(k); steps++; continue;
                        }
                    }

                    /* ---- deterministic 1-operand writers ---- */
                    if (dk >= 0 && pk->nops == 1 &&
                        (ci_eq(pk->mnem, "inc") || ci_eq(pk->mnem, "dec") ||
                         ci_eq(pk->mnem, "not") || ci_eq(pk->mnem, "neg"))) {
                        int e = kprop_find_fam(kp, nkp, g_regs[dk].fam);
                        if (e >= 0 && dk == kp[e].reg) {
                            unsigned long m = reg_mask(dk);
                            unsigned long v = kp[e].val;
                            if (ci_eq(pk->mnem, "inc"))
                                kprop_set(kp, &nkp, dk, v + 1);
                            else if (ci_eq(pk->mnem, "dec"))
                                kprop_set(kp, &nkp, dk, v - 1);
                            else if (ci_eq(pk->mnem, "not"))
                                kprop_set(kp, &nkp, dk, ~v);
                            else
                                kprop_set(kp, &nkp, dk,
                                          (v == 0) ? 0 : (m - v + 1));
                        } else if (e >= 0) {
                            kprop_kill_fam(kp, &nkp, g_regs[dk].fam);
                        }
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- imul R,S (register multiplier): deterministic
                     *  only when both operands are known ---- */
                    if (dk >= 0 && ci_eq(pk->mnem, "imul") && sk >= 0) {
                        int e1 = kprop_find_fam(kp, nkp, g_regs[dk].fam);
                        int e2 = kprop_find_fam(kp, nkp, g_regs[sk].fam);
                        if (e1 >= 0 && e2 >= 0 && dk == kp[e1].reg &&
                            sk == kp[e2].reg &&
                            reg_width(dk) == reg_width(sk)) {
                            kprop_set(kp, &nkp, dk,
                                      kp[e1].val * kp[e2].val);
                        } else {
                            kprop_kill_fam(kp, &nkp, g_regs[dk].fam);
                        }
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- x87 ops never touch the GP registers ---- */
                    if (pk->cls == I_X87) {
                        k = next_code(k); steps++; continue;
                    }

                    /* ---- any other reg-dest writer kills knowledge ----
                     *  adc/sbb/rcl/rcr (CF-dependent), mul/div/idiv,
                     *  shld/shrd, bswap, setcc, segment moves, and every
                     *  unrecognized mnemonic (cpuid, rdtsc, ...) break
                     *  the walk entirely -- v2.13 kept scanning through
                     *  opaque instructions, which was unsound. */
                    if (dk >= 0) {
                        kprop_kill_fam(kp, &nkp, g_regs[dk].fam);
                        k = next_code(k); steps++; continue;
                    }
                    break;
                }
            }
            #undef CONST_PROP_WIN
        }


        /* ---- v2.18: extended reverse-mov (P15 window) ----
         *  mov R,S ... mov S,R  within REV_MOV_WIN lines: if neither
         *  R nor S is written in between, the second mov is redundant
         *  (both regs still hold the original S value). */
        {
            #define REV_MOV_WIN 6
            if (!pi->toobig && !pi->haslabel && pi->cls == I_MOV &&
                pi->dreg >= 0 && pi->sreg >= 0 &&
                pi->dreg != pi->sreg &&
                g_regs[pi->dreg].fam != 4 && g_regs[pi->sreg].fam != 4) {
                int r_dst = pi->dreg, r_src = pi->sreg;
                int fam_d = g_regs[r_dst].fam, fam_s = g_regs[r_src].fam;
                long k = next_code(i);
                int steps = 0;
                while (k >= 0 && steps < REV_MOV_WIN) {
                    struct pinfo *pk = &g_pscan;
                    int dk, sk;
                    if (DEL(k)) { k = next_code(k); continue; }
                    parse_line(k, pk);
                    if (pk->haslabel) break;
                    if (!pk->hasinstr) { k = next_code(k); steps++; continue; }
                    if (pk->toobig || pk->mnem[0] == '.') break;
                    if (pk->cls == I_JMP || pk->cls == I_JCC ||
                        ci_eq(pk->mnem, "call") || ci_eq(pk->mnem, "ret") ||
                        ci_eq(pk->mnem, "retn") || ci_eq(pk->mnem, "retf"))
                        break;
                    dk = find_reg(pk->op0);
                    sk = (pk->nops >= 2) ? find_reg(pk->op1) : -1;
                    /* hit: mov S,R */
                    if (pk->cls == I_MOV && dk == r_src && sk == r_dst) {
                        vlog("smartpp: line %ld: deleted reverse mov (P15x)\n",
                            k + 1);
                        delete_keep_label(k, pk);
                        st[15]++;
                        break;
                    }
                    /* write to R or S family kills the equality */
                    if (dk >= 0 && (g_regs[dk].fam == fam_d ||
                                    g_regs[dk].fam == fam_s))
                        break;
                    if (pk->cls == I_XCHG || pk->cls == I_POP) {
                        if (dk >= 0 && (g_regs[dk].fam == fam_d ||
                                        g_regs[dk].fam == fam_s))
                            break;
                    }
                    k = next_code(k);
                    steps++;
                }
            }
            #undef REV_MOV_WIN
        }

        /* ---- v2.18 x64: xor r32,r32 already zeros r64; drop
         *  following xor r64,r64 of the same family.  Also drop
         *  mov r32,r32 (P1) is enough for identity; extra: after
         *  any 32-bit GP write, a same-reg mov r32,r32 is P1. */
        if (g_curcpu >= 128 && !pi->toobig && !pi->haslabel &&
            ci_eq(pi->mnem, "xor") && pi->nops == 2) {
            int r0 = find_reg(pi->op0), r1 = find_reg(pi->op1);
            if (r0 >= 0 && r0 == r1) {
                int w = g_regs[r0].hi - g_regs[r0].lo;
                if (w == 32) {
                    long k = next_code(i);
                    if (k >= 0 && !DEL(k)) {
                        struct pinfo *pk = &g_pscan;
                        parse_line(k, pk);
                        if (!pk->haslabel && ci_eq(pk->mnem, "xor") &&
                            pk->nops == 2) {
                            int q0 = find_reg(pk->op0), q1 = find_reg(pk->op1);
                            if (q0 >= 0 && q0 == q1 &&
                                g_regs[q0].fam == g_regs[r0].fam &&
                                (g_regs[q0].hi - g_regs[q0].lo) == 64) {
                                vlog("smartpp: line %ld: deleted xor r64 after xor r32 (P343 x64)\n",
                                    k + 1);
                                delete_keep_label(k, pk);
                                st[343]++;
                            }
                        }
                    }
                }
            }
        }


        /* ---- v2.19: constant-flag jumps (SAFE; label from op0) ----
         *  Table templates cannot bind jcc targets ($a is a reg capture).
         *  Implemented here with explicit label copy. */
        if (!pi->toobig && !pi->haslabel && pi->hasinstr) {
            long j = next_code(i);
            if (j >= 0 && !DEL(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->hasinstr &&
                    pj->nops >= 1 && pj->op0[0] != '\0') {
                    const char *lab = pj->op0;
                    int fire = 0;
                    /* clc / jnc L -> jmp L */
                    if (ci_eq(pi->mnem, "clc") &&
                        (ci_eq(pj->mnem, "jnc") || ci_eq(pj->mnem, "jae") ||
                         ci_eq(pj->mnem, "jnb"))) {
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "jmp ");
                        strcat(g_build, lab);
                        vlog("smartpp: line %ld: 'clc' / jnc rewritten to '%s' (P351)\n",
                            i + 1, g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[351]++;
                        fire = 1;
                    }
                    /* stc / jc L -> jmp L */
                    else if (ci_eq(pi->mnem, "stc") &&
                             (ci_eq(pj->mnem, "jc") || ci_eq(pj->mnem, "jb") ||
                              ci_eq(pj->mnem, "jnae"))) {
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "jmp ");
                        strcat(g_build, lab);
                        vlog("smartpp: line %ld: 'stc' / jc rewritten to '%s' (P352)\n",
                            i + 1, g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[352]++;
                        fire = 1;
                    }
                    /* clc / jc L -> delete jc */
                    else if (ci_eq(pi->mnem, "clc") &&
                             (ci_eq(pj->mnem, "jc") || ci_eq(pj->mnem, "jb") ||
                              ci_eq(pj->mnem, "jnae"))) {
                        vlog("smartpp: line %ld: deleted '%s' after 'clc' (P353)\n",
                            j + 1, L(j));
                        DEL(j) = 1;
                        st[353]++;
                        fire = 1;
                    }
                    /* stc / jnc L -> delete jnc */
                    else if (ci_eq(pi->mnem, "stc") &&
                             (ci_eq(pj->mnem, "jnc") || ci_eq(pj->mnem, "jae") ||
                              ci_eq(pj->mnem, "jnb"))) {
                        vlog("smartpp: line %ld: deleted '%s' after 'stc' (P354)\n",
                            j + 1, L(j));
                        DEL(j) = 1;
                        st[354]++;
                        fire = 1;
                    }
                    /* xor R,R / jz|je L -> jmp L (keep xor; rewrite jcc) */
                    else if ((pi->cls == I_XORRR ||
                              (ci_eq(pi->mnem, "xor") && pi->nops == 2 &&
                               find_reg(pi->op0) >= 0 &&
                               find_reg(pi->op0) == find_reg(pi->op1))) &&
                             (ci_eq(pj->mnem, "jz") || ci_eq(pj->mnem, "je"))) {
                        strcpy(g_build, pj->prefix);
                        strcat(g_build, "jmp ");
                        strcat(g_build, lab);
                        vlog("smartpp: line %ld: 'xor R,R' / jz rewritten to '%s' (P355)\n",
                            j + 1, g_build);
                        replace_line(j, g_build);
                        st[355]++;
                        fire = 1;
                    }
                    /* xor R,R / jnz|jne L -> delete jcc */
                    else if ((pi->cls == I_XORRR ||
                              (ci_eq(pi->mnem, "xor") && pi->nops == 2 &&
                               find_reg(pi->op0) >= 0 &&
                               find_reg(pi->op0) == find_reg(pi->op1))) &&
                             (ci_eq(pj->mnem, "jnz") || ci_eq(pj->mnem, "jne"))) {
                        vlog("smartpp: line %ld: deleted '%s' after 'xor R,R' (P356)\n",
                            j + 1, L(j));
                        DEL(j) = 1;
                        st[356]++;
                        fire = 1;
                    }
                    /* ---- setcc after constant flags (GCC/Clang/MSVC idioms) ----
                     *  xor R,R sets ZF=1,SF=0,PF=1,CF=0,OF=0.
                     *  setz/sete -> 1; setnz/setne -> 0; sets -> 0; setc/setb -> 0. */
                    else if ((pi->cls == I_XORRR ||
                              (ci_eq(pi->mnem, "xor") && pi->nops == 2 &&
                               find_reg(pi->op0) >= 0 &&
                               find_reg(pi->op0) == find_reg(pi->op1))) &&
                             (ci_eq(pj->mnem, "setz") || ci_eq(pj->mnem, "sete") ||
                              ci_eq(pj->mnem, "setnz") || ci_eq(pj->mnem, "setne") ||
                              ci_eq(pj->mnem, "sets") || ci_eq(pj->mnem, "setns") ||
                              ci_eq(pj->mnem, "setc") || ci_eq(pj->mnem, "setb") ||
                              ci_eq(pj->mnem, "setnc") || ci_eq(pj->mnem, "setae") ||
                              ci_eq(pj->mnem, "seto") || ci_eq(pj->mnem, "setno"))) {
                        int val = -1;
                        if (ci_eq(pj->mnem, "setz") || ci_eq(pj->mnem, "sete") ||
                            ci_eq(pj->mnem, "setns") || ci_eq(pj->mnem, "setnc") ||
                            ci_eq(pj->mnem, "setae") || ci_eq(pj->mnem, "setno"))
                            val = 1;
                        else
                            val = 0; /* setnz/setne/sets/setc/setb/seto */
                        if (pj->nops >= 1 && pj->op0[0] != '\0') {
                            strcpy(g_build, pj->prefix);
                            if (val == 0) {
                                /* xor dest,dest is better zeroing if 32/64-bit;
                                 *  for 8-bit setcc dest, mov dest,0 is fine. */
                                strcat(g_build, "mov ");
                                strcat(g_build, pj->op0);
                                strcat(g_build, ", 0");
                            } else {
                                strcat(g_build, "mov ");
                                strcat(g_build, pj->op0);
                                strcat(g_build, ", 1");
                            }
                            vlog("smartpp: line %ld: setcc after 'xor R,R' rewritten to '%s' (P360)\n",
                                j + 1, g_build);
                            replace_line(j, g_build);
                            st[360]++;
                            fire = 1;
                        }
                    }
                    /* clc / setc|setb -> mov 0; clc / setnc|setae -> mov 1 */
                    else if (ci_eq(pi->mnem, "clc") &&
                             (ci_eq(pj->mnem, "setc") || ci_eq(pj->mnem, "setb") ||
                              ci_eq(pj->mnem, "setnc") || ci_eq(pj->mnem, "setae") ||
                              ci_eq(pj->mnem, "setnb"))) {
                        int val = (ci_eq(pj->mnem, "setnc") ||
                                   ci_eq(pj->mnem, "setae") ||
                                   ci_eq(pj->mnem, "setnb")) ? 1 : 0;
                        if (pj->nops >= 1 && pj->op0[0] != '\0') {
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "mov ");
                            strcat(g_build, pj->op0);
                            strcat(g_build, val ? ", 1" : ", 0");
                            vlog("smartpp: line %ld: setcc after 'clc' rewritten to '%s' (P361)\n",
                                j + 1, g_build);
                            replace_line(j, g_build);
                            st[361]++;
                            fire = 1;
                        }
                    }
                    /* stc / setc|setb -> mov 1; stc / setnc -> mov 0 */
                    else if (ci_eq(pi->mnem, "stc") &&
                             (ci_eq(pj->mnem, "setc") || ci_eq(pj->mnem, "setb") ||
                              ci_eq(pj->mnem, "setnc") || ci_eq(pj->mnem, "setae") ||
                              ci_eq(pj->mnem, "setnb"))) {
                        int val = (ci_eq(pj->mnem, "setc") ||
                                   ci_eq(pj->mnem, "setb")) ? 1 : 0;
                        if (pj->nops >= 1 && pj->op0[0] != '\0') {
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "mov ");
                            strcat(g_build, pj->op0);
                            strcat(g_build, val ? ", 1" : ", 0");
                            vlog("smartpp: line %ld: setcc after 'stc' rewritten to '%s' (P362)\n",
                                j + 1, g_build);
                            replace_line(j, g_build);
                            st[362]++;
                            fire = 1;
                        }
                    }
                    if (fire) continue;
                }
            }
        }


        /* ---- v2.21: lea R,[S+S] -> lea R,[S*2] (386+ SIB scale) ----
         *  Compilers emit [S*2] or [S+S]; canonicalize to scale form. */
        if (!pi->toobig && !pi->haslabel && pi->cls == I_LEA &&
            pi->nops == 2 && g_curcpu >= 8 /* 386 */) {
            int r1 = -1, r2 = -1;
            long disp = 0;
            if (lea_two_regs(pi->op1, &r1, &r2, &disp) &&
                r1 >= 0 && r2 >= 0 &&
                g_regs[r1].fam == g_regs[r2].fam &&
                disp == 0) {
                char operand[MAXTOK];
                /* Emit [S*2] or [S+S*1] - prefer scale */
                if (g_att)
                    sprintf(operand, "(,%%%s,2)", g_regs[r1].name);
                else
                    sprintf(operand, "[%s*2]", g_regs[r1].name);
                strcpy(g_build, pi->prefix);
                strcat(g_build, "lea ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", ");
                strcat(g_build, operand);
                if (pi->comment[0] != 0) {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'lea %s, %s' canonicalized to '%s' (P365)\n",
                    i + 1, pi->op0, pi->op1, g_build);
                replace_line(i, g_build);
                st[365]++;
                continue;
            }
        }

        /* ---- v2.21: cmov after constant flags (P6+) ----
         *  xor R,R => ZF=1, CF=0, SF=0, OF=0
         *  cmovz/cmove  dest,src -> mov dest,src (always)
         *  cmovnz/cmovne dest,src -> delete (never; dest unchanged)
         *  cmovc/cmovb -> delete; cmovnc/cmovae -> mov
         *  cmovs -> delete; cmovns -> mov
         *  cmovo -> delete; cmovno -> mov */
        if (g_curcpu >= 64 && !pi->toobig && !pi->haslabel && pi->hasinstr) {
            int is_xor0 = (pi->cls == I_XORRR ||
                (ci_eq(pi->mnem, "xor") && pi->nops == 2 &&
                 find_reg(pi->op0) >= 0 &&
                 find_reg(pi->op0) == find_reg(pi->op1)));
            int is_clc = ci_eq(pi->mnem, "clc");
            int is_stc = ci_eq(pi->mnem, "stc");
            if (is_xor0 || is_clc || is_stc) {
                long j = next_code(i);
                if (j >= 0 && !DEL(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig && pj->hasinstr &&
                        ci_eq_n(pj->mnem, "cmov", 4) && pj->nops == 2) {
                        const char *cc = pj->mnem + 4; /* after "cmov" */
                        int always = 0, never = 0;
                        if (is_xor0) {
                            /* ZF=1 SF=0 CF=0 OF=0 */
                            if (ci_eq(cc, "z") || ci_eq(cc, "e")) always = 1;
                            else if (ci_eq(cc, "nz") || ci_eq(cc, "ne")) never = 1;
                            else if (ci_eq(cc, "s") || ci_eq(cc, "c") ||
                                     ci_eq(cc, "b") || ci_eq(cc, "o") ||
                                     ci_eq(cc, "nae") || ci_eq(cc, "l") ||
                                     ci_eq(cc, "nge")) never = 1;
                            else if (ci_eq(cc, "ns") || ci_eq(cc, "nc") ||
                                     ci_eq(cc, "ae") || ci_eq(cc, "nb") ||
                                     ci_eq(cc, "no") || ci_eq(cc, "ge") ||
                                     ci_eq(cc, "nl")) always = 1;
                        } else if (is_clc) {
                            /* CF=0 */
                            if (ci_eq(cc, "c") || ci_eq(cc, "b") ||
                                ci_eq(cc, "nae")) never = 1;
                            else if (ci_eq(cc, "nc") || ci_eq(cc, "ae") ||
                                     ci_eq(cc, "nb")) always = 1;
                        } else if (is_stc) {
                            /* CF=1 */
                            if (ci_eq(cc, "c") || ci_eq(cc, "b") ||
                                ci_eq(cc, "nae")) always = 1;
                            else if (ci_eq(cc, "nc") || ci_eq(cc, "ae") ||
                                     ci_eq(cc, "nb")) never = 1;
                        }
                        if (always) {
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "mov ");
                            strcat(g_build, pj->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, pj->op1);
                            vlog("smartpp: line %ld: cmov with known flags rewritten to '%s' (P366)\n",
                                j + 1, g_build);
                            replace_line(j, g_build);
                            st[366]++;
                            continue;
                        }
                        if (never) {
                            vlog("smartpp: line %ld: deleted cmov with known flags (P367)\n",
                                j + 1);
                            DEL(j) = 1;
                            st[367]++;
                            continue;
                        }
                    }
                }
            }
        }


        /* ---- v2.22 (-Ox): widen string ops when count is constant ----
         *  mov CX/ECX, N  ...  rep movsb/stosb/lodsb
         *  If N is divisible by 2 (or 4), use movsw/stosw/lodsw (or
         *  dword forms on 386+).  NOT applied to ins/outs: port width
         *  would change and that is not equivalent for devices.
         *
         *  Safety: -Ox only (alignment / overlapping movs can matter
         *  on real-mode odd pointers; modern CPUs tolerate unaligned
         *  but behavior with DF=1 and overlap can differ by element
         *  size).  Count register must not be written in the window. */
        if (opt_aggressive && !pi->toobig && !pi->haslabel &&
            pi->cls == I_MOV && pi->srcimm && pi->dreg >= 0) {
            int cfam = g_regs[pi->dreg].fam;
            long cnt;
            /* CX family = 1 in typical tables; also accept ECX/RCX by name */
            if ((cfam == 1 || ci_eq(g_regs[pi->dreg].name, "cx") ||
                 ci_eq(g_regs[pi->dreg].name, "ecx") ||
                 ci_eq(g_regs[pi->dreg].name, "rcx")) &&
                try_parse_number(pi->op1, & cnt) && cnt > 0) {
                long k = next_code(i);
                int steps = 0;
                #define STR_WIDEN_WIN 8
                while (k >= 0 && steps < STR_WIDEN_WIN) {
                    struct pinfo *pk = &g_pscan;
                    const char *base = NULL; /* "movs" / "stos" / "lods" */
                    char width = 0;          /* 'b','w','d','q' */
                    int has_rep = 0;
                    int dk;
                    if (DEL(k)) { k = next_code(k); continue; }
                    parse_line(k, pk);
                    if (pk->haslabel) break;
                    if (!pk->hasinstr) { k = next_code(k); steps++; continue; }
                    if (pk->toobig || pk->mnem[0] == '.') break;
                    if (pk->cls == I_JMP || pk->cls == I_JCC ||
                        ci_eq(pk->mnem, "call") || ci_eq(pk->mnem, "ret") ||
                        ci_eq(pk->mnem, "retn") || ci_eq(pk->mnem, "retf"))
                        break;
                    /* count reg written?  v2.18: removed the
                     *  !(mov && srcimm) carve-out -- "mov CX,M"
                     *  redefines CX and must break the window, or
                     *  P370 would widen using the OLD count N while
                     *  the actual count at the rep is M. */
                    dk = find_reg(pk->op0);
                    if (dk >= 0 && g_regs[dk].fam == cfam) {
                        /* any RMW or redef of CX family */
                        if (!ci_eq_n(pk->mnem, "movs", 4) &&
                            !ci_eq_n(pk->mnem, "stos", 4) &&
                            !ci_eq_n(pk->mnem, "lods", 4) &&
                            !ci_eq(pk->mnem, "rep") &&
                            !ci_eq(pk->mnem, "repz") &&
                            !ci_eq(pk->mnem, "repne"))
                            break;
                    }
                    /* Identify string op: "rep movsb" or mnem movsb */
                    if (ci_eq(pk->mnem, "rep") || ci_eq(pk->mnem, "repz") ||
                        ci_eq(pk->mnem, "repne") || ci_eq(pk->mnem, "repnz")) {
                        has_rep = 1;
                        if (ci_eq_n(pk->op0, "movs", 4)) base = "movs";
                        else if (ci_eq_n(pk->op0, "stos", 4)) base = "stos";
                        else if (ci_eq_n(pk->op0, "lods", 4)) base = "lods";
                        if (base) {
                            char last = pk->op0[strlen(pk->op0) - 1];
                            if (last == 'b' || last == 'w' || last == 'd' ||
                                last == 'q')
                                width = last;
                            else if (ci_eq(pk->op0, "movs") ||
                                     ci_eq(pk->op0, "stos") ||
                                     ci_eq(pk->op0, "lods"))
                                width = 'b'; /* default byte in some ASMs */
                        }
                    } else if (ci_eq_n(pk->mnem, "movs", 4) ||
                               ci_eq_n(pk->mnem, "stos", 4) ||
                               ci_eq_n(pk->mnem, "lods", 4)) {
                        /* optional: look back for rep on previous - skip
                         *  for simplicity require "rep xxx" same line */
                        if (ci_eq_n(pk->mnem, "movs", 4)) base = "movs";
                        else if (ci_eq_n(pk->mnem, "stos", 4)) base = "stos";
                        else base = "lods";
                        {
                            char last = pk->mnem[strlen(pk->mnem) - 1];
                            if (last == 'b' || last == 'w' || last == 'd' ||
                                last == 'q')
                                width = last;
                            else
                                width = 'b';
                        }
                        /* Only upgrade if this line has rep prefix in
                         *  the raw text (cheap check). */
                        if (strstr(L(k), "rep") == NULL &&
                            strstr(L(k), "REP") == NULL)
                            base = NULL;
                        else
                            has_rep = 1;
                    }
                    if (base && has_rep && width != 0) {
                        long newcnt = 0;
                        char neww = 0;
                        /* Prefer largest legal width */
                        if (width == 'b') {
                            if (g_curcpu >= 8 && (cnt % 4) == 0) {
                                newcnt = cnt / 4; neww = 'd';
                            } else if ((cnt % 2) == 0) {
                                newcnt = cnt / 2; neww = 'w';
                            }
                        } else if (width == 'w') {
                            if (g_curcpu >= 8 && (cnt % 2) == 0) {
                                newcnt = cnt / 2; neww = 'd';
                            }
                        }
                        /* q forms: only if already on x64 and count even
                         *  from dword - skip for conservatism */
                        if (neww && newcnt > 0) {
                            char newimm[32];
                            char newstr[32];
                            sprintf(newimm, "%ld", newcnt);
                            sprintf(newstr, "%s%c", base, neww);
                            /* rewrite count */
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "mov ");
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, newimm);
                            replace_line(i, g_build);
                            /* rewrite string insn */
                            strcpy(g_build, pk->prefix);
                            if (ci_eq(pk->mnem, "rep") ||
                                ci_eq(pk->mnem, "repz") ||
                                ci_eq(pk->mnem, "repne") ||
                                ci_eq(pk->mnem, "repnz")) {
                                strcat(g_build, pk->mnem);
                                strcat(g_build, " ");
                                strcat(g_build, newstr);
                            } else {
                                strcat(g_build, "rep ");
                                strcat(g_build, newstr);
                            }
                            replace_line(k, g_build);
                            st[370]++;
                            vlog("smartpp: line %ld/%ld: widen string %s -> %s count %ld -> %ld (-Ox P370)\n",
                                i + 1, k + 1, base, newstr, cnt, newcnt);
                            steps = STR_WIDEN_WIN; /* end window */
                            break; /* one widen per count load */
                        }
                    }
                    k = next_code(k);
                    steps++;
                }
                #undef STR_WIDEN_WIN
                continue;  /* v2.18: stale pi (old count) would make
                            *  P79/P87 fire with the wrong immediate */
            }
        }


        /* ---- v2.23: not R / add R,1 -> neg R (flags dead) ---- */
        if (!pi->toobig && !pi->haslabel && ci_eq(pi->mnem, "not") &&
            pi->nops == 1 && find_reg(pi->op0) >= 0) {
            long j = next_code(i);
            if (j >= 0 && !DEL(j)) {
                struct pinfo *pj = &g_ppair;
                long v;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    ci_eq(pj->mnem, "add") && pj->nops == 2 &&
                    find_reg(pj->op0) == find_reg(pi->op0) &&
                    try_parse_number(pj->op1, &v) && v == 1 &&
                    flags_clear(next_code(j), F_ALL6)) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "neg ");
                    strcat(g_build, pi->op0);
                    vlog("smartpp: line %ld: 'not' / 'add R,1' folded to '%s' (P371)\n",
                        i + 1, g_build);
                    replace_line(i, g_build);
                    DEL(j) = 1;
                    st[371]++;
                    continue;
                }
            }
        }

        /* ---- v2.23: rol R,k / ror R,k (same k) -> delete both ---- */
        if (!pi->toobig && !pi->haslabel &&
            (ci_eq(pi->mnem, "rol") || ci_eq(pi->mnem, "ror")) &&
            pi->nops == 2 && find_reg(pi->op0) >= 0) {
            long j = next_code(i);
            long k1, k2;
            if (j >= 0 && !DEL(j) &&
                try_parse_number(pi->op1, &k1)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->nops == 2 &&
                    find_reg(pj->op0) == find_reg(pi->op0) &&
                    try_parse_number(pj->op1, &k2) && k1 == k2 &&
                    ((ci_eq(pi->mnem, "rol") && ci_eq(pj->mnem, "ror")) ||
                     (ci_eq(pi->mnem, "ror") && ci_eq(pj->mnem, "rol"))) &&
                    flags_clear(next_code(j), F_ALL6)) {
                    vlog("smartpp: line %ld: deleted 'rol'/'ror' pair (P373)\n",
                        i + 1);
                    DEL(i) = 1;
                    DEL(j) = 1;
                    st[373]++;
                    continue;
                }
            }
        }

        /* ---- v2.23: cmp R,R -> constant-flag jcc ----
         *  ZF=1, CF=0, SF=0, OF=0 (equal). */
        if (!pi->toobig && !pi->haslabel && ci_eq(pi->mnem, "cmp") &&
            pi->nops == 2) {
            int r0 = find_reg(pi->op0), r1 = find_reg(pi->op1);
            if (r0 >= 0 && r0 == r1) {
                long j = next_code(i);
                if (j >= 0 && !DEL(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig && pj->nops >= 1 &&
                        pj->op0[0] != 0) {
                        const char *lab = pj->op0;
                        int always = 0, never = 0;
                        /* equal: ZF=1 CF=0 SF=0 OF=0 */
                        if (ci_eq(pj->mnem, "je") || ci_eq(pj->mnem, "jz") ||
                            ci_eq(pj->mnem, "jae") || ci_eq(pj->mnem, "jnb") ||
                            ci_eq(pj->mnem, "jnc") || ci_eq(pj->mnem, "jge") ||
                            ci_eq(pj->mnem, "jnl") || ci_eq(pj->mnem, "jbe") ||
                            ci_eq(pj->mnem, "jna") || ci_eq(pj->mnem, "jle") ||
                            ci_eq(pj->mnem, "jng"))
                            always = 1;
                        else if (ci_eq(pj->mnem, "jne") || ci_eq(pj->mnem, "jnz") ||
                                 ci_eq(pj->mnem, "jb") || ci_eq(pj->mnem, "jnae") ||
                                 ci_eq(pj->mnem, "jc") || ci_eq(pj->mnem, "jl") ||
                                 ci_eq(pj->mnem, "jnge") || ci_eq(pj->mnem, "ja") ||
                                 ci_eq(pj->mnem, "jnbe") || ci_eq(pj->mnem, "jg") ||
                                 ci_eq(pj->mnem, "jnle"))
                            never = 1;
                        if (always) {
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "jmp ");
                            strcat(g_build, lab);
                            vlog("smartpp: line %ld: jcc after 'cmp R,R' rewritten to '%s' (P377)\n",
                                j + 1, g_build);
                            replace_line(j, g_build);
                            st[377]++;
                            continue;
                        }
                        if (never) {
                            vlog("smartpp: line %ld: deleted jcc after 'cmp R,R' (P378)\n",
                                j + 1);
                            DEL(j) = 1;
                            st[378]++;
                            continue;
                        }
                    }
                }
            }
        }


        /* ---- v2.14: imul R,K / imul R,S,K -> lea/shl strength reduction
         *  (386+, flags dead, Intel syntax).  v2.20: now handles the
         *  3-operand form "imul R, S, K" (R = S * K) as well as the
         *  2-operand form "imul R, K" (R = R * K).  The LEA uses S
         *  as the base/index for the 3-operand form.
         *  Unified engine: absorbs the old C rule P50 and P380.
         *  Decompose K = m * 2^a with m odd:
         *    m == 1     -> handled earlier by P38 (shl R,a / delete)
         *    m == 3/5/9 -> lea R,[S+S*(m-1)]                 (+ shl R,a)
         *    m == 7     -> lea T,[S+S*2];  lea R,[S+T*2]     (+ shl R,a)
         *    m == 11    -> lea T,[S+S*4];  lea R,[S+T*2]     (+ shl R,a)
         *    m == 13    -> lea T,[S+S*2];  lea R,[S+T*4]     (+ shl R,a)
         *    m == 15    -> lea T,[S+S*2];  lea R,[T+T*4]     (+ shl R,a)
         *  T is a scratch register of the same width that reg_dead_cf
         *  proves dead after the imul; the inserted leas write T before
         *  any existing instruction can read it, so the scan stays
         *  valid.  Every emitted op except the optional final shl is a
         *  lea (flag-neutral); the original imul defined the flags too,
         *  so flags_clear(F_ALL6) is required in all cases.
         *  Width gate: the SIB byte's scaled-index form needs 32-bit
         *  registers (or 64-bit on x64); 16-bit addressing has no SIB,
         *  and ESP/RSP cannot be an index (SIB index field 4 means "no
         *  index").  This closes the v2.24 hole where a 16-bit imul
         *  emitted the unencodable "[ax+ax*2]".
         *  Covers 3,5,6,7,9,10,11,12,13,14,15 and every m*2^a form of
         *  those (18, 20, 24, 28, 30, 36, 40, 56, ...). */
        if (!pi->toobig && !pi->haslabel && !g_att &&
            ci_eq(pi->mnem, "imul") &&
            (pi->nops == 2 || pi->nops == 3) &&
            find_reg(pi->op0) >= 0 && g_curcpu >= 8) {
            long v;
            int dst_r = find_reg(pi->op0);
            int src_r;              /* source register for the LEA base */
            const char *src_name;   /* source register name */
            int w = g_regs[dst_r].hi - g_regs[dst_r].lo;

            /* v2.20: extract source and immediate based on operand count.
             *  2-operand "imul R, K": src = R, imm = op1
             *  3-operand "imul R, S, K": src = S, imm = op2 */
            if (pi->nops == 3) {
                src_r = find_reg(pi->op1);
                if (src_r < 0) goto skip_imul380;
                src_name = pi->op1;
                if (!try_parse_number(pi->op2, &v)) goto skip_imul380;
            } else {
                src_r = dst_r;
                src_name = pi->op0;
                if (!try_parse_number(pi->op1, &v)) goto skip_imul380;
            }

            if ((w == 32 || (w == 64 && g_curcpu >= 128)) &&
                g_regs[dst_r].fam != 4 &&
                g_regs[src_r].fam != 4 &&   /* SIB index can't be SP */
                v > 1 &&
                flags_clear(next_code(i), F_ALL6)) {
                long m = v;
                int a = 0;
                char opnd[MAXTOK];
                while ((m & 1L) == 0) { m >>= 1; a++; }
                if (m == 3 || m == 5 || m == 9) {
                    /* single lea, optional trailing shl */
                    emit_lea_scaled(opnd, src_r, (int)(m - 1));
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "lea ");
                    strcat(g_build, pi->op0);       /* dest */
                    strcat(g_build, ", ");
                    strcat(g_build, opnd);          /* [src+src*k] */
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'imul %s, %s, %ld' -> 'lea %s, %s'%s (P380)\n",
                        i + 1, pi->op0, src_name, v, pi->op0, opnd,
                        a > 0 ? " + shl" : "");
                    replace_line(i, g_build);
                    if (a > 0) {
                        char shln[MAXTOK];
                        char nb[16];
                        strcpy(shln, pi->prefix);
                        strcat(shln, "shl ");
                        strcat(shln, pi->op0);
                        strcat(shln, ", ");
                        sprintf(nb, "%d", a);
                        strcat(shln, nb);
                        insert_line_after(i, shln);
                    }
                    st[380]++;
                    continue;
                }
                else {
                    /* v2.16: table-driven two-lea factors -- 7, 11, 13,
                     *  15 (as before) plus 17, 19, 21, 25, 27, 37, 41,
                     *  45, 73 and 81, through a dead scratch register */
                    const struct imul2_s *t2 = imul2_tab;
                    while (t2->m != 0 && t2->m != m) t2++;
                    if (t2->m != 0) {
                        int t = find_dead_scratch(next_code(i), dst_r, w);
                        if (t >= 0) {
                            char shln[MAXTOK];
                            char nb[16];
                            /* T = src + src*t_s */
                            sprintf(g_build, "%slea %s, ", pi->prefix,
                                g_regs[t].name);
                            emit_lea_scaled(opnd, src_r, t2->t_s);
                            strcat(g_build, opnd);
                            if (pi->comment[0] != 0) {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: 'imul %s, %s, %ld' -> 'lea %s, %s' + 'lea %s, ...'%s (P380)\n",
                                i + 1, pi->op0, src_name, v, g_regs[t].name, opnd,
                                pi->op0, a > 0 ? " + shl" : "");
                            replace_line(i, g_build);
                            /* R = base + T*f_s  (base = R or T) */
                            sprintf(g_build, "%slea %s, [%s+%s*%d]",
                                pi->prefix, pi->op0,
                                t2->fx_is_t ? g_regs[t].name : src_name,
                                g_regs[t].name, t2->f_s);
                            insert_line_after(i, g_build);
                            if (a > 0) {
                                strcpy(shln, pi->prefix);
                                strcat(shln, "shl ");
                                strcat(shln, pi->op0);
                                strcat(shln, ", ");
                                sprintf(nb, "%d", a);
                                strcat(shln, nb);
                                insert_line_after(i + 1, shln);
                            }
                            st[380]++;
                            continue;
                        }
                    }
                }
            }
            skip_imul380: ;
        }
        /* ---- v2.24: LEA CSE in short window ----
         *  lea R,[expr] ... lea S,[same expr] -> mov S,R if R not written
         *  and S not SP.  Linear window of 8. */
        if (!pi->toobig && !pi->haslabel && pi->cls == I_LEA &&
            pi->nops == 2 && pi->dreg >= 0 &&
            g_regs[pi->dreg].fam != 4) {
            long k = next_code(i);
            int steps = 0;
            int fam_r = g_regs[pi->dreg].fam;
            while (k >= 0 && steps < 8) {
                struct pinfo *pk = &g_pscan;
                int dk;
                if (DEL(k)) { k = next_code(k); continue; }
                parse_line(k, pk);
                if (pk->haslabel) break;
                if (!pk->hasinstr) { k = next_code(k); steps++; continue; }
                if (pk->toobig || pk->mnem[0] == '.') break;
                if (pk->cls == I_JMP || pk->cls == I_JCC ||
                    ci_eq(pk->mnem, "call") || ci_eq(pk->mnem, "ret") ||
                    ci_eq(pk->mnem, "retn") || ci_eq(pk->mnem, "retf"))
                    break;
                dk = find_reg(pk->op0);
                if (pk->cls == I_LEA && pk->nops == 2 && pk->dreg >= 0 &&
                    lea_expr_eq(pk->op1, pi->op1) &&
                    pk->dreg != pi->dreg &&
                    g_regs[pk->dreg].fam != 4) {
                    /* same address expr -> mov S, R */
                    strcpy(g_build, pk->prefix);
                    strcat(g_build, "mov ");
                    strcat(g_build, pk->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, pi->op0);
                    vlog("smartpp: line %ld: duplicate LEA rewritten to '%s' (P381)\n",
                        k + 1, g_build);
                    replace_line(k, g_build);
                    st[381]++;
                    break;
                }
                /* R written -> stop */
                if (dk >= 0 && g_regs[dk].fam == fam_r)
                    break;
                k = next_code(k);
                steps++;
            }
        }

        /* ---- v2.24: mov R,S / lea T,[R+disp] with R dead -> lea T,[S+disp]
         *  (S and T registers, Intel syntax). */
        if (!pi->toobig && !pi->haslabel && !g_att &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->sreg >= 0 &&
            pi->dreg != pi->sreg) {
            long j = next_code(i);
            if (j >= 0 && !DEL(j)) {
                struct pinfo *pj = &g_ppair;
                int base;
                long disp;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_LEA &&
                    pj->nops == 2 &&
                    lea_bracket(pj->op1, &base, &disp) &&
                    base == pi->dreg &&
                    find_reg(pj->op0) != pi->dreg &&
                    reg_dead_cf(next_code(j), pi->dreg)) {
                    char opnd[MAXTOK];
                    emit_lea_disp(opnd, pi->sreg, disp);
                    strcpy(g_build, pj->prefix);
                    strcat(g_build, "lea ");
                    strcat(g_build, pj->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, opnd);
                    vlog("smartpp: line %ld: 'mov %s, %s' / 'lea %s, [%s+d]' folded to 'lea %s, %s' (P382)\n",
                        j + 1, pi->op0, pi->op1,
                        pj->op0, pi->op0, pj->op0, opnd);
                    replace_line(j, g_build);
                    /* mov may still be needed if S was only for lea - if
                     *  R was only used for lea and is dead, also delete mov */
                    /* mov becomes dead if nothing else reads R after it;
                     *  scan from the line after mov (the lea is rewritten). */
                    if (reg_dead_cf(next_code(i), pi->dreg)) {
                        DEL(i) = 1;
                    }
                    st[382]++;
                    continue;
                }
            }
        }

        /* ---- v2.24 (-Ox): call F / ret -> jmp F (tail call) ----
         *  No intervening instruction.  Conservative: same label form.
         *
         *  v2.14 SOUNDNESS GUARD: "call F / ret" is only equivalent to
         *  "jmp F" when the stack at the call is exactly at function-
         *  entry depth, i.e. [esp] already points at OUR return
         *  address.  If the path pushed anything since the last
         *  boundary (arguments for a stdcall F, saved registers,
         *  locals), F's "ret N" would pop that payload in the original
         *  but the top argument in the rewritten form -- a miscompile.
         *  tailcall_stack_ok() walks backwards accumulating the esp
         *  delta and fires when the walk reaches the entry boundary
         *  with delta 0.  It also accepts a sound epilogue: a
         *  "mov sp,bp / pop bp" pair (or "leave") immediately before
         *  the call, when the matching "push bp / mov bp,sp" prologue
         *  is found further up -- esp is then restored absolutely, so
         *  the delta at the call is entry depth by construction.  The
         *  call-first form ("call F / add esp,N / ret") is NOT
         *  rewritten: F's stack arguments would be discarded. */
        if (opt_aggressive && !pi->toobig && !pi->haslabel &&
            ci_eq(pi->mnem, "call") && pi->nops == 1 &&
            tailcall_stack_ok(i)) {
            long j = next_code(i);
            if (j >= 0 && !DEL(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    (ci_eq(pj->mnem, "ret") || ci_eq(pj->mnem, "retn")) &&
                    pj->nops == 0) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "jmp ");
                    strcat(g_build, pi->op0);
                    vlog("smartpp: line %ld: tail-call 'call %s' / 'ret' -> 'jmp %s' (P383)\n",
                        i + 1, pi->op0, pi->op0);
                    replace_line(i, g_build);
                    DEL(j) = 1;
                    st[383]++;
                    continue;
                }
            }
        }

        /* ---- v2.16 (-Ox): tail call across the epilogue ----
         *  call F / mov sp,bp / pop bp / ret   (or: call F / leave / ret)
         *  -> mov sp,bp / pop bp / jmp F
         *  The restoration is kept and runs before F; see
         *  tailcall_epilogue_ok() for the soundness proof. */
        if (opt_aggressive && !pi->toobig && !pi->haslabel &&
            ci_eq(pi->mnem, "call") && pi->nops == 1) {
            long tcl = -1;
            if (tailcall_epilogue_ok(i, &tcl)) {
                char tgt[MAXTOK];
                struct pinfo *pk = &g_pscan;
                strcpy(tgt, pi->op0);
                parse_line(tcl, pk);
                strcpy(g_build, pk->prefix);
                strcat(g_build, "jmp ");
                strcat(g_build, tgt);
                vlog("smartpp: line %ld: tail-call 'call %s' / epilogue / 'ret' -> epilogue + 'jmp %s' (P383)\n",
                    i + 1, tgt, tgt);
                replace_line(tcl, g_build);
                DEL(i) = 1;
                st[383]++;
                continue;
            }
        }

        /* ---- v2.24 (-Ox): partial reg - movzx R32, R8 after xor R32,R32
         *  is redundant if only low byte was written by setcc etc - skip.
         *  Safer: on x64, mov eax,eax is nop (P1). movzx rax,eax after
         *  32-bit write: delete movzx when source is 32-bit half of dest. */
        if (g_curcpu >= 128 && !pi->toobig && !pi->haslabel &&
            (ci_eq(pi->mnem, "movzx") || ci_eq(pi->mnem, "movsx")) &&
            pi->nops == 2) {
            int d = find_reg(pi->op0), s = find_reg(pi->op1);
            if (d >= 0 && s >= 0 && g_regs[d].fam == g_regs[s].fam) {
                int wd = g_regs[d].hi - g_regs[d].lo;
                int ws = g_regs[s].hi - g_regs[s].lo;
                /* movzx rax, eax: 32-bit write already zero-extends on x64 */
                if (ci_eq(pi->mnem, "movzx") && wd == 64 && ws == 32) {
                    vlog("smartpp: line %ld: deleted redundant 'movzx %s, %s' (P384)\n",
                        i + 1, pi->op0, pi->op1);
                    DEL(i) = 1;
                    st[384]++;
                    continue;
                }
            }
        }


        /* ---- P387 (v2.14, REMOVED): "or R,R / and R,R -> test R,R".
         *  Dead code: the C rule P8 (earlier in run_pass) already
         *  rewrites every "or R,R" / "and R,R" (any width) to
         *  "test R,R", or deletes it when all flags are dead, so this
         *  fallback never fired.  See rname[387]. */

        /* ---- v2.15: rules implemented after the coverage review -----
         *  P17, P41, P47, P56, P63, P68, P70, P79, P80, P82 and
         *  P85-P87 were documented in this header but had no code
         *  behind them: their helper parsers (lea_bracket,
         *  lea_two_regs, lea_scaled_single, emit_lea_disp,
         *  width_imm_limit) sat unreferenced in smartpp_kept_helpers
         *  since the v1.85 table refactor.  They are implemented
         *  below.  P57 is NOT reinstated: the v2.21 rule P365 already
         *  canonicalizes "lea R,[S+S]" to "lea R,[S*2]" and P63 below
         *  folds the scaled form to "shl R,log2 K", so a separate P57
         *  could never fire; see rname[57]. */

        /* P17 (v1.30, extended v1.40; implemented v2.15): FPC's LEA
         *  conversion.
         *    "lea R,[const]"       ->  "mov R,const"  (exact, no scan)
         *    "lea R,[S]" / "[S+0]" ->  "mov R,S"      (equal width;
         *                              exact: lea computes the offset
         *                              only, no segment is involved)
         *    "lea R,[R]" / "[R+0]" ->  deleted (old P124; lea touches
         *                              no flag and no memory)
         *    "lea R,[R+1]"         ->  "inc R"  (CF survives inc/dec,
         *                              matching lea, so only
         *                              SZAPC+OF must be dead)
         *    "lea R,[R-1]"         ->  "dec R"   (same gate)
         *    "lea R,[R+c]"         ->  "add R,c" / "sub R,-c" (all six
         *                              flags dead; the constant must
         *                              re-encode at R's width)
         *  16-bit bases are restricted to BX/BP/SI/DI (the only legal
         *  16-bit addressing registers); 32-bit bases need the 386+
         *  addressing forms. */
        if (!pi->toobig && pi->cls == I_LEA && pi->nops == 2 &&
            pi->dreg >= 0) {
            int w17 = reg_width(pi->dreg);
            int b17;
            long d17;
            if ((w17 == 16 || w17 == 32) &&
                lea_bracket(pi->op1, &b17, &d17)) {
                if (b17 < 0) {
                    /* "lea R,[const]" -> "mov R,const" (exact); the
                     *  constant must fit R's width.  v2.17: the 32-bit
                     *  case is always satisfiable because d17 is a
                     *  signed long (32-bit on every target SMARTPP
                     *  builds for), so the old bounds check
                     *  (d17 >= INT32_MIN && d17 <= 0xFFFFFFFF) was
                     *  tautological and tripped W124 ("Comparison
                     *  result always 1") on Watcom -- 0xFFFFFFFFL
                     *  promotes the signed d17 to unsigned long for
                     *  the upper-bound test, which is then always
                     *  true.  For 16-bit destinations the real
                     *  range check stays. */
                    char num[32];
                    int fit17 = (w17 == 16)
                        ? (d17 >= -0x8000L && d17 <= 0xFFFFL)
                        : 1;
                    if (fit17) {
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "mov ");
                        if (g_att) {
                            strcat(g_build, "$");
                            sprintf(num, "%ld", d17);
                            strcat(g_build, num);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op0);
                        } else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            sprintf(num, "%ld", d17);
                            strcat(g_build, num);
                        }
                        if (pi->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P17)\n",
                            i + 1, pi->op0, pi->op1, g_build);
                        replace_line(i, g_build);
                        st[17]++;
                        continue;
                    }
                }
                if (lea_base_ok(b17, w17)) {
                    if (d17 == 0) {
                        if (b17 == pi->dreg) {
                            /* "lea R,[R]" / "[R+0]" -> delete (P124) */
                            vlog("smartpp: line %ld: deleted 'lea %s, %s' (identity, P17)\n",
                                i + 1, pi->op0, pi->op1);
                            DEL(i) = 1;
                            st[17]++;
                            continue;
                        }
                        if (reg_width(b17) == w17) {
                            /* "lea R,[S]" -> "mov R,S" (exact) */
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "mov ");
                            if (g_att) {
                                strcat(g_build, "%");
                                strcat(g_build, g_regs[b17].name);
                                strcat(g_build, ", ");
                                strcat(g_build, pi->op0);
                            } else {
                                strcat(g_build, pi->op0);
                                strcat(g_build, ", ");
                                strcat(g_build, g_regs[b17].name);
                            }
                            if (pi->comment[0] != 0) {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P17)\n",
                                i + 1, pi->op0, pi->op1, g_build);
                            replace_line(i, g_build);
                            st[17]++;
                            continue;
                        }
                    }
                    else if (b17 == pi->dreg) {
                        if (d17 == 1 || d17 == -1) {
                            /* CF survives inc/dec, matching lea */
                            if (flags_clear(next_code(i),
                                            F_ALL6 & ~F_CF)) {
                                strcpy(g_build, pi->prefix);
                                strcat(g_build, (d17 == 1) ? "inc " : "dec ");
                                strcat(g_build, pi->op0);
                                if (pi->comment[0] != 0) {
                                    strcat(g_build, " ");
                                    strcat(g_build, pi->comment);
                                }
                                vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P17)\n",
                                    i + 1, pi->op0, pi->op1, g_build);
                                replace_line(i, g_build);
                                st[17]++;
                                continue;
                            }
                        } else {
                            long lim17 = width_imm_limit(w17);
                            long mag17 = (d17 > 0) ? d17 : -d17;
                            if (d17 <= lim17 && mag17 <= lim17 &&
                                flags_clear(next_code(i), F_ALL6)) {
                                char num[32];
                                strcpy(g_build, pi->prefix);
                                if (g_att) {
                                    strcat(g_build,
                                        (d17 > 0) ? "add $" : "sub $");
                                    sprintf(num, "%ld", mag17);
                                    strcat(g_build, num);
                                    strcat(g_build, ", ");
                                    strcat(g_build, pi->op0);
                                } else {
                                    strcat(g_build,
                                        (d17 > 0) ? "add " : "sub ");
                                    strcat(g_build, pi->op0);
                                    strcat(g_build, ", ");
                                    sprintf(num, "%ld", mag17);
                                    strcat(g_build, num);
                                }
                                if (pi->comment[0] != 0) {
                                    strcat(g_build, " ");
                                    strcat(g_build, pi->comment);
                                }
                                vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P17)\n",
                                    i + 1, pi->op0, pi->op1, g_build);
                                replace_line(i, g_build);
                                st[17]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P41 (v1.80; implemented v2.15): "lea R,[R+S]" (two different
         *  registers, equal width, no displacement) -> "add R,S" (all
         *  six flags dead).  Two-register cousin of P17.  Intel-only
         *  (the AT&T two-register form carries an index/scale the
         *  parser refuses).  Pre-386 the only legal 16-bit pairs are
         *  [BX+SI], [BX+DI], [BP+SI], [BP+DI]; 386+ accepts any
         *  32-bit pair. */
        if (!pi->toobig && !pi->haslabel && !g_att &&
            pi->cls == I_LEA && pi->nops == 2 && pi->dreg >= 0 &&
            g_regs[pi->dreg].fam != 4) {
            int w41 = reg_width(pi->dreg);
            int q41, s41;
            long d41;
            if (lea_two_regs(pi->op1, &q41, &s41, &d41) &&
                d41 == 0 && q41 >= 0 && s41 >= 0 && q41 != s41) {
                int dst41 = -1, src41 = -1;
                int pair41 = 0;
                if (q41 == pi->dreg)      { dst41 = q41; src41 = s41; }
                else if (s41 == pi->dreg) { dst41 = s41; src41 = q41; }
                if (w41 == 32) {
                    pair41 = (g_curcpu >= 8 &&
                              lea_base_ok(q41, 32) &&
                              lea_base_ok(s41, 32));
                } else if (w41 == 16) {
                    /* legal 16-bit pairs: {BX,BP} + {SI,DI}, any order */
                    int f1 = g_regs[q41].fam, f2 = g_regs[s41].fam;
                    pair41 = (reg_width(q41) == 16 && reg_width(s41) == 16 &&
                              (((f1 == 3 || f1 == 5) &&
                                (f2 == 6 || f2 == 7)) ||
                               ((f2 == 3 || f2 == 5) &&
                                (f1 == 6 || f1 == 7))));
                }
                if (dst41 >= 0 && pair41 && reg_width(src41) == w41 &&
                    g_regs[src41].fam != 4 &&
                    flags_clear(next_code(i), F_ALL6)) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "add ");
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, g_regs[src41].name);
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P41)\n",
                        i + 1, pi->op0, pi->op1, g_build);
                    replace_line(i, g_build);
                    st[41]++;
                    continue;
                }
            }
        }

        /* P47 (v1.80; implemented v2.15): "mov R,S / add R,imm"
         *  (R != S, equal widths) -> "lea R,[S+imm]" (all six flags
         *  dead).  Inverse of P17.  386+ accepts any same-width pair;
         *  pre-386 only the 16-bit bases BX/BP/SI/DI.  Intel-only
         *  (matching P42/P46/P50). */
        if (!pi->toobig && !pi->haslabel && !g_att &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->sreg >= 0 &&
            pi->dreg != pi->sreg &&
            g_regs[pi->dreg].fam != 4) {
            int w47 = reg_width(pi->dreg);
            if (reg_width(pi->sreg) == w47 &&
                (w47 == 32 ? g_curcpu >= 8
                           : (w47 == 16 &&
                              (g_regs[pi->sreg].fam == 3 ||
                               g_regs[pi->sreg].fam == 5 ||
                               g_regs[pi->sreg].fam == 6 ||
                               g_regs[pi->sreg].fam == 7)))) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long imm47;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "add") &&
                        find_reg(pj->op0) == pi->dreg &&
                        try_parse_number(pj->op1, &imm47) && imm47 != 0 &&
                        flags_clear(next_code(j), F_ALL6)) {
                        char opnd[MAXTOK];
                        emit_lea_disp(opnd, pi->sreg, imm47);
                        strcpy(g_build, pj->prefix);
                        strcat(g_build, "lea ");
                        strcat(g_build, pj->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, opnd);
                        if (pj->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pj->comment);
                        }
                        vlog("smartpp: line %ld: 'mov %s, %s' / 'add %s, %s' rewritten to 'lea %s, %s' (P47)\n",
                            i + 1, pi->op0, pi->op1,
                            pj->op0, pj->op1, pj->op0, opnd);
                        replace_line(j, g_build);
                        DEL(i) = 1;
                        st[47]++;
                        continue;
                    }
                }
            }
        }

        /* P56 (v1.81; implemented v2.15): "add R,c1 / sub R,c2" (or
         *  reverse, mixed, net != 0) -> a single "add R,c1-c2" (or
         *  "sub R,c2-c1").  The intermediate carry/borrow can differ
         *  from the single-op form, so all six flags must be proven
         *  dead.  R must not be SP (parity with P22/P24/P27/P39).  The
         *  net == 0 case is P39's, which runs earlier; the
         *  same-mnemonic case is P16's.  Two-instruction only; mixed
         *  chains reduce step-by-step via the multi-pass loop. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub"))) {
            int r56 = find_reg(pi->op0);
            long c1;
            if (r56 >= 0 && g_regs[r56].fam != 4 &&
                try_parse_number(pi->op1, &c1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long c2;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ((ci_eq(pi->mnem, "add") && ci_eq(pj->mnem, "sub")) ||
                         (ci_eq(pi->mnem, "sub") && ci_eq(pj->mnem, "add"))) &&
                        find_reg(pj->op0) == r56 &&
                        try_parse_number(pj->op1, &c2)) {
                        long net;
                        int ovf = 0;
                        if (ci_eq(pi->mnem, "add")) {
                            if (c1 > 0 && c2 < 0 && c1 - c2 < c1) ovf = 1;
                            net = c1 - c2;
                        } else {
                            if (c2 > 0 && c1 < 0 && c2 - c1 < c2) ovf = 1;
                            net = c2 - c1;
                        }
                        /* net > 0 -> "add R,net"; net < 0 -> "sub R,-net" */
                        if (!ovf && net != 0) {
                            long mag56 = (net > 0) ? net : -net;
                            if (mag56 <= width_imm_limit(reg_width(r56)) &&
                                flags_clear(next_code(j), F_ALL6)) {
                                char num[32];
                                strcpy(g_build, pi->prefix);
                                if (g_att) {
                                    strcat(g_build,
                                        (net > 0) ? "add $" : "sub $");
                                    sprintf(num, "%ld", mag56);
                                    strcat(g_build, num);
                                    strcat(g_build, ", ");
                                    strcat(g_build, pi->op0);
                                } else {
                                    strcat(g_build,
                                        (net > 0) ? "add " : "sub ");
                                    strcat(g_build, pi->op0);
                                    strcat(g_build, ", ");
                                    sprintf(num, "%ld", mag56);
                                    strcat(g_build, num);
                                }
                                if (pi->comment[0] != 0) {
                                    strcat(g_build, " ");
                                    strcat(g_build, pi->comment);
                                }
                                vlog("smartpp: line %ld: '%s %s, %ld' / '%s %s, %ld' folded to '%s' (P56)\n",
                                    i + 1, pi->mnem, pi->op0, c1,
                                    pj->mnem, pj->op0, c2, g_build);
                                replace_line(i, g_build);
                                DEL(j) = 1;
                                st[56]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P63 (v1.82; implemented v2.15): "lea R,[R*K]" (K in {2,4,8};
         *  386+ -- the SIB byte was added with the 386; AT&T form
         *  "(,%R,K)" accepted) -> "shl R, log2 K" (all six flags
         *  dead: lea defines none, shl defines all six).  Generalizes
         *  P57's [R+R] form, which the v2.21 rule P365 first
         *  canonicalizes to [R*2].  ESP/RSP cannot be the index (SIB
         *  index field 4 means "no index"). */
        if (!pi->toobig && pi->cls == I_LEA && pi->nops == 2 &&
            pi->dreg >= 0 && g_curcpu >= 8) {
            int w63 = reg_width(pi->dreg);
            if (w63 == 32 || (w63 == 64 && g_curcpu >= 128)) {
                int s63, sc63;
                if (lea_scaled_single(pi->op1, &s63, &sc63) &&
                    s63 == pi->dreg && g_regs[s63].fam != 4 &&
                    flags_clear(next_code(i), F_ALL6)) {
                    int k63 = (sc63 == 2) ? 1 : (sc63 == 4) ? 2 : 3;
                    char num[32];
                    strcpy(g_build, pi->prefix);
                    if (g_att) {
                        strcat(g_build, "shl $");
                        sprintf(num, "%d", k63);
                        strcat(g_build, num);
                        strcat(g_build, ", ");
                        strcat(g_build, pi->op0);
                    } else {
                        strcat(g_build, "shl ");
                        strcat(g_build, pi->op0);
                        strcat(g_build, ", ");
                        sprintf(num, "%d", k63);
                        strcat(g_build, num);
                    }
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P63)\n",
                        i + 1, pi->op0, pi->op1, g_build);
                    replace_line(i, g_build);
                    st[63]++;
                    continue;
                }
            }
        }

        /* P68 (v1.82; implemented v2.15): "xchg R,S" (equal-width
         *  registers) with one operand provably dead after the swap ->
         *  "mov <alive>, <dead>".  The dead operand's OLD value is
         *  what the live one receives, so the mov keeps the live
         *  register's new value exact.  xchg and mov are both
         *  flag-neutral: no scan beyond the liveness proof.  The
         *  1-byte "xchg eax,r" short forms and 64-bit xchg (2 bytes
         *  vs mov's 3) are refused, so the rewrite never grows the
         *  code.  SP excluded: a mov to SP changes observable
         *  stack-pointer behaviour between interrupts differently
         *  than xchg would.
         *  [GCC i386.md peephole2 #9/#10 REG_UNUSED xchg -> mov] */
        if (!pi->toobig && pi->cls == I_XCHG && pi->nops == 2 &&
            pi->dreg >= 0 && pi->sreg >= 0 && pi->dreg != pi->sreg &&
            g_regs[pi->dreg].fam != 4 && g_regs[pi->sreg].fam != 4) {
            int w68 = reg_width(pi->dreg);
            if (w68 == reg_width(pi->sreg) &&
                (w68 == 8 || w68 == 16 ||
                 (w68 == 32 && g_regs[pi->dreg].fam != 0 &&
                  g_regs[pi->sreg].fam != 0))) {
                int dead68 = -1;
                if (reg_dead_cf(next_code(i), pi->sreg))
                    dead68 = pi->sreg;
                else if (reg_dead_cf(next_code(i), pi->dreg))
                    dead68 = pi->dreg;
                if (dead68 >= 0) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "mov ");
                    if (dead68 == pi->sreg) {
                        /* mov <live R>, <dead S> */
                        if (g_att) {
                            strcat(g_build, pi->op1);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op0);
                        } else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op1);
                        }
                    } else {
                        /* mov <live S>, <dead R> */
                        if (g_att) {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op1);
                        } else {
                            strcat(g_build, pi->op1);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op0);
                        }
                    }
                    if (pi->comment[0] != 0) {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'xchg %s, %s' rewritten to '%s' (P68)\n",
                        i + 1, pi->op0, pi->op1, g_build);
                    replace_line(i, g_build);
                    st[68]++;
                    continue;
                }
            }
        }

        /* P70 (v1.82; implemented v2.15): "lea R,[S+off1] /
         *  lea D,[R+off2]" (R dead after the second LEA) -> single
         *  "lea D,[S+off1+off2]"; the first LEA is deleted.  Both
         *  LEAs are flag-free; only the intermediate R is observable,
         *  and R is dead.  Simple base+displacement forms only (the
         *  scaled/index form needs extra parser work).  Intel-only,
         *  matching the sibling rule P382.
         *  [FPC OptPass1LEA "LeaLea2Lea" simple sub-case] */
        if (!pi->toobig && !pi->haslabel && !g_att &&
            pi->cls == I_LEA && pi->nops == 2 && pi->dreg >= 0) {
            int w70 = reg_width(pi->dreg);
            int s70, b70;
            long o70a, o70b;
            if ((w70 == 16 || w70 == 32) &&
                lea_bracket(pi->op1, &s70, &o70a) && s70 >= 0 &&
                o70a >= -0x7FFFFFFFL &&
                lea_base_ok(s70, w70)) {
                long j70 = next_code(i);
                if (j70 >= 0 && !INDEF(j70)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j70, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_LEA && pj->nops == 2 &&
                        pj->dreg >= 0 &&
                        reg_width(pj->dreg) == w70 &&
                        lea_bracket(pj->op1, &b70, &o70b) &&
                        b70 == pi->dreg &&
                        o70b >= -0x7FFFFFFFL &&
                        reg_dead_cf(next_code(j70), pi->dreg)) {
                        char opnd[MAXTOK];
                        emit_lea_disp(opnd, s70, o70a + o70b);
                        strcpy(g_build, pj->prefix);
                        strcat(g_build, "lea ");
                        strcat(g_build, pj->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, opnd);
                        if (pj->comment[0] != 0) {
                            strcat(g_build, " ");
                            strcat(g_build, pj->comment);
                        }
                        vlog("smartpp: line %ld: fused 'lea %s, %s' / '%s' into 'lea %s, %s' (P70)\n",
                            i + 1, pi->op0, pi->op1, L(j70),
                            pj->op0, opnd);
                        replace_line(j70, g_build);
                        DEL(i) = 1;
                        st[70]++;
                        continue;
                    }
                }
            }
        }

        /* P80 (v1.83; implemented v2.15): "push R / <writer> / pop R"
         *  (adjacent; the writer fully overwrites R without reading
         *  it, without touching the stack or reading memory) ->
         *  all three deleted.  The pop restores the pushed value, so
         *  the writer's store is dead; with the pop gone, the push's
         *  save is dead too.  Flag-neutral writers need no scan; an
         *  "xor R,R" writer defines all six flags, so those must be
         *  dead.  16/32/64-bit only; SP excluded (parity with
         *  P22/P27/P39/P49/P58/P71). */
        if (!pi->haslabel && !pi->toobig &&
            pi->cls == I_PUSH && pi->dreg >= 0 &&
            g_regs[pi->dreg].fam != 4) {
            int w80 = reg_width(pi->dreg);
            if (w80 == 16 || w80 == 32 || w80 == 64) {
                long j80 = next_code(i);
                if (j80 >= 0 && !INDEF(j80)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j80, pj);
                    if (!pj->haslabel && !pj->toobig && pj->hasinstr &&
                        p80_writer_ok(pj, pi->dreg, 0)) {
                        long k80 = next_code(j80);
                        if (k80 >= 0 && !INDEF(k80)) {
                            struct pinfo *pk = &g_plook;
                            parse_line(k80, pk);
                            if (!pk->haslabel && !pk->toobig &&
                                pk->cls == I_POP &&
                                pk->dreg == pi->dreg &&
                                (pj->cls != I_XORRR ||
                                 flags_clear(next_code(k80), F_ALL6))) {
                                vlog("smartpp: line %ld: deleted push '%s' / '%s' / pop '%s' (P80)\n",
                                    i + 1, L(i), L(j80), L(k80));
                                DEL(i) = 1;
                                DEL(j80) = 1;
                                DEL(k80) = 1;
                                st[80]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P82 (v1.84 SMART.INC port; implemented v2.15): "lea r16, var"
         *  -> "mov r16, OFFSET var" in a USE16 segment with a 16-bit
         *  destination and a bare symbol source (3 bytes vs 4).
         *  Exact: LEA computes the offset and so does MOV with the
         *  OFFSET operator; neither touches flags or memory.  Items 8
         *  and 10/11 of SMART.INC were already covered by P1 and by
         *  the assembler's own near/short pick on 386+. */
        if (!pi->toobig && !g_att && !g_use32 &&
            pi->cls == I_LEA && pi->nops == 2 && pi->dreg >= 0 &&
            reg_width(pi->dreg) == 16 &&
            pi->op1[0] != '\0' &&
            is_ident_start((unsigned char)pi->op1[0])) {
            int ok82 = 1;
            size_t q82;
            for (q82 = 0; pi->op1[q82] != '\0'; q82++)
                if (!is_ident_char((unsigned char)pi->op1[q82])) {
                    ok82 = 0;
                    break;
                }
            if (ok82 && find_reg(pi->op1) < 0) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "mov ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", OFFSET ");
                strcat(g_build, pi->op1);
                if (pi->comment[0] != 0) {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'lea %s, %s' rewritten to '%s' (P82)\n",
                    i + 1, pi->op0, pi->op1, g_build);
                replace_line(i, g_build);
                st[82]++;
                continue;
            }
        }

        /* P85/P86 (v1.84; implemented v2.15): "mov R,K / cmp R,K" (or
         *  "mov R,K / test R,K") with the same plain constant K, R
         *  dead after the pair AND all six status flags dead ->
         *  both deleted.  cmp/test read R, so the mov is not dead on
         *  its own; only the PAIR is dead when both R and the flags
         *  die together (reg_dead_cf + flags_clear). */
        if (!pi->haslabel && !pi->toobig &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->srcimm &&
            g_regs[pi->dreg].fam != 4) {
            long v85;
            if (try_parse_number(pi->op1, &v85)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long v85b;
                    int rule86 = 0;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2)
                        rule86 = ci_eq(pj->mnem, "cmp")  ? 85 :
                                 ci_eq(pj->mnem, "test") ? 86 : 0;
                    if (rule86 != 0 &&
                        find_reg(pj->op0) == pi->dreg &&
                        try_parse_number(pj->op1, &v85b) &&
                        v85b == v85 &&
                        reg_dead_cf(next_code(j), pi->dreg) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted '%s' / '%s' pair (P%d)\n",
                            i + 1, L(i), L(j), rule86);
                        DEL(i) = 1;
                        DEL(j) = 1;
                        st[rule86]++;
                        continue;
                    }
                }
            }
        }

        /* P79 (v1.83; implemented v2.15): "mov R,imm / push R" with
         *  the instruction right after the push already killing R ->
         *  single "push imm".  Both sides are flag-neutral: no scan.
         *  P87 (v1.84; implemented v2.15): the same fold under the
         *  general control-flow-aware dead scan (reg_dead_cf), which
         *  also fires when a conditional jump separates the push from
         *  its kill -- the case the linear P79 had to refuse.  SP
         *  excluded; 64-bit pushes need the immediate to fit a
         *  sign-extended imm32. */
        if (!pi->haslabel && !pi->toobig &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->srcimm &&
            g_regs[pi->dreg].fam != 4) {
            long v79;
            if (try_parse_number(pi->op1, &v79)) {
                int w79 = reg_width(pi->dreg);
                int fits79 = 0;
                if (w79 == 16)
                    fits79 = (v79 >= -0x8000L && v79 <= 0xFFFFL);
                else if (w79 == 32)
                    /* v2.17: v79 is a signed long (32-bit on every
                     *  SMARTPP target), so the old bounds check
                     *  (v79 >= INT32_MIN && v79 <= 0xFFFFFFFF) was
                     *  tautological and tripped W124 -- the upper
                     *  bound promotes v79 to unsigned long.  Any
                     *  32-bit long value encodes in a 32-bit reg. */
                    fits79 = 1;
                else if (w79 == 64 && g_curcpu >= 128)
                    /* v2.17: same -- a 32-bit long always sign-extends
                     *  to 64 bits. */
                    fits79 = 1;
                if (fits79) {
                    j = next_code(i);
                    if (j >= 0 && !INDEF(j)) {
                        struct pinfo *pj = &g_ppair;
                        parse_line(j, pj);
                        if (!pj->haslabel && !pj->toobig &&
                            pj->cls == I_PUSH &&
                            find_reg(pj->op0) == pi->dreg) {
                            int rule79 = 0;
                            long k79 = next_code(j);
                            if (k79 >= 0 && !INDEF(k79)) {
                                struct pinfo *pk = &g_plook;
                                parse_line(k79, pk);
                                if (!pk->toobig && pk->hasinstr &&
                                    p80_writer_ok(pk, pi->dreg, 1))
                                    rule79 = 79;
                            }
                            if (rule79 == 0 &&
                                reg_dead_cf(next_code(j), pi->dreg))
                                rule79 = 87;
                            if (rule79 != 0) {
                                char num[32];
                                strcpy(g_build, pj->prefix);
                                strcat(g_build, "push ");
                                if (g_att) strcat(g_build, "$");
                                sprintf(num, "%ld", v79);
                                strcat(g_build, num);
                                if (pj->comment[0] != 0) {
                                    strcat(g_build, " ");
                                    strcat(g_build, pj->comment);
                                }
                                vlog("smartpp: line %ld: 'mov %s, %s' / 'push %s' rewritten to 'push %ld' (P%ld)\n",
                                    i + 1, pi->op0, pi->op1,
                                    pj->op0, v79, (long)rule79);
                                replace_line(j, g_build);
                                DEL(i) = 1;
                                st[rule79]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P88 (v1.84; implemented v2.15, CORRECTED): the canonical
         *  486 byte-swap idiom is
         *      "xchg al,ah / rol eax,16 / xchg al,ah" -> "bswap eax"
         *  (swap the low-byte pair, rotate the words, swap again).
         *  The form previously documented here ("rol eax,16 / xchg
         *  al,ah / rol eax,16") is NOT an identity for bswap -- it
         *  swaps only the two HIGH bytes (verified exhaustively) --
         *  so the rule fires on the corrected order.  The two xchg
         *  are flag-neutral; each rol writes CF (OF undefined for
         *  count 16) while bswap writes no flags, so CF and OF must
         *  be dead.  Intel-only, 32-bit register, 486+. */
        if (!pi->toobig && !g_att && g_curcpu >= 16 &&
            pi->cls == I_XCHG && pi->nops == 2 &&
            pi->dreg >= 0 && pi->sreg >= 0 &&
            reg_width(pi->dreg) == 8 && reg_width(pi->sreg) == 8 &&
            g_regs[pi->dreg].fam == g_regs[pi->sreg].fam &&
            g_regs[pi->dreg].fam <= 3 &&
            ((g_regs[pi->dreg].lo == 0 && g_regs[pi->sreg].lo == 8) ||
             (g_regs[pi->dreg].lo == 8 && g_regs[pi->sreg].lo == 0))) {
            int fam88 = g_regs[pi->dreg].fam;
            int r32_88 = reg_by_bits(fam88, 0, 32);
            long j88 = next_code(i);
            if (r32_88 >= 0 && j88 >= 0 && !INDEF(j88)) {
                struct pinfo *pj = &g_ppair;
                long v88;
                parse_line(j88, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_SHIFT && pj->nops == 2 &&
                    ci_eq(pj->mnem, "rol") &&
                    find_reg(pj->op0) == r32_88 &&
                    try_parse_number(pj->op1, &v88) && v88 == 16) {
                    long k88 = next_code(j88);
                    if (k88 >= 0 && !INDEF(k88)) {
                        struct pinfo *pk = &g_plook;
                        parse_line(k88, pk);
                        if (!pk->haslabel && !pk->toobig &&
                            pk->cls == I_XCHG && pk->nops == 2 &&
                            ((pk->dreg == pi->dreg &&
                              pk->sreg == pi->sreg) ||
                             (pk->dreg == pi->sreg &&
                              pk->sreg == pi->dreg)) &&
                            flags_clear(next_code(k88), F_CFOF)) {
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "bswap ");
                            strcat(g_build, g_regs[r32_88].name);
                            if (pi->comment[0] != 0) {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: 'xchg %s, %s' / 'rol %s, 16' / 'xchg %s, %s' rewritten to 'bswap %s' (P88)\n",
                                i + 1, pi->op0, pi->op1,
                                g_regs[r32_88].name,
                                pi->op0, pi->op1,
                                g_regs[r32_88].name);
                            replace_line(i, g_build);
                            DEL(j88) = 1;
                            DEL(k88) = 1;
                            st[88]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P89 (v1.84; implemented v2.15): "mov R,0 / setcc R8" (386+)
         *  with R dead after the setcc -> the mov is deleted.  setcc
         *  writes only the low byte and reads only the flags, so the
         *  mov's zero is unobservable when R is dead.  No flag scan
         *  (neither mov nor setcc writes the status flags).
         *  [GCC zero_extendqisi2_qi + setcc; FPC OptPass2MOVZX.] */
        if (!pi->haslabel && !pi->toobig && g_curcpu >= 8 &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->srcimm &&
            g_regs[pi->dreg].fam != 4) {
            long v89;
            if (try_parse_number(pi->op1, &v89) && v89 == 0) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig && pj->nops == 1 &&
                        ci_eq_n(pj->mnem, "set", 3) &&
                        pj->mnem[3] != '\0') {
                        char jm[MAXNAME + 2];
                        int d89;
                        jm[0] = 'j';
                        strncpy(jm + 1, pj->mnem + 3, MAXNAME);
                        jm[MAXNAME + 1] = '\0';
                        if (is_jcc_mnem(jm) &&
                            (d89 = find_reg(pj->op0)) >= 0 &&
                            reg_width(d89) == 8 &&
                            g_regs[d89].fam == g_regs[pi->dreg].fam &&
                            reg_dead_cf(next_code(j), pi->dreg)) {
                            vlog("smartpp: line %ld: deleted '%s' before setcc (P89)\n",
                                i + 1, L(i));
                            DEL(i) = 1;
                            st[89]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* ===== v2.21: NEW OPTIMIZATIONS from GCC/LLVM/FPC research ===== */

        /* P410 (v2.22): "mov [mem], 0" -> "and [mem], 0" (flags dead).
         *  Size win: and [mem],0 is 3 bytes vs mov [mem],0 is 10 bytes.
         *  v2.22: gated to stack memory only ([bp/ebp/rbp±N]) — the
         *  rewrite converts a pure store to read-modify-write, which
         *  is unsafe for MMIO.  Also requires !g_att (Intel syntax).
         *  GCC i386.md peephole2 #5 uses optimize_insn_for_size_p. */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            pi->cls == I_OTHER && pi->nops == 2 &&
            ci_eq(pi->mnem, "mov") && find_reg(pi->op0) < 0) {
            long v410;
            if (find_reg(pi->op0) < 0 &&
                is_stack_mem_operand(pi->op0) && /* v2.22: stack mem only */
                try_parse_number(pi->op1, &v410) &&
                (v410 == 0 || v410 == -1) &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, (v410 == 0) ? "and " : "or ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", ");
                strcat(g_build, pi->op1);
                if (pi->comment[0] != 0) { strcat(g_build, " "); strcat(g_build, pi->comment); }
                vlog("smartpp: line %ld: 'mov %s, %ld' -> '%s' (P410)\n",
                    i + 1, pi->op0, v410, g_build);
                replace_line(i, g_build);
                st[410]++;
                continue;
            }
        }

        /* P411 (v2.22 REMOVED): "or R, 80000000h -> stc / rcl R, 1" was
         *  mathematically WRONG.  or sets only the MSB; rcl rotates ALL
         *  bits left through carry — the results share no bits in common
         *  for most inputs (e.g. R=0x40000000: or→0xC0000000,
         *  rcl→0x80000001).  Neither rcl nor rol can set a single bit
         *  without disturbing the others.  rname[411] kept as doc. */

        /* P412 (v2.21): "add R, S / add R, imm" -> "lea R, [R+S+imm]"
         *  (386+, flags dead, Intel).  GCC i386.md #25-28.  Very common
         *  in address arithmetic.  Saves one instruction, flag-free. */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            pi->cls == I_OTHER && pi->nops == 2 &&
            ci_eq(pi->mnem, "add")) {
            int r412 = find_reg(pi->op0);
            int s412 = find_reg(pi->op1);
            if (r412 >= 0 && s412 >= 0 && r412 != s412 &&
                g_regs[r412].fam != 4 && g_regs[s412].fam != 4 &&
                (g_regs[r412].hi - g_regs[r412].lo) == 32 &&
                g_curcpu >= 8) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    long imm412;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "add") &&
                        find_reg(pj->op0) == r412 &&
                        find_reg(pj->op1) < 0 &&
                        try_parse_number(pj->op1, &imm412) &&
                        imm412 != 0 &&
                        flags_clear(next_code(j), F_ALL6)) {
                        char opnd[MAXTOK];
                        emit_lea_sib(opnd, r412, s412, 1, imm412);
                        strcpy(g_build, pj->prefix);
                        strcat(g_build, "lea ");
                        strcat(g_build, pj->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, opnd);
                        vlog("smartpp: line %ld: 'add %s,%s' / 'add %s,%ld' -> 'lea %s, %s' (P412)\n",
                            i + 1, pi->op0, pi->op1, pj->op0, imm412, pj->op0, opnd);
                        replace_line(j, g_build);
                        DEL(i) = 1;
                        st[412]++;
                        continue;
                    }
                }
            }
        }

        /* P413 (v2.21): "shl R, N / add R, S" -> "lea R, [R+S*2^N]"
         *  (386+, flags dead, Intel).  FPC ShlAddLeaSubIncDec2Lea;
         *  LLVM X86OptimizeLEAs.  Array-index pattern.  N must be
         *  1, 2, or 3 (SIB scales 2, 4, 8). */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            g_curcpu >= 8 && pi->cls == I_SHIFT && pi->nops == 2 &&
            (ci_eq(pi->mnem, "shl") || ci_eq(pi->mnem, "sal"))) {
            int r413 = find_reg(pi->op0);
            if (r413 >= 0 && g_regs[r413].fam != 4 &&
                (g_regs[r413].hi - g_regs[r413].lo) == 32 &&
                pi->shiftcount >= 1 && pi->shiftcount <= 3) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "add") &&
                        find_reg(pj->op0) == r413) {
                        int s413 = find_reg(pj->op1);
                        if (s413 >= 0 && s413 != r413 &&
                            g_regs[s413].fam != 4 &&
                            (g_regs[s413].hi - g_regs[s413].lo) == 32 &&
                            flags_clear(next_code(j), F_ALL6)) {
                            int scale = 1 << pi->shiftcount;
                            char opnd[MAXTOK];
                            emit_lea_sib(opnd, r413, s413, scale, 0);
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, "lea ");
                            strcat(g_build, pj->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, opnd);
                            vlog("smartpp: line %ld: 'shl %s,%ld' / 'add %s,%s' -> 'lea %s, %s' (P413)\n",
                                i + 1, pi->op0, pi->shiftcount,
                                pj->op0, pj->op1, pj->op0, opnd);
                            replace_line(j, g_build);
                            DEL(i) = 1;
                            st[413]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P414 (v2.21): "sar EAX, 31" -> "cdq" (386+, flags dead).
         *  FPC MovSar2Cltd.  sar EAX,31 sign-extends bit 31 to all of
         *  EAX (the sign mask).  cdq sign-extends EAX into EDX:EAX,
         3  putting the same mask in EDX.  If the user then moves EAX
         *  to another register, we replace with cdq + mov from EDX.
         *  Here we handle the simplest case: sar eax,31 / mov reg, eax
         *  -> cdq / mov reg, edx (flags dead). */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            g_curcpu >= 8 && pi->cls == I_SHIFT && pi->nops == 2 &&
            ci_eq(pi->mnem, "sar") && pi->shiftcount == 31) {
            int r414 = find_reg(pi->op0);
            if (r414 >= 0 && g_regs[r414].fam == 0 &&
                (g_regs[r414].hi - g_regs[r414].lo) == 32 &&
                flags_clear(next_code(i), F_ALL6)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_MOV && pj->nops == 2 &&
                        find_reg(pj->op1) == r414) {
                        int dst414 = find_reg(pj->op0);
                        if (dst414 >= 0 && dst414 != r414 &&
                            (g_regs[dst414].hi - g_regs[dst414].lo) == 32 &&
                            /* v2.22: eax must be dead after the mov
                             * (sar overwrites eax with sign mask;
                             * cdq leaves eax unchanged → eax differs) */
                            reg_dead_cf(next_code(j), r414)) {
                            /* sar eax,31 / mov reg, eax -> cdq / mov reg, edx */
                            char movbuf[MAXLINE];
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "cdq");
                            sprintf(movbuf, "%smov %s, edx", pj->prefix, pj->op0);
                            vlog("smartpp: line %ld: 'sar eax,31' / 'mov %s,eax' -> 'cdq' / 'mov %s,edx' (P414)\n",
                                i + 1, pj->op0, pj->op0);
                            replace_line(i, g_build);
                            replace_line(j, movbuf);
                            st[414]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P415 (v2.21): "bts/btr/btc R, N" -> "or/and/xor R, (1<<N)"
         *  (flags dead, N constant 0..31).  GCC i386.md #62-64.
         *  BT-family is microcoded on some CPUs; the AND/OR/XOR form
         *  is faster and the same size or shorter.  Value-equivalent
         *  (same bits written to R); flags differ (bt sets CF from
         *  old bit, or/and/xor set SZP), so needs flags dead. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 &&
            (ci_eq(pi->mnem, "bts") || ci_eq(pi->mnem, "btr") ||
             ci_eq(pi->mnem, "btc"))) {
            int r415 = find_reg(pi->op0);
            long n415;
            if (r415 >= 0 && g_regs[r415].fam != 4 &&
                try_parse_number(pi->op1, &n415) && n415 >= 0 && n415 < 32) {
                int w415 = g_regs[r415].hi - g_regs[r415].lo;
                unsigned long mask415 = 1UL << n415;
                if (w415 == 32 || (w415 == 16 && n415 < 16) ||
                    (w415 == 8 && n415 < 8)) {
                    if (flags_clear(next_code(i), F_ALL6)) {
                        char num[32];
                        const char *op415;
                        if (ci_eq(pi->mnem, "bts")) { op415 = "or "; mask415 &= (w415==8)?0xFFUL:(w415==16)?0xFFFFUL:0xFFFFFFFFUL; }
                        else if (ci_eq(pi->mnem, "btr")) { op415 = "and "; mask415 = ~(1UL << n415) & ((w415==8)?0xFFUL:(w415==16)?0xFFFFUL:0xFFFFFFFFUL); }
                        else { op415 = "xor "; mask415 &= (w415==8)?0xFFUL:(w415==16)?0xFFFFUL:0xFFFFFFFFUL; }
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, op415);
                        strcat(g_build, pi->op0);
                        strcat(g_build, ", ");
                        sprintf(num, "%lu", mask415);
                        strcat(g_build, num);
                        vlog("smartpp: line %ld: '%s %s, %ld' -> '%s %s, %lu' (P415)\n",
                            i + 1, pi->mnem, pi->op0, n415,
                            op415, pi->op0, mask415);
                        replace_line(i, g_build);
                        st[415]++;
                        continue;
                    }
                }
            }
        }

        /* P416 (v2.21): setcc + movzx fusion.
         *  "setcc R8 / movzx R32, R8" -> "xor R32, R32 / setcc R8"
         *  (386+).  LLVM X86FixupSetCC; GCC peephole2 #66.
         *  Avoids partial-register stall on P5/PPro.  The xor must
         *  go BEFORE the flag-defining instruction (xor clobbers
         *  flags).  We walk backward to find it. */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            g_curcpu >= 8 && pi->cls == I_OTHER && pi->nops == 1 &&
            ci_eq_n(pi->mnem, "set", 3) && pi->mnem[3] != '\0') {
            int r416 = find_reg(pi->op0);
            if (r416 >= 0 && (g_regs[r416].hi - g_regs[r416].lo) == 8) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_MOVZX && pj->nops == 2 &&
                        ci_eq(pj->mnem, "movzx") &&
                        find_reg(pj->op1) == r416 &&
                        g_regs[pj->dreg].fam == g_regs[r416].fam &&
                        (g_regs[pj->dreg].hi - g_regs[pj->dreg].lo) == 32) {
                        int r32_416 = pj->dreg;
                        /* walk backward to find the flag-defining instr */
                        long b;
                        int found_flagdef = 0;
                        for (b = i - 1; b >= 0; b--) {
                            struct pinfo *pb = &g_plook;
                            int rd, wr, div;
                            if (DEL(b) || INDEF(b)) continue;
                            parse_line(b, pb);
                            if (pb->haslabel) break;
                            if (!pb->hasinstr) continue;
                            if (pb->toobig) break;
                            /* check if this instruction reads/writes flags */
                            if (flag_sets(pb, &rd, &wr, &div) != 0) break;
                            if (wr != 0) { found_flagdef = 1; break; }
                            if (div) break;
                        }
                        if (found_flagdef) {
                            char xorbuf[MAXLINE];
                            /* v2.22 fix: insert xor BEFORE the flag-defining
                             * instruction (b), not after it.  insert_line_after(b-1)
                             * places it between b-1 and b.  If b==0, we can't
                             * insert before — skip the rule.
                             * The xor clobbers all flags, so it MUST go before
                             * the cmp/add/sub/etc that sets the flags the setcc
                             * reads.  Inserting after would make setcc read
                             * xor's flags (always ZF=1) instead. */
                            if (b <= 0) continue;
                            DEL(j) = 1;  /* delete movzx first (no index shift) */
                            sprintf(xorbuf, "%sxor %s, %s",
                                g_plook.prefix, g_regs[r32_416].name,
                                g_regs[r32_416].name);
                            vlog("smartpp: line %ld: 'setcc %s' / 'movzx %s, %s' -> insert 'xor %s, %s' before line %ld + delete movzx (P416)\n",
                                i + 1, pi->op0, pj->op0, pi->op0,
                                g_regs[r32_416].name, g_regs[r32_416].name,
                                b + 1);
                            insert_line_after(b - 1, xorbuf);
                            st[416]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P417 (v2.22): "mov R, [mem] / op R, S / mov [mem], R"
         *  -> "op [mem], S" (R dead, RMW fold, stack mem only).
         *  v2.22: gated to stack memory — RMW on arbitrary mem is
         *  unsafe for MMIO (read side effect).  GCC i386.md #29-47. */
        if (!pi->haslabel && !pi->toobig && !g_att &&
            pi->cls == I_MOV && pi->nops == 2 && pi->dreg >= 0 &&
            pi->sreg < 0 && !pi->srcimm &&
            is_stack_mem_operand(pi->op1)) { /* v2.22: stack mem */
            /* op0 is a register (dest), op1 is memory (source) */
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 2 &&
                    find_reg(pj->op0) == pi->dreg &&
                    (ci_eq(pj->mnem, "add") || ci_eq(pj->mnem, "sub") ||
                     ci_eq(pj->mnem, "or") || ci_eq(pj->mnem, "and") ||
                     ci_eq(pj->mnem, "xor") || ci_eq(pj->mnem, "adc") ||
                     ci_eq(pj->mnem, "sbb"))) {
                    long k417 = next_code(j);
                    if (k417 >= 0 && !INDEF(k417)) {
                        struct pinfo *pk = &g_plook;
                        parse_line(k417, pk);
                        if (!pk->haslabel && !pk->toobig &&
                            pk->cls == I_MOV && pk->nops == 2 &&
                            find_reg(pk->op1) == pi->dreg &&
                            ci_eq(pk->op0, pi->op1) &&
                            reg_dead_cf(next_code(k417), pi->dreg)) {
                            /* Fold: op [mem], S */
                            strcpy(g_build, pj->prefix);
                            strcat(g_build, pj->mnem);
                            strcat(g_build, " ");
                            strcat(g_build, pi->op1);  /* mem dest */
                            strcat(g_build, ", ");
                            strcat(g_build, pj->op1);  /* source */
                            vlog("smartpp: line %ld: RMW fold 'mov %s,%s' / '%s %s,%s' / 'mov %s,%s' -> '%s' (P417)\n",
                                i + 1, pi->op0, pi->op1,
                                pj->mnem, pj->op0, pj->op1,
                                pk->op0, pk->op1, g_build);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            DEL(k417) = 1;
                            st[417]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* ===== v2.25: EASY optimizations from the 10-item list ===== */

        /* P42 (v2.25): "push bp / mov bp, sp / sub sp, N" -> "enter N, 0"
         *  (186+, 16-bit only, !g_att, flags dead).  enter preserves
         *  flags; sub sp,N defines them.  Size win: 6..7 -> 4 bytes.
         *  FPC; documented since v1.70 but never implemented. */
        if (!pi->haslabel && !pi->toobig && !g_att && !g_use32 &&
            g_curcpu >= 2 && pi->cls == I_PUSH && pi->nops == 1) {
            int r42 = find_reg(pi->op0);
            if (r42 >= 0 && g_regs[r42].fam == 5) {  /* push bp */
                long j42a = next_code(i);
                if (j42a >= 0 && !INDEF(j42a)) {
                    struct pinfo *pa = &g_ppair;
                    parse_line(j42a, pa);
                    if (!pa->haslabel && !pa->toobig &&
                        pa->cls == I_MOV && pa->nops == 2 &&
                        pa->dreg >= 0 && g_regs[pa->dreg].fam == 5 &&
                        pa->sreg >= 0 && g_regs[pa->sreg].fam == 4) {
                        /* mov bp, sp */
                        long j42b = next_code(j42a);
                        if (j42b >= 0 && !INDEF(j42b)) {
                            struct pinfo *pb = &g_plook;
                            parse_line(j42b, pb);
                            if (!pb->haslabel && !pb->toobig &&
                                pb->cls == I_OTHER && pb->nops == 2 &&
                                ci_eq(pb->mnem, "sub") &&
                                find_reg(pb->op0) >= 0 &&
                                g_regs[find_reg(pb->op0)].fam == 4) {
                                /* sub sp, N */
                                long n42;
                                if (try_parse_number(pb->op1, &n42) &&
                                    n42 >= 0 && n42 <= 0xFFFF &&
                                    flags_clear(next_code(j42b), F_ALL6)) {
                                    char num[32];
                                    strcpy(g_build, pi->prefix);
                                    strcat(g_build, "enter ");
                                    sprintf(num, "%ld", n42);
                                    strcat(g_build, num);
                                    strcat(g_build, ", 0");
                                    vlog("smartpp: line %ld: 'push bp'/'mov bp,sp'/'sub sp,%ld' -> '%s' (P42)\n",
                                        i + 1, n42, g_build);
                                    replace_line(i, g_build);
                                    DEL(j42a) = 1;
                                    DEL(j42b) = 1;
                                    st[42]++;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* P426 (v2.25): "cmp R, 1 / jl L" -> "test R, R / jle L"
         *  R < 1 (signed) ⟺ R <= 0 (signed).  cmp R,1 sets flags for
         *  R-1; jl checks SF≠OF (R<1).  test R,R sets flags for R;
         *  jle checks ZF=1 or SF≠OF (R<=0).  Since R<1 ⟺ R<=0,
         *  the transformation is exact.  FPC Cmp1Jl2Cmp0Jle.
         *  Also: "cmp R, -1 / jg L" -> "test R, R / jge L"
         *  R > -1 ⟺ R >= 0.  FPC CmpNeg1Jg2Cmp0Jge. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "cmp") &&
            find_reg(pi->op0) >= 0) {
            long v426;
            if (try_parse_number(pi->op1, &v426)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_JCC && pj->jtarget_ok) {
                        const char *new_jcc = NULL;
                        /* cmp R,1 / jl -> test R,R / jle */
                        if (v426 == 1 &&
                            (ci_eq(pj->mnem, "jl") || ci_eq(pj->mnem, "jnge")))
                            new_jcc = "jle";
                        /* cmp R,-1 / jg -> test R,R / jge */
                        else if (v426 == -1 &&
                                 (ci_eq(pj->mnem, "jg") || ci_eq(pj->mnem, "jnle")))
                            new_jcc = "jge";
                        if (new_jcc != NULL) {
                            char testbuf[MAXLINE];
                            char jccbuf[MAXLINE];
                            /* rewrite cmp R,imm -> test R,R */
                            strcpy(testbuf, pi->prefix);
                            strcat(testbuf, "test ");
                            strcat(testbuf, pi->op0);
                            strcat(testbuf, ", ");
                            strcat(testbuf, pi->op0);
                            if (pi->comment[0] != 0) {
                                strcat(testbuf, " ");
                                strcat(testbuf, pi->comment);
                            }
                            /* rewrite jcc */
                            strcpy(jccbuf, pj->prefix);
                            strcat(jccbuf, new_jcc);
                            strcat(jccbuf, " ");
                            strcat(jccbuf, pj->op0);
                            if (pj->comment[0] != 0) {
                                strcat(jccbuf, " ");
                                strcat(jccbuf, pj->comment);
                            }
                            vlog("smartpp: line %ld: 'cmp %s,%ld'/'%s' -> 'test %s,%s'/'%s' (P426)\n",
                                i + 1, pi->op0, v426, pj->mnem,
                                pi->op0, pi->op0, new_jcc);
                            replace_line(i, testbuf);
                            replace_line(j, jccbuf);
                            st[426]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P427 (v2.25): "dec cx / jnz L" -> "loop L" (8086 only, -Oz).
         *  loop decrements CX and jumps if CX!=0; dec cx/jnz does the
         *  same.  But loop doesn't touch flags while dec sets them,
         *  so flags must be dead.  CX must be dead after (loop
         *  overwrites CX).  -Oz only: loop is 2 bytes (shorter than
         *  dec+jnz = 3-4 bytes) but slower on 386+ (11 vs 9 cycles).
         *  GEMA note: autoalign moves addresses; this is safe. */
        if (opt_zopt && !pi->haslabel && !pi->toobig &&
            pi->cls == I_OTHER && pi->nops == 1 &&
            ci_eq(pi->mnem, "dec")) {
            int r427 = find_reg(pi->op0);
            if (r427 >= 0 && g_regs[r427].fam == 1 &&
                (g_regs[r427].hi - g_regs[r427].lo) == 16) {
                /* dec cx */
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_JCC && pj->jtarget_ok &&
                        (ci_eq(pj->mnem, "jnz") || ci_eq(pj->mnem, "jne")) &&
                        flags_clear(next_code(j), F_ALL6) &&
                        reg_dead_cf(next_code(j), r427)) {
                        char loopbuf[MAXLINE];
                        strcpy(loopbuf, pi->prefix);
                        strcat(loopbuf, "loop ");
                        strcat(loopbuf, pj->op0);
                        if (pj->comment[0] != 0) {
                            strcat(loopbuf, " ");
                            strcat(loopbuf, pj->comment);
                        }
                        vlog("smartpp: line %ld: 'dec cx'/'jnz %s' -> 'loop %s' (P427, -Oz)\n",
                            i + 1, pj->op0, pj->op0);
                        replace_line(i, loopbuf);
                        DEL(j) = 1;
                        st[427]++;
                        continue;
                    }
                }
            }
        }

        if (try_table_rules(i)) continue;


    }
    {
        long after = 0;
        for (kk = 1; kk < STSZ; kk++) after += st[kk];
        return after - before;
    }
}

/* ---- driver ----------------------------------------------------------------*/


/* v2.25 (S7): unified sparse rule-name map.  Replaces the
 *  dense rname[0..216] array and the separate g_rname_ext[]
 *  sparse extension table that rule_name() used to consult in
 *  sequence.  Every named rule lives here now; rule_name() is
 *  a single linear lookup followed by the g_rule_tbl[].desc
 *  fallback for declarative-table rules.  Placeholders
 *  ("(withdrawn)", "(removed...)", "(covered by...)",
 *  "(handled by...)", "(reserved)") were dropped: rule_name
 *  returns "(unnamed)" for them, which print_version's
 *  filter already skips.  Catalogue output is unchanged. */
static const struct rname_ext_s {
    int no;
    const char *name;
} g_rname_map[] = {
    {   1, "delete mov/xchg R,R" },
    {   2, "dead register store" },
    {   3, "push/pop pair" },
    {   4, "merge shifts" },
    {   5, "thread jmp/jcc" },
    {   6, "redundant jump" },
    {   7, "invert jcc" },
    {   8, "or/and->test (ext)" },
    {   9, "mov0->xor" },
    {  10, "add/sub 1->inc/dec" },
    {  11, "cmp0->test" },
    {  12, "dup jumps" },
    {  13, "unreachable" },
    {  14, "double xchg" },
    {  15, "mov R,S/mov S,R" },
    {  16, "const fold" },
    {  17, "lea conv" },
    {  18, "add/sub R,0" },
    {  19, "dup cmp/test/or/and" },
    {  20, "shift R,0" },
    {  21, "dup flag op" },
    {  22, "inc/dec pair" },
    {  23, "not pair" },
    {  24, "neg pair" },
    {  25, "cmc pair" },
    {  26, "dead xor0" },
    {  27, "add/sub pair" },
    {  28, "dup sign-extend" },
    {  29, "zero-ext movzx" },
    {  30, "zero-ext imm" },
    {  31, "movsx" },
    {  32, "push/pop->mov" },
    {  33, "shift pair" },
    {  34, "and-mask" },
    {  35, "mov-1->or" },
    {  36, "leave" },
    {  37, "xor R,-1->not" },
    {  38, "imul 2^k->shl" },
    {  39, "add/sub pair (const)" },
    {  40, "mov+add->mov" },
    {  41, "lea R,[R+S]->add" },
    {  42, "push bp/mov bp,sp/sub sp,N->enter" },
    {  43, "xor+arith->mov" },
    {  44, "xor/inc->mov1" },
    {  45, "xor/dec->mov-1" },
    {  46, "push imm/pop->mov" },
    {  47, "mov+add->lea" },
    {  48, "xor+test->delete test" },
    {  49, "sp add/sub pair" },
    {  51, "imul -1->neg" },
    {  52, "mov+shl fold" },
    {  53, "mov+and fold" },
    {  54, "mov+or fold" },
    {  55, "mov+xor fold" },
    {  56, "mixed add/sub fold" },
    {  58, "xor/xor pair" },
    {  59, "and R,0->mov R,0" },
    {  60, "or R16,-1->mov R16,-1" },
    {  61, "and+and->and" },
    {  62, "and/or mask tighten" },
    {  63, "lea R,[R*K]->shl" },
    {  65, "dec/cmp -1->dec" },
    {  68, "xchg dead->mov" },
    {  70, "lea+lea fusion" },
    {  71, "sub R,R->xor R,R" },
    {  72, "mov+shr fold" },
    {  73, "mov+sar fold" },
    {  74, "mov+rol fold" },
    {  75, "mov+ror fold" },
    {  76, "xor+reg->mov" },
    {  77, "dup mov/lea/movzx" },
    {  78, "lea+lea same-dst" },
    {  79, "mov+push->push imm" },
    {  80, "push+write+pop->nothing" },
    {  81, "mov+movzx->movzx" },
    {  82, "lea r16,var->mov OFFSET" },
    {  85, "mov+cmp same-const dead" },
    {  86, "mov+test same-const dead" },
    {  87, "mov+push->push imm (CF)" },
    {  88, "xchg8/rol16/xchg8->bswap" },
    {  89, "mov0 before setcc dead" },
    {  90, "and K / jcc->test K" },
    {  92, "sub R,1->dec R (jcc)" },
    {  93, "xor dead before mov" },
    {  94, "mov 0 / OP K -> mov K" },
    {  97, "mov+test R,R dead" },
    {  98, "shift dead before mov 0" },
    { 111, "or R,0->del" },
    { 112, "and R,-1->del" },
    { 115, "xor R,0->del" },
    { 119, "test R,K->del" },
    { 120, "cmp R,K->del" },
    { 123, "imul R,0->xor R,R (flags dead)" },
    { 124, "lea R,[R]/[R+0]->del" },
    { 127, "bswap/bswap->del one" },
    { 128, "xor R,R/push R->push 0" },
    { 129, "fld st/fstp st->del" },
    { 130, "fldz/fstp st->del" },
    { 131, "fchs/fchs->del" },
    { 132, "fabs/fabs->fabs" },
    { 134, "ffree/ffree->ffree" },
    { 135, "fninit/fninit->fninit" },
    { 136, "fwait/fwait->fwait" },
    { 137, "fxch st,st->del" },
    { 141, "not/inc->neg" },
    { 142, "neg/dec->not" },
    { 143, "add R,R->shl R,1" },
    { 144, "mov/not->mov ~imm" },
    { 145, "mov/neg->mov -imm" },
    { 146, "shift R,0->del" },
    { 147, "or/and R,R->del" },
    { 148, "test R,R->del" },
    { 149, "imul 2^k->shl ($Klog2)" },
    { 150, "test R,R / test R,R" },
    { 151, "cmp R,R->del" },
    { 152, "push S/mov R,S/pop S" },
    { 153, "dup mov R,S" },
    { 154, "and R,R->del" },
    { 155, "shl 1/1->shl 2" },
    { 156, "shr 1/1->shr 2" },
    { 157, "xor0 / or R,R->del or" },
    { 158, "add R,R/add R,R->shl 2" },
    { 159, "dup or R,K" },
    { 160, "dup and R,K" },
    { 161, "stc/sbb R,R->or -1" },
    { 162, "clc/adc R,0->del" },
    { 163, "mov/and same->del and" },
    { 164, "sal R,1->add R,R" },
    { 165, "imul 3->lea [R+R*2]" },
    { 166, "imul 5->lea [R+R*4]" },
    { 167, "imul 9->lea [R+R*8]" },
    { 168, "mov R,S/mov S,R->del 2nd" },
    { 169, "xor R,S twice->del" },
    { 170, "imul 4->shl 2" },
    { 171, "imul 8->shl 3" },
    { 172, "add R,R x3->shl 3" },
    { 173, "imul 2->shl 1" },
    { 174, "imul 16->shl 4" },
    { 175, "imul 32->shl 5" },
    { 176, "imul 64->shl 6" },
    { 177, "imul 128->shl 7" },
    { 178, "imul 256->shl 8" },
    { 180, "mov MEM/push->push MEM" },
    { 181, "push/pop same->del" },
    { 182, "pop/push same->del" },
    { 183, "call/nop->del nop" },
    { 184, "jmp/nop->del nop" },
    { 185, "ret/nop->del nop" },
    { 186, "mov0/push->push 0" },
    { 187, "sub0/push->push 0" },
    { 188, "mov R,S/push R->push S" },
    { 189, "nop/nop->del 2nd" },
    { 190, "and/test R,R->del test" },
    { 191, "or/test R,R->del test" },
    { 192, "stack-swap->xchg" },
    { 193, "mov imm/add->add imm" },
    { 194, "mov imm/sub->sub imm" },
    { 195, "mov imm/and->and imm" },
    { 196, "mov imm/or->or imm" },
    { 197, "mov imm/xor->xor imm" },
    { 198, "mov imm/cmp->cmp imm" },
    { 199, "mov/add->lea [S+imm]" },
    { 200, "stack-load fold into ALU" },
    { 201, "lea/load fold into mem" },
    { 202, "xor/test R,R->del test" },
    { 203, "fchs/fabs->fabs" },
    { 204, "fwait/fwait" },
    { 205, "fnop/fnop" },
    { 206, "fld1/fmulp->del" },
    { 207, "fdecstp/fincstp" },
    { 208, "fincstp/fdecstp" },
    { 209, "finit/finit" },
    { 210, "cdqe/cdqe" },
    { 211, "cqo/cqo" },
    { 212, "pushf/popf->del" },
    { 213, "pushfd/popfd->del" },
    { 214, "pushfq/popfq->del" },
    { 215, "cld/cld" },
    { 216, "std/std" },
    { 217, "fabs/fchs/fabs->fabs" },
    { 343, "xor r64 after xor r32 (x64)" },
    { 344, "redundant const store (prop)" },
    { 351, "clc/jnc->jmp" },
    { 352, "stc/jc->jmp" },
    { 353, "clc/jc->del" },
    { 354, "stc/jnc->del" },
    { 355, "xor0/jz->jmp" },
    { 356, "xor0/jnz->del" },
    { 360, "const-flags setcc->mov" },
    { 361, "clc/setc->mov" },
    { 362, "stc/setc->mov" },
    { 365, "lea [S+S]->lea [S*2]" },
    { 366, "cmov always->mov" },
    { 367, "cmov never->del" },
    { 370, "widen rep string (-Ox)" },
    { 371, "not/add 1->neg" },
    { 373, "rol/ror pair->del" },
    { 377, "cmp R,R/jcc->jmp" },
    { 378, "cmp R,R/jcc->del" },
    { 380, "imul K->lea/shl (unified)" },
    { 381, "LEA CSE->mov" },
    { 382, "mov+lea->lea (R dead)" },
    { 383, "call/ret->jmp tail-call" },
    { 384, "movzx r64,r32->del (x64)" },
    { 385, "const-ZF jcc/cmov/setcc" },
    { 386, "const-prop ALU fold->mov" },
    { 392, "or R8,0FFh->mov R8,0FFh" },
    { 393, "or R16,0FFFFh->mov R16,0FFFFh" },
    { 396, "load fold into ALU (stack mem)" },
    { 397, "push [bp+N]/pop R->mov R,[bp+N]" },
    { 398, "movq XMM,XMM->del" },
    { 399, "movdqa XMM,XMM->del" },
    { 400, "movdqu XMM,XMM->del" },
    { 401, "por XMM,XMM->del" },
    { 402, "pand XMM,XMM->del" },
    { 403, "pandn XMM,XMM->pxor" },
    { 404, "psubb XMM,XMM->pxor" },
    { 405, "psubw XMM,XMM->pxor" },
    { 406, "psubd XMM,XMM->pxor" },
    { 407, "orpd XMM,XMM->del" },
    { 408, "andpd XMM,XMM->del" },
    { 409, "andnpd XMM,XMM->xorpd" },
    { 410, "mov [mem],0/-1->and/or [mem]" },
    { 411, "or R,80000000h->stc/rcl" },
    { 412, "add+add->lea [R+S+imm]" },
    { 413, "shl+add->lea [R+S*scale]" },
    { 414, "sar eax,31->cdq+mov" },
    { 415, "bts/btr/btc->or/and/xor mask" },
    { 416, "setcc+movzx->xor+setcc" },
    { 417, "RMW fold (mov/op/mov->op mem)" },
    { 418, "leave/leave->leave" },
    { 419, "xchg/xchg pair->del" },
    { 420, "mov+xchg->del xchg" },
    { 421, "nop->del (single, no label)" },
    { 422, "sahf/sahf->sahf" },
    { 424, "movzx R,R->del (same width)" },
    { 425, "movsx R,R->del (same width)" },
    { 426, "cmp R,1/jl->test R,R/jle" },
    { 427, "dec cx/jnz->loop (-Oz)" },
    { 428, "lea R,[R+R]->add R,R" },
    { 429, "mov R,S/push R->push S" },
    { 430, "or/and/or 3-op chain->del or1" },
    { 431, "mov R8lo,0/mov R8hi,0->xor R16" },
    { 432, "movzx+test R,R->test S,S" },
    { 433, "add+add->add fold (M4)" },
    { 434, "sub+sub->sub fold (M4)" },
    { 435, "sub+add->sub fold (M4)" },
    { 436, "add+sub->add fold (M4)" },
    { 437, "or+or->or fold (M4)" },
    { 438, "and+and->and fold (M4)" },
    { 439, "xor+xor->xor fold (M4)" },
    { 441, "test -1/setcc->setcc (M6)" },
    { 443, "add 0/adc 0->del (M4)" },
    { 0, NULL }
};


/* v2.25 (S7): rule_name() now consults the single g_rname_map[]
 *  above plus the g_rule_tbl[].desc fallback.  The dense rname[]
 *  array (216 positional slots, ~70% empty or placeholder) and the
 *  separate g_rname_ext[] sparse table are gone -- every named rule
 *  lives in g_rname_map[].  Placeholders ("(withdrawn)",
 *  "(removed...)", "(covered by...)", "(handled by...)",
 *  "(reserved)") were dropped: rule_name returns "(unnamed)" for
 *  them, which print_version's filter already skips, so the
 *  catalogue output is byte-identical. */
static const char *rule_name(int k)
{
    const struct rname_ext_s *re;
    if (k < 0) return "(unnamed)";
    for (re = g_rname_map; re->name != NULL; re++)
        if (re->no == k) return re->name;
    /* declarative-table rules carry their own desc; consult it last
     *  so a manually-curated entry in g_rname_map[] wins. */
    {
        size_t ti;
        for (ti = 0; ti < sizeof(g_rule_tbl) / sizeof(g_rule_tbl[0]); ti++)
            if (g_rule_tbl[ti].rule_no == k &&
                g_rule_tbl[ti].desc != NULL && g_rule_tbl[ti].desc[0] != '\0')
                return g_rule_tbl[ti].desc;
    }
    return "(unnamed)";
}

static void print_summary(long nout, long ndel)
{
    long total_fired = 0;
    int k, nrules_fired = 0;
    int use_color = color_enabled();

    fprintf(stderr, "\n");
    if (use_color) {
        fprintf(stderr, "%s%s==========================================================%s\n",
                C_BOLD, C_CYAN, C_RESET);
        fprintf(stderr, "  %sSMARTPP %s%s  %s--  peephole summary%s\n",
                C_BOLD C_CYAN, SMARTPP_VERSION, C_RESET, C_DIM, C_RESET);
        fprintf(stderr, "  %sCopyright (c) %s%s\n", C_DIM, AUTHOR_STR, C_RESET);
        fprintf(stderr, "%s%s==========================================================%s\n",
                C_BOLD, C_CYAN, C_RESET);
        fprintf(stderr, "  %sInput%s   : %s%ld%s lines\n",
                C_BOLD, C_RESET, C_GREEN, g_nlines, C_RESET);
        fprintf(stderr, "  %sOutput%s  : %s%ld%s lines\n",
                C_BOLD, C_RESET, C_GREEN, nout, C_RESET);
        fprintf(stderr, "  %sRemoved%s : %s%ld%s lines\n",
                C_BOLD, C_RESET, ndel ? C_YELLOW : C_GREEN, ndel, C_RESET);
        fprintf(stderr, "  %sPasses%s  : %s%d%s (max %d)\n",
                C_BOLD, C_RESET, C_GREEN, g_passes_run, C_RESET, MAX_PASSES);
        fprintf(stderr, "  %sCPU%s     : %s%s%s\n",
                C_BOLD, C_RESET, C_BOLD C_GREEN, cpu_name(g_curcpu), C_RESET);
        fprintf(stderr, "%s----------------------------------------------------------%s\n",
                C_CYAN, C_RESET);
        fprintf(stderr, "  %s%-6s  %-34s  %s%s\n",
                C_BOLD, "Rule", "Optimization applied", "Hits", C_RESET);
        fprintf(stderr, "  %-6s  %-34s  %s\n", "----",
                "----------------------------------", "----");
    } else {
        fprintf(stderr, "==========================================================\n");
        fprintf(stderr, "  SMARTPP %s  --  peephole summary\n", SMARTPP_VERSION);
        fprintf(stderr, "  Copyright (c) %s\n", AUTHOR_STR);
        fprintf(stderr, "==========================================================\n");
        fprintf(stderr, "  Input   : %ld lines\n", g_nlines);
        fprintf(stderr, "  Output  : %ld lines\n", nout);
        fprintf(stderr, "  Removed : %ld lines\n", ndel);
        fprintf(stderr, "  Passes  : %d (max %d)\n", g_passes_run, MAX_PASSES);
        fprintf(stderr, "  CPU     : %s\n", cpu_name(g_curcpu));
        fprintf(stderr, "----------------------------------------------------------\n");
        fprintf(stderr, "  %-6s  %-34s  %s\n", "Rule", "Optimization applied", "Hits");
        fprintf(stderr, "  %-6s  %-34s  %s\n", "----",
                "----------------------------------", "----");
    }

    for (k = 1; k < STSZ; k++) {
        const char *nm;
        if (st[k] == 0) continue;
        nm = rule_name(k);
        fprintf(stderr, "  ");
        if (use_color) fprintf(stderr, "%s", C_YELLOW);
        fprintf(stderr, "P%-5d", k);
        if (use_color) fprintf(stderr, "%s", C_RESET);
        fprintf(stderr, "  %-34s  ", nm);
        if (use_color) fprintf(stderr, "%s", C_GREEN);
        fprintf(stderr, "%ld", st[k]);
        if (use_color) fprintf(stderr, "%s", C_RESET);
        fprintf(stderr, "\n");
        total_fired += st[k];
        nrules_fired++;
    }

    if (use_color) {
        fprintf(stderr, "%s----------------------------------------------------------%s\n",
                C_CYAN, C_RESET);
        fprintf(stderr, "  %sTOTAL%s   %d rule%s, %s%ld%s rewrite%s\n",
                C_BOLD, C_RESET,
                nrules_fired, nrules_fired == 1 ? "" : "s",
                C_BOLD C_GREEN, total_fired, C_RESET,
                total_fired == 1 ? "" : "s");
        if (nrules_fired == 0)
            fprintf(stderr, "  %s(no rules fired; input already optimal)%s\n",
                    C_DIM, C_RESET);
        fprintf(stderr, "%s%s==========================================================%s\n",
                C_BOLD, C_CYAN, C_RESET);
    } else {
        fprintf(stderr, "----------------------------------------------------------\n");
        fprintf(stderr, "  TOTAL   %d rule%s, %ld rewrite%s\n",
                nrules_fired, nrules_fired == 1 ? "" : "s",
                total_fired, total_fired == 1 ? "" : "s");
        if (nrules_fired == 0)
            fprintf(stderr, "  (no rules fired; input already optimal)\n");
        fprintf(stderr, "==========================================================\n");
    }
    fflush(stderr);
}

static void print_version(void)
{
    int ntable = 0;
    int i;
    const char *compiler = "unknown";
    const char *platform =
#if defined(_WIN32) || defined(_WIN64)
        "Windows"
#elif defined(__linux__)
        "Linux"
#elif defined(__APPLE__)
        "macOS"
#else
        "unknown"
#endif
#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__)
        " x64"
#elif defined(_M_IX86) || defined(__i386__)
        " x86"
#else
        ""
#endif
        ;

#if defined(__WATCOMC__)
    compiler = "Open Watcom / Watcom C";
#elif defined(__BORLANDC__)
    compiler = "Borland C++";
#elif defined(_MSC_VER)
    compiler = "Microsoft Visual C++";
#elif defined(__clang__)
    compiler = "Clang";
#elif defined(__GNUC__)
    compiler = "GCC";
#endif

    init_table_rules();
    ntable = g_nrules;

    print_banner(stdout);
    printf("Version     : %s\n", SMARTPP_VERSION);
    printf("Built       : %s %s\n", __DATE__, __TIME__);
#ifdef __WATCOMC__
    printf("Compiler    : %s (__WATCOMC__=%d)\n", compiler, __WATCOMC__);
#elif defined(__BORLANDC__)
    printf("Compiler    : %s (__BORLANDC__=%d)\n", compiler, __BORLANDC__);
#elif defined(_MSC_VER)
    printf("Compiler    : %s (_MSC_VER=%d)\n", compiler, _MSC_VER);
#elif defined(__clang__)
    printf("Compiler    : %s (%s)\n", compiler, __VERSION__);
#elif defined(__GNUC__)
    printf("Compiler    : %s %s\n", compiler, __VERSION__);
#else
    printf("Compiler    : %s\n", compiler);
#endif
    printf("Platform    : %s\n", platform);
    printf("Table rules : %d\n", ntable);
    printf("Max P-id    : %d (STSZ=%d)\n", STSZ - 1, STSZ);
    printf("\nRule catalogue (active / named slots only):\n");
    for (i = 1; i < STSZ; i++) {
        const char *nm = rule_name(i);
        if (nm[0] == '\0') continue;
        if (strcmp(nm, "(unnamed)") == 0) continue;
        if (strcmp(nm, "(withdrawn)") == 0) continue;
        if (strcmp(nm, "(reserved)") == 0) continue;
        if (strncmp(nm, "(handled", 8) == 0) continue;
        printf("  P%-4d  %s\n", i, nm);
    }
    printf("\nTable-engine entries (%d):\n", ntable);
    for (i = 0; i < ntable; i++) {
        printf("  P%-4d  %s\n", g_rules[i].rule_no, g_rules[i].desc);
    }
}

static void usage(FILE *f)
{
    print_banner(f);
    fprintf(f, "usage: smartpp [options] [in [out]]\n");
    fprintf(f, "       smartpp [options] -o out in\n");
    fprintf(f, "\n");
    fprintf(f, "Options:\n");
    fprintf(f, "  -m86|-m186|-m286|-m386|-m486|-m586|-m686|-m64\n");
    fprintf(f, "                  initial CPU level (default 8086; source directives override)\n");
    fprintf(f, "  -att|-intel     force AT&T or Intel syntax (default: auto-detect)\n");
    fprintf(f, "  -Os             optimize for speed (default)\n");
    fprintf(f, "  -Oz             optimize for size (shorter encoding preferred)\n");
    fprintf(f, "  -Ox             maximum optimization with non-100%%-safe transforms\n");
    fprintf(f, "  -mark|-nomark   enable/disable '; SMARTPP ...(Pn)' markers (default: on)\n");
    fprintf(f, "  -v|-nv          enable/disable per-line rule notices (default: off)\n");
    fprintf(f, "  -color|-ncolor  force colored diagnostics on/off (default: on)\n");
    fprintf(f, "  -I DIR         add include search path (repeatable)\n");
    fprintf(f, "  -noinclude     do not follow INCLUDE / include / .include\n");
    fprintf(f, "  -o FILE         output file (default stdout; '-' = stdin/stdout)\n");
    fprintf(f, "  -V|--version    detailed version, build, rules\n");
    fprintf(f, "  -h|--help       this help\n");
    fprintf(f, "\n");
    fprintf(f, "Applies conservative peephole rewrites (dead stores, jump threading,\n");
    fprintf(f, "constant folding, strength reduction, compiler idioms, x87 pairs, ...).\n");
    fprintf(f, "See README.md for the full rule catalogue (P1..P140) and design limits.\n");
    fprintf(f, "End-of-run summary always prints on stderr.\n");
}

static const char *cpu_name(int cpu)
{
    switch (cpu) {
        case 1:  return "8086";
        case 2:  return "80186";
        case 4:  return "80286";
        case 8:  return "80386";
        case 16: return "80486";
        case 32: return "Pentium (P5)";
        case 64: return "Pentium Pro (P6)";
        case 128: return "x86-64 (long mode)";
        default: return "unknown";
    }
}

int main(int argc, char *argv[])
{
    char *inpath = NULL, *outpath = NULL;
    FILE *in, *out;
    long i, nout = 0, ndel = 0;
    int argi;

    for (argi = 1; argi < argc; argi++) {
        char *a = argv[argi];
        if (a[0] == '-' && a[1] != '\0') {
            if (strcmp(a, "-o") == 0) {
                /* v2.18: don't consume the next arg if it looks like an
                 *  option (starts with '-') -- "-o -v file" was eating
                 *  "-v" as the output path, silently disabling verbose
                 *  and then erroring on "too many file arguments". */
                if (argi + 1 >= argc || argv[argi + 1][0] == '-') {
                    usage(stderr); return 1;
                }
                outpath = argv[++argi];
            }
            else if (a[1] == 'o' && a[2] != '\0') outpath = a + 2;
            else if (strcmp(a, "-v") == 0) opt_verbose = 1;          /* enable per-line notices */
            else if (strcmp(a, "-nv") == 0) opt_verbose = 0;         /* disable (default) */
            else if (strcmp(a, "-color") == 0) opt_color = 1;       /* force color ON */
            else if (strcmp(a, "-ncolor") == 0) opt_color = 0;      /* force color OFF */
            else if (strcmp(a, "--ncolor") == 0) opt_color = 0;     /* alias */
            else if (strcmp(a, "-mark") == 0) opt_mark = 1;          /* enable rewrite markers (default ON) */
            else if (strcmp(a, "-nomark") == 0) opt_mark = 0;        /* disable rewrite markers */
            else if (strcmp(a, "-Oz") == 0 || strcmp(a, "-oz") == 0) { opt_zopt = 1; opt_speed = 0; }
            else if (strcmp(a, "-Os") == 0 || strcmp(a, "-os") == 0) { opt_zopt = 0; opt_speed = 1; }
            else if (strcmp(a, "-Ox") == 0 || strcmp(a, "-ox") == 0) opt_aggressive = 1;
            else if (strcmp(a, "-noinclude") == 0) opt_noinclude = 1;
            else if (strcmp(a, "-I") == 0) {
                if (++argi >= argc) { usage(stderr); return 1; }
                if (g_ninc_paths < MAX_INCL_PATHS)
                    g_inc_paths[g_ninc_paths++] = argv[argi];
            }
            else if (a[1] == 'I' && a[2] != '\0') {
                if (g_ninc_paths < MAX_INCL_PATHS)
                    g_inc_paths[g_ninc_paths++] = a + 2;
            }
            else if (strcmp(a, "-att") == 0) {
                g_att = 1; g_gas = 1; g_synforced = 1;
            }
            else if (strcmp(a, "-intel") == 0) {
                g_att = 0; g_synforced = 1;
            }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "-?") == 0 ||
                     strcmp(a, "--help") == 0) { usage(stdout); return 0; }
            else if (strcmp(a, "--version") == 0 || strcmp(a, "-V") == 0) {
                print_version();
                return 0;
            }
            else if (strcmp(a, "-m86") == 0 || strcmp(a, "-m8086") == 0) {
                g_curcpu = 1;  g_cpu_max = 1;
            }
            else if (strcmp(a, "-m186") == 0) { g_curcpu = 2;  g_cpu_max = 2; }
            else if (strcmp(a, "-m286") == 0) { g_curcpu = 4;  g_cpu_max = 4; }
            else if (strcmp(a, "-m386") == 0) { g_curcpu = 8;  g_cpu_max = 8; }
            else if (strcmp(a, "-m486") == 0) { g_curcpu = 16; g_cpu_max = 16; }
            else if (strcmp(a, "-m586") == 0) { g_curcpu = 32; g_cpu_max = 32; }
            else if (strcmp(a, "-m686") == 0) { g_curcpu = 64; g_cpu_max = 64; }
            else if (strcmp(a, "-m64") == 0 ||
                     strcmp(a, "-mx64") == 0 ||
                     strcmp(a, "-mx86-64") == 0) { g_curcpu = 128; g_cpu_max = 128; }
            else {
                fprintf(stderr, "smartpp: unknown option '%s'\n", a);
                usage(stderr);
                return 1;
            }
        }
        else if (strcmp(a, "-") == 0) {
            if (inpath == NULL) inpath = a;
            else if (outpath == NULL) outpath = a;
            else { fprintf(stderr, "smartpp: too many file arguments\n"); return 1; }
        }
        else {
            if (inpath == NULL) inpath = a;
            else if (outpath == NULL) outpath = a;
            else { fprintf(stderr, "smartpp: too many file arguments\n"); return 1; }
        }
    }
    if (inpath == NULL) { usage(stderr); return 1; }
    if (outpath != NULL && strcmp(inpath, outpath) == 0 &&
        strcmp(inpath, "-") != 0) {
        fprintf(stderr, "smartpp: input and output are the same file\n");
        return 1;
    }

#ifdef _WIN32
    /* CP1252 so AUTHOR_STR (é = 0xE9) matches Spanish Windows consoles */
    SetConsoleOutputCP(1252);
    SetConsoleCP(1252);
#endif
    /* Unbuffered stderr so progress + summary always appear immediately */
    setvbuf(stderr, NULL, _IONBF, 0);

    print_banner(stderr);
    fprintf(stderr, "smartpp: loading '%s'...\n", inpath);
    fflush(stderr);

    if (strcmp(inpath, "-") == 0) {
        in = stdin;
        read_file(in);
    } else {
        read_file_path(inpath);
        in = NULL;
    }
    fprintf(stderr, "smartpp: read %ld lines\n", g_nlines);
    fflush(stderr);
    scan_indefs();
    detect_use32();
    collect_labels();
    fprintf(stderr, "smartpp: %ld labels, CPU %s\n", g_nlab, cpu_name(g_curcpu));
    fflush(stderr);
    init_table_rules();    /* v1.85: declarative rule engine */
    /* Fixed-point: keep running passes until no rewrite fires or
     *  MAX_PASSES is reached.  Each pass re-scans all live lines, so
     *  chained rewrites (P45 -> P35, P43 -> P9, P40 -> P9, P16 -> P18)
     *  converge without further machinery. */
    {
        int pass;
        for (pass = 0; pass < MAX_PASSES; pass++) {
            long n;
            /* v2.25 (S1): drop the pinfo cache at start of each pass.
             *  The previous pass may have rewritten or deleted lines;
             *  their cached pinfo is now stale.  The cache rebuilds
             *  lazily as parse_line is called. */
            pi_cache_invalidate_all();
            n = run_pass();
            g_passes_run = pass + 1;
            fprintf(stderr, "smartpp: pass %d: %ld rewrite%s\n",
                    g_passes_run, n, n == 1 ? "" : "s");
            fflush(stderr);
            if (n == 0) break;
        }
    }


    /* Count kept / deleted lines first (no I/O yet). */
    nout = 0;
    ndel = 0;
    for (i = 0; i < g_nlines; i++) {
        if (DEL(i)) ndel++;
        else        nout++;
    }

    /* ---- SUMMARY BEFORE writing the output file -------------------
     *  Writing a fully expanded INCLUDE of SMART.INC can take a long
     *  time (or look hung).  Emit the table now so the user always
     *  sees which rules fired. */
    print_summary(nout, ndel);
    fprintf(stderr, "smartpp: writing output...\n");

    out = (outpath == NULL || strcmp(outpath, "-") == 0) ? stdout : fopen(outpath, "wb");
    if (out == NULL) {
        fprintf(stderr, "smartpp: cannot create '%s'\n", outpath ? outpath : "(null)");
        return 1;
    }
    for (i = 0; i < g_nlines; i++) {
        if (DEL(i)) continue;
        fputs(L(i), out);
        switch (TERM(i)) {
        case 1: fputc('\n', out); break;
        case 2: fputs("\r\n", out); break;
        case 3: fputc('\r', out); break;
        default: break;
        }
    }
    /* Append a short comment footer with the hit summary */
    {
        int k;
        fprintf(out, "\n; ---- SMARTPP %s summary: %ld lines out, %ld removed, %d pass(es) ----\n",
                SMARTPP_VERSION, nout, ndel, g_passes_run);
        for (k = 1; k < STSZ; k++) {
            if (st[k] == 0) continue;
            fprintf(out, ";   P%d: %ld\n", k, st[k]);
        }
        fprintf(out, "; --------------------------------------------------------------------\n");
    }
    if (out != stdout) fclose(out);
    fprintf(stderr, "smartpp: done (%ld lines written).\n", nout);
    return 0;
}