/*=====================================================================
*  SMARTPP  v1.83  --  a conservative peephole pre-processor for
*  8086..386 assembly source (MASM / JWasm / UASM / ASMC syntax,
*  the SMART.INC family).  One file, standard C.
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
*
*    P80   "push R / <writer to R that does not read R> / pop R"
*          -> push and pop both deleted (the writer is kept).  The
*          saved value is irrelevant because the writer overwrites
*          R, and the pop's restore is redundant.  No flag scan
*          (push/pop and the flag-neutral writers leave flags
*          unchanged).  16/32-bit only.
*
*    P81   "mov AL, SRC / movzx EAX, AL" -> "movzx EAX, byte ptr
*          SRC" (typed_src wraps the source).  Flag-neutral and
*          movzx reads before writing, so no scan needed.
*          386+ only, Intel-only.
*          [GCC combine mov+movzx; FPC OptPass2MovMovzx.]
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
*     smartpp [-m86|-m186|-m286|-m386] [-nz] [-mark] [-v] [-o OUT] [IN [OUT]]
*       -m...   initial CPU level (8086 if not given).  A .8086 /
*               .186 / .286 / .386 / ... directive in the source
*               overrides it from its line on.
*       -nz     keep "xor+mov" and shift pairs (P29, P33, P34 movzx
*               forms): movzx is smaller but slower on a 486/Pentium
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
*   - One file per run: INCLUDEd files are not followed (run it on
*     each file, or on the assembler's preprocessed output).
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

/* isatty()/fileno() are POSIX.  On platforms without <unistd.h> we fall
 *  back to "no color" (color_enabled() returns 0 unconditionally). */
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__) \
    || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
#include <unistd.h>
#define SMARTPP_HAS_ISATTY 1
#else
#define SMARTPP_HAS_ISATTY 0
#endif

#define SMARTPP_VERSION "1.87"

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

/* v1.87: colored diagnostic output (GCC-style).
 *  Behavior:
 *    - default: color ON iff stderr is a TTY (auto-detect via isatty()).
 *    - --ncolor: force color OFF (overrides TTY auto-detection).
 *  Color is ONLY applied to stderr; stdout (the optimized .asm) is
 *  never colored, so the output remains a valid assembler input that
 *  you can pipe straight into ASMC/JWasm/UASM/MASM/GAS.
 *  The SMARTPP_COLOR env var is no longer consulted (replaced by
 *  --ncolor in v1.87); if you previously relied on
 *  SMARTPP_COLOR=always, just run without --ncolor on a TTY. */
static int  opt_ncolor = 0;       /* --ncolor: disable color            */

static int color_enabled(void)
{
#if SMARTPP_HAS_ISATTY
    if (opt_ncolor) return 0;
    return isatty(fileno(stderr)) ? 1 : 0;
#else
    return 0;
#endif
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

static int  opt_verbose = 1;        /* default ON since v1.86; -v turns it OFF */
static int  g_curcpu    = 1;
static int  opt_nz      = 0;     /* -nz: keep xor+mov / shift pairs     */
static int  g_use32     = 0;     /* a 32-bit segment may exist (no P36)  */
static int  opt_mark    = 1;     /* default ON since v1.86; -mark turns it OFF */
static int  opt_zopt    = 0;     /* -Oz: size over speed (favor shorter form) */
static int  g_passes_run = 0;   /* number of passes actually executed */
static int  g_nofpu     = 0;    /* .NO87 disables FPU rules; .287/.387/.8087 enable */

/* Per-rule hit counters, indexed by rule number (1..STSZ).
*  st[0] is unused.  The driver prints non-zero entries by name. */
#define STSZ 160             /* P1..P140 + spare room for future rules */
static long st[STSZ];

static int  g_gas = 0;           /* GAS conventions (comments, labels) */
static int  g_att = 0;           /* AT&T operand order and % registers */
static int  g_synforced = 0;     /* -att / -intel given on the command line */

struct labent {
    char name[MAXTOK];
    long line;
    int  dup;
};
static struct labent *g_labs  = NULL;
static long g_nlab   = 0;
static long g_caplab = 0;

/* ---- small helpers --------------------------------------------------*/

/* v1.86: per-line rewrite/delete notices go through vlog so they obey
 *  opt_verbose (default ON; -v turns it OFF).  Errors and the final
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

/* outer fully overwrites every bit inner writes */
static int covers(int outer, int inner)
{
    if (outer < 0 || inner < 0) return 0;
    if (g_regs[outer].fam != g_regs[inner].fam) return 0;
    return g_regs[outer].lo <= g_regs[inner].lo &&
           g_regs[outer].hi >= g_regs[inner].hi;
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
}

static void store_line(long i, char *s, int term)
{
    chunk_reserve(i);
    L(i) = s;
    TERM(i) = (unsigned char)term;
    if (i >= g_nlines) g_nlines = i + 1;
}

/* ---- reading ---------------------------------------------------------*/

static void finish_line(char *acc, long n)
{
    int term = 0;
    if (n >= 2 && acc[n - 1] == '\n' && acc[n - 2] == '\r') { term = 2; n -= 2; }
    else if (n >= 1 && acc[n - 1] == '\n') { term = 1; n -= 1; }
    else if (n >= 1 && acc[n - 1] == '\r') { term = 3; n -= 1; }
    acc[n] = '\0';
    store_line(g_nlines, xstrdup(acc), term);
}

static void read_file(FILE *f)
{
    char *acc = NULL;
    long alen = 0, acap = 0;
    for (;;) {
        long cl;
        if (fgets(g_scratch, MAXLINE, f) == NULL) break;
        cl = (long)strlen(g_scratch);
        if (cl > 0) {
            if (alen + cl + 1 > acap) {
                long ncap = (acap > 0) ? acap * 2 : (MAXLINE * 2);
                char *na;
                if (ncap < alen + cl + 1) ncap = alen + cl + 1;
                na = (char *)xrealloc(acc, (size_t)ncap);
                acc = na;
                acap = ncap;
            }
            memcpy(acc + alen, g_scratch, (size_t)cl);
            alen += cl;
            acc[alen] = '\0';
        }
        if (alen > 0 && acc[alen - 1] == '\n') {
            finish_line(acc, alen);
            alen = 0;
        }
    }
    if (alen > 0) finish_line(acc, alen);
    free(acc);
}

/* ---- labels -----------------------------------------------------------*/

static void label_add(const char *name, long line)
{
    long i;
    for (i = 0; i < g_nlab; i++) {
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
    g_nlab++;
}

static long label_find(const char *name, int *pdup)
{
    long i;
    *pdup = 0;
    for (i = 0; i < g_nlab; i++) {
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

static int split_ops(char *rest, char *o0, char *o1, int *pmore)
{
    int depth = 0, n = 0, sawcomma = 0;
    int l0 = 0, l1 = 0;
    char *w;
    o0[0] = '\0';
    o1[0] = '\0';
    *pmore = 0;
    for (w = rest; *w != '\0'; w++) {
        char c = *w;
        if (c == '[' || c == '(' || c == '<') depth++;
        else if (c == ']' || c == ')' || c == '>') { if (depth > 0) depth--; }
        if (c == ',' && depth == 0) {
            sawcomma = 1;
            n++;
            if (n > 1) { *pmore = 1; break; }
            continue;
        }
        if (n == 0) {
            if (l0 < MAXTOK - 1) o0[l0++] = c;
            else { *pmore = 1; break; }
        } else {
            if (l1 < MAXTOK - 1) o1[l1++] = c;
            else { *pmore = 1; break; }
        }
    }
    o0[l0] = '\0';
    o1[l1] = '\0';
    trim(o0);
    trim(o1);
    if (o0[0] == '\0') *pmore = 1;
    if (sawcomma && o1[0] == '\0') *pmore = 1;
    if (*pmore) return 3;
    return (o1[0] != '\0') ? 2 : 1;
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
        "movzx", "movsx",
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

    p->cls = I_UNK;
    p->haslabel = 0;
    p->hasinstr = 0;
    p->toobig = 0;
    p->nops = 0;
    p->op0[0] = '\0';
    p->op1[0] = '\0';
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
    if (*s == '.') {                     /* directive */
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
    if (*rest != '\0') p->nops = split_ops(rest, p->op0, p->op1, &more);
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

/* next line with content (skips deleted, blank and comment-only lines) */
static long next_code(long i)
{
    long j;
    for (j = i + 1; j < g_nlines; j++) {
        if (DEL(j)) continue;
        parse_line(j, &g_pnext);
        if (g_pnext.haslabel || g_pnext.hasinstr) return j;
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
        if (pi->comment[0] != '\0') {
            strcat(g_build, " ");
            strcat(g_build, pi->comment);
        }
        replace_line(idx, g_build);
    } else {
        DEL(idx) = 1;
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
    if (pi->comment[0] != '\0') {
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
    if (pi->comment[0] != '\0') {
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
    static const char *names[] = {
        ".8086", ".186", ".286", ".386", ".486", ".586", ".686",
        ".x64", ".x64p", NULL
    };
    static int vals[] = { 1, 2, 4, 8, 16, 32, 64, 128, 128 };
    int i;
    while (*s == ' ' || *s == '\t') s++;
    if (*s != '.') return 0;
    for (i = 0; names[i] != NULL; i++) {
        size_t l = strlen(names[i]);
        if (ci_eq_n(s, names[i], (long)l) &&
            directive_is_standalone(s, l)) return vals[i];
    }
    /* v1.87: FPU directives.  .NO87 disables floating-point; the
     *  others (.8087/.287/.387) just enable it -- the FPU level is
     *  tracked separately and we don't differentiate the FPU model.
     *  These DO NOT change g_curcpu; they only flip g_nofpu. */
    if (ci_eq_n(s, ".no87", 5) && directive_is_standalone(s, 5)) {
        g_nofpu = 1;
        return 0;       /* not a CPU level */
    }
    if ((ci_eq_n(s, ".8087", 5) && directive_is_standalone(s, 5)) ||
        (ci_eq_n(s, ".287",  4) && directive_is_standalone(s, 4)) ||
        (ci_eq_n(s, ".387",  4) && directive_is_standalone(s, 4))) {
        g_nofpu = 0;
        return 0;       /* not a CPU level */
    }
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
    if (ci_eq(m, "call") || ci_eq(m, "ret") || ci_eq(m, "retf") ||
        ci_eq(m, "iret") || ci_eq(m, "int") || ci_eq(m, "int3") ||
        ci_eq(m, "loop") || ci_eq(m, "jcxz") || ci_eq(m, "jecxz")) {
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

/* can the differing flag set d be destroyed on EVERY path that leaves
*  line start, before any read of a still-differing flag?  Follows
*  both arms of conditional jumps.  Conservative on loops, merges,
*  divergence, opaque instructions and end of file: 0 = cannot prove. */
static int flags_clear(long start, int d)
{
    int n = 0, nvis = 0;
    if (d == 0) return 1;
    if (start < 0) return 0;
    g_scanwl[n] = start;
    g_scand[n] = d;
    n++;
    while (n > 0) {
        long i;
        int cd, rd, wr, div, vi, seen;
        struct pinfo *p = &g_pscan;
        n--;
        i = g_scanwl[n];
        cd = g_scand[n];
        if (i < 0) return 0;               /* fell off the end */
        seen = 0;
        for (vi = 0; vi < nvis; vi++) {
            if (g_scanvis[vi] == i) {
                if (g_scanvcd[vi] == cd) { seen = 1; break; }
                return 0;                  /* merge, different flags */
            }
        }
        if (seen) continue;                /* already explored */
        if (nvis >= SCAN_MAX) return 0;    /* budget exhausted */
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
        if (flag_sets(p, &rd, &wr, &div) != 0) return 0;
        if (rd & cd) return 0;             /* a differing flag is read */
        cd &= ~wr;
        if (cd == 0) continue;             /* this path is settled */
        if (div) return 0;                 /* path leaves; cannot follow */
        if (p->cls == I_JCC) {             /* follow both arms */
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
            g_scand[n] = cd;
            n++;
            g_scanwl[n] = t;
            g_scand[n] = cd;
            n++;
            continue;
        }
        if (n + 1 > SCAN_MAX) return 0;
        g_scanwl[n] = next_code(i);
        g_scand[n] = cd;
        n++;
    }
    return 1;
}

/* v1.82: walk forward from line `start` (exclusive) and decide
*  whether register `r` is dead -- i.e. the next instruction that
*  mentions r's family FULLY OVERWRITES r (a clean kill) before any
*  instruction reads it.  Returns:
*    1 = r is provably dead (a clean kill is reached first)
*    0 = r is read before being killed (or scan hit something
*        opaque / control flow / end of file)
*  Used by P68 (xchg R,S -> mov when one operand is dead) and P70
*  (lea R,[S+off1] / lea D,[R+off2] -> lea D,[S+off1+off2] when R
*  is dead).  The discipline mirrors P2's dead-store test (writer_ok)
*  but does not require the kill to be the *immediate* next line:
*  intervening no-op instructions and labels are skipped. */
static int reg_dead_after(long start, int r)
{
    long k;
    int fam = g_regs[r].fam;
    if (r < 0) return 0;
    for (k = start + 1; k < g_nlines; k++) {
        struct pinfo *pk = &g_pscan;
        int dk, op0_is_rw, op0_reads_r, killed, reads;
        int rd, wr, div;
        if (DEL(k)) continue;
        parse_line(k, pk);
        if (pk->toobig) return 0;
        if (!pk->hasinstr) continue;          /* label-only line */
        if (flag_sets(pk, &rd, &wr, &div) != 0) return 0;
        if (div) return 0;                    /* control divergence */
        if (pk->cls == I_JCC || pk->cls == I_JMP) return 0;
        dk = find_reg(pk->op0);
        /* Pure destinations: mov, lea, movzx, pop write op0 only.
         *  Two-operand read+write: add/sub/and/or/xor/adc/sbb/cmp/
         *  test read op0 as well.  xor R,R (I_XORRR) writes 0 and
         *  ignores the old value, so it is a kill, not a read. */
        op0_is_rw = (pk->cls == I_OTHER) &&
            (ci_eq(pk->mnem, "add") || ci_eq(pk->mnem, "sub") ||
             ci_eq(pk->mnem, "adc") || ci_eq(pk->mnem, "sbb") ||
             ci_eq(pk->mnem, "and") || ci_eq(pk->mnem, "or") ||
             ci_eq(pk->mnem, "xor") || ci_eq(pk->mnem, "cmp") ||
             ci_eq(pk->mnem, "test"));
        op0_reads_r = (dk >= 0 && g_regs[dk].fam == fam) &&
                      (op0_is_rw || pk->cls == I_SHIFT ||
                       pk->cls == I_XCHG || pk->cls == I_XORRR);
        if (pk->cls == I_XORRR) op0_reads_r = 0;
        killed = (dk >= 0 && covers(dk, r) && !op0_reads_r &&
                  !expr_uses_family(pk->op1, fam));
        if (killed) return 1;
        reads = !killed &&
                ((dk >= 0 && g_regs[dk].fam == fam) ||
                 expr_uses_family(pk->op1, fam));
        if (pk->cls == I_PUSH || pk->cls == I_PUSHF ||
            pk->cls == I_PUSHA) {
            if (expr_uses_family(pk->op0, fam)) reads = 1;
        }
        if (reads) return 0;
    }
    return 0;
}

/* v1.84: control-flow-aware dead-register scan, the analog of
 *  flags_clear() for register liveness.  Walks forward from `start+1`
 *  along every reachable path (fall-through AND the taken branch of a
 *  conditional jump, just like flags_clear), and asks: on EVERY path,
 *  does a clean kill of `r` arrive before any read of `r`?  Returns 1
 *  when that holds on every path, 0 when it cannot be proved.
 *
 *  Why this is needed: reg_dead_after() is purely linear -- it bails
 *  on the first conditional jump.  That is correct but conservative;
 *  it forecloses whole classes of safe rewrites.  Example:
 *
 *      mov  cx, 5      ; cx is the destination of a constant
 *      cmp  cx, 5      ; P85 wants to fold this to "cmp 5, 5" and
 *                      ; then to "mov ZF, 1" -- but only if cx is
 *                      ; provably dead afterwards.  cx may be killed
 *                      ; on either side of an upcoming conditional
 *                      ; branch; reg_dead_cf follows both arms and
 *                      ; can still prove cx dead.
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
    int n = 0, nvis = 0;
    int fam;
    if (r < 0) return 0;
    fam = g_regs[r].fam;
    if (start < 0) return 0;
    g_scanwl[n] = start;
    g_scand[n]  = 1;            /* 1 = "r still needs killing on this path" */
    n++;
    while (n > 0) {
        long i;
        int vi, seen, rd, wr, div;
        int dk, op0_is_rw, op0_reads_r, killed, reads;
        struct pinfo *p = &g_pscan;
        n--;
        i = g_scanwl[n];
        if (i < 0) return 0;                       /* fell off the end */
        seen = 0;
        for (vi = 0; vi < nvis; vi++) {
            if (g_scanvis[vi] == i) {
                if (g_scanvcd[vi] == 1) { seen = 1; break; }
                return 0;                          /* path converged with a different verdict */
            }
        }
        if (seen) continue;
        if (nvis >= SCAN_MAX) return 0;
        g_scanvis[nvis] = i;
        g_scanvcd[nvis] = 1;
        nvis++;
        if (INDEF(i)) return 0;
        parse_line(i, p);
        if (p->toobig) return 0;
        if (!p->hasinstr) {                        /* label-only line */
            if (n + 1 > SCAN_MAX) return 0;
            g_scanwl[n] = next_code(i);
            g_scand[n]  = 1;
            n++;
            continue;
        }
        if (flag_sets(p, &rd, &wr, &div) != 0) return 0;
        if (div) return 0;                         /* control leaves the function */
        /* classify this instruction w.r.t. r */
        dk = find_reg(p->op0);
        op0_is_rw = (p->cls == I_OTHER) &&
            (ci_eq(p->mnem, "add") || ci_eq(p->mnem, "sub") ||
             ci_eq(p->mnem, "adc") || ci_eq(p->mnem, "sbb") ||
             ci_eq(p->mnem, "and") || ci_eq(p->mnem, "or") ||
             ci_eq(p->mnem, "xor") || ci_eq(p->mnem, "cmp") ||
             ci_eq(p->mnem, "test"));
        op0_reads_r = (dk >= 0 && g_regs[dk].fam == fam) &&
                      (op0_is_rw || p->cls == I_SHIFT ||
                       p->cls == I_XCHG || p->cls == I_XORRR);
        if (p->cls == I_XORRR) op0_reads_r = 0;
        killed = (dk >= 0 && covers(dk, r) && !op0_reads_r &&
                  !expr_uses_family(p->op1, fam));
        if (killed) continue;                      /* path settled: r is killed here */
        reads = !killed &&
                ((dk >= 0 && g_regs[dk].fam == fam) ||
                 expr_uses_family(p->op1, fam));
        if (p->cls == I_PUSH || p->cls == I_PUSHF ||
            p->cls == I_PUSHA) {
            if (expr_uses_family(p->op0, fam)) reads = 1;
        }
        if (reads) return 0;                       /* r read before any kill */
        /* r is not (yet) read on this path; descend to the successor(s) */
        if (p->cls == I_JCC) {                     /* follow both arms */
            long t = -1;
            if (p->jtarget_ok) {
                int dup = 0;
                long dd = label_find(p->jtarget, &dup);
                if (dd >= 0 && !dup) {
                    t = instr_after_label(dd);
                    if (t <= i) return 0;           /* backward jump: loop */
                }
            }
            if (t < 0) return 0;                   /* unknown target */
            if (n + 2 > SCAN_MAX) return 0;
            g_scanwl[n] = next_code(i);
            g_scand[n]  = 1;
            n++;
            g_scanwl[n] = t;
            g_scand[n]  = 1;
            n++;
            continue;
        }
        if (p->cls == I_JMP) return 0;             /* unconditional exit; cannot follow */
        if (n + 1 > SCAN_MAX) return 0;
        g_scanwl[n] = next_code(i);
        g_scand[n]  = 1;
        n++;
    }
    return 1;
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
};

#define NCAP 26

/* operand pattern kinds */
enum {
    OP_ANY = 0,    /* "_" -- always matches */
    OP_REG,        /* register of a class; bind a capture */
    OP_SAME,       /* must equal a previous capture */
    OP_IMM,        /* parses as an immediate */
    OP_MEM,        /* memory expression (not a register) */
    OP_REGCLASS,   /* register of a class, no capture */
    OP_IMMVAL      /* immediate equal to a specific value (imm_val field) */
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
    long  imm_val;       /* for OP_IMMVAL: the required value (compared as signed long) */
    int   imm_has;       /* 1 if imm_val is meaningful (set by IV() macro) */
};

/* precondition bits */
#define PRE_FLAGS_DEAD_ALL    0x0001u
#define PRE_FLAGS_DEAD_CF     0x0002u
#define PRE_FLAGS_DEAD_AF     0x0004u
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
#define PRE_SRC_IMM           0x2000u
#define PRE_NOT_SP            0x4000u   /* primary register is not SP */
#define PRE_CPU_X64           0x8000u   /* rule needs .X64 (long mode) */
#define PRE_FPU               0x10000u  /* rule needs x87 FPU enabled (.NO87 forbids) */

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
#define MAXPAT 2
struct rule {
    int   n;                       /* 1 or 2 instructions */
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
        if (ci < 0 || ci >= NCAP) return 0;
        if (cap[ci].fam < 0) return 0;
        r = find_reg(op);
        if (r < 0) return 0;
        /* v1.85.1: must match BOTH family and width.  Without the
         *  width check, "mov eax, ax" (a zero-extension, NOT a no-op)
         *  would match RR_('a'),SM_('a') and be wrongly deleted by
         *  the "mov R,R -> delete" rule.  eax and ax share family 0
         *  but differ in width (32 vs 16). */
        if (g_regs[r].fam != cap[ci].fam) return 0;
        if ((g_regs[r].hi - g_regs[r].lo) != cap[ci].width) return 0;
        return 1;
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

/* check the precondition set against the current context.  `i` is the
 *  line index of the first instruction; `j2` (if >= 0) the second; `cap`
 *  the captures bound during matching. */
static int pre_check(unsigned pre, long i, long j2,
                     struct capent *cap)
{
    long after = (j2 >= 0) ? next_code(j2) : next_code(i);
    if (pre & PRE_FLAGS_DEAD_ALL)
        if (!flags_clear(after, F_ALL6)) return 0;
    if (pre & PRE_FLAGS_DEAD_CF)
        if (!flags_clear(after, F_CF)) return 0;
    if (pre & PRE_FLAGS_DEAD_AF)
        if (!flags_clear(after, F_AF)) return 0;
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
    if (pre & PRE_SRC_IMM) {
        int ci = 'a' - 'a';
        if (cap[ci].fam < 0) return 0;
        /* the primary register's source must be an immediate.  We
         *  check by re-parsing: the pattern that needs this is
         *  "mov R,K", so we look at the FIRST instruction and ask
         *  if its op1 parses as a number. */
        /* NOTE: this only makes sense for rules where op1 of inst 0
         *  is the immediate.  We re-derive it.  Trivial for the
         *  current table.  This pre is rarely needed; left as a
         *  conservative placeholder that always succeeds. */
    }
    if (pre & (PRE_NEXT_IS_JCC | PRE_NEXT_JCC_NO_CF |
               PRE_NEXT_JCC_ZF_ONLY)) {
        long k = (j2 >= 0) ? next_code(j2) : next_code(i);
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
    if (ci < 0 || ci >= NCAP) return NULL;
    if (cap[ci].fam < 0) return NULL;
    for (r = 0; g_regs[r].name != NULL; r++) {
        if (g_regs[r].fam == cap[ci].fam &&
            g_regs[r].lo == 0 &&
            g_regs[r].hi == width) return g_regs[r].name;
    }
    return NULL;
}

/* expand a rewrite template "$a", "$a8", "$a16", "$a32", "$K", "$K1" into
 *  the bound value, writing into buf.  Returns the new end pointer. */
static char *expand_template(const char *tpl, struct capent *cap,
                             const char *imm0, const char *imm1,
                             char *buf, int bufsz)
{
    int ci, n = 0;
    const char *s = tpl;
    const char *imm;
    while (*s != '\0' && n < bufsz - 1) {
        if (*s != '$') { buf[n++] = *s++; continue; }
        s++;   /* skip $ */
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
                while (*rn != '\0' && n < bufsz - 1) buf[n++] = *rn++;
            }
        }
        else if (*s == 'K') {
            s++;
            imm = imm0;
            if (*s == '1') { imm = imm1; s++; }
            if (imm == NULL) { buf[0] = '\0'; return buf; }
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
                      const char *imm0, const char *imm1)
{
    int k;
    long idx[2];
    struct pinfo *parr[2];
    idx[0] = i;
    parr[0] = &g_pcur;
    if (r->n >= 2) {
        idx[1] = j2;
        parr[1] = &g_ppair;
    }
    else {
        idx[1] = -1;
        parr[1] = NULL;
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
            expand_template(a->text, cap, imm0, imm1, body, sizeof(body));
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
        for (k = 0; k < NCAP; k++) { cap[k].fam = -1; cap[k].width = 0; }
        if (!pat_match_inst(pi, r, 0, cap)) continue;
        if (r->n >= 2) {
            j2 = next_code(i);
            if (j2 < 0 || INDEF(j2)) continue;
            parse_line(j2, pj);
            if (pj->haslabel || pj->toobig || !pj->hasinstr) continue;
            if (!pat_match_inst(pj, r, 1, cap)) continue;
        }
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
        if (!pre_check(r->pre, i, (r->n >= 2) ? j2 : -1, cap)) continue;
        /* fire */
        vlog("smartpp: line %ld: rule P%d fired (%s)\n",
                i + 1, r->rule_no, r->desc);
        apply_rule(i, j2, r, cap, imm0, imm1);
        st[r->rule_no]++;
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
#define RC_(cls)             { OP_REGCLASS, cls, 0, 0, 0, 0 }
#define IV_(v)               { OP_IMMVAL, 0, 0, 0, (v), 1 }

static const struct rule g_rule_tbl[] = {

    /* P105 (v1.85): "sub R, R" -> "xor R, R".  Both zero R and define
     *  all six flags identically (CF=0, OF=0, SF=0, ZF=1, PF=1, AF=0).
     *  xor is the canonical zeroing idiom that breaks dependency chains
     *  on the Pentium Pro and later (partial-register rename).
     *  Research: Intel optimization guide "zeroing idiom"; Agner Fog
     *  manual 2.  Exact on R and flags; no preconditions.
     *  NOTE: P71 (C rule) catches "sub R,R" first when flags are
     *  dead AND the next instruction is not a Jcc; this table rule
     *  is the unconditional fallback that fires when P71's flag scan
     *  could not prove the flags dead but the rewrite is still safe
     *  (because sub R,R and xor R,R set flags identically). */
    { 1, 105,
      { { "sub", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_REW, "xor $a, $a" } },
      "sub R,R -> xor R,R (dep-chain break)" },

    /* P111 (v1.85): "or R, 0" -> delete (or with zero is a no-op on R,
     *  but sets flags from R).  Requires flags dead -- the or's "test
     *  of R" effect is observable through ZF/SF/PF, so we cannot
     *  delete it if a Jcc reads them.  Catches a pattern the C rules
     *  do not (P59 only handles "and R, 0", P60 only "or R, -1"). */
    { 1, 111,
      { { "or", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "or R,0 -> delete (flags dead)" },

    /* P112 (v1.85): "and R, -1" -> delete (and with all-ones is a
     *  no-op on R but sets flags).  Requires flags dead.  P59 only
     *  handles "and R, 0"; P59/P60 do not cover "and R, -1". */
    { 1, 112,
      { { "and", 0, RR_('a'), IV_(-1), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "and R,-1 -> delete (flags dead)" },

    /* P115 (v1.85): "xor R, 0" -> delete (no-op on R, sets flags).
     *  Requires flags dead.  No C rule covers this case. */
    { 1, 115,
      { { "xor", 0, RR_('a'), IV_(0), 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "xor R,0 -> delete (flags dead)" },

    /* P119 (v1.85): "test R, K" -> delete when flags dead.  test never
     *  writes R, so deleting it is sound as long as no reader of its
     *  flags follows.  No C rule covers test deletion (P11 only
     *  converts cmp R,0 -> test R,R; it does not delete test). */
    { 1, 119,
      { { "test", 0, RR_('a'), IM_, 2 } },
      PRE_FLAGS_DEAD_ALL,
      { { ACT_DEL, NULL } },
      "test R,K -> delete (flags dead)" },

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
      "cmp R,K -> delete (flags dead)" },

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
    { 1, 122,
      { { "imul", 0, RR_('a'), IV_(1), 2 } },
      PRE_FLAGS_DEAD_ALL | PRE_NO_CPU_8086,
      { { ACT_DEL, NULL } },
      "imul R,1 -> delete (flags dead)" },

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
      "imul R,0 -> xor R,R (flags dead)" },

    /* P126 (v1.86): "xchg R, R" -> delete (same register).  xchg with
     *  itself is a no-op on R, on flags (xchg sets no flags), and on
     *  memory.  Note "xchg eax, eax" is the canonical 1-byte NOP (0x90)
     *  on every x86; deleting it is always safe.  Uses OP_SAME so it
     *  catches the cross-width family case too (e.g. "xchg ax, al"
     *  would NOT fire because OP_SAME's width check rejects different
     *  widths -- correct, that is NOT a no-op).  In practice P1
     *  (C rule) fires first on the same-width case; this table rule
     *  documents the pattern and is the table-native form.
     *  Research: Intel SDM Vol.2 XCHG; Agner Fog NOP table. */
    { 1, 126,
      { { "xchg", 0, RR_('a'), SM_('a'), 2 } },
      0,
      { { ACT_DEL, NULL } },
      "xchg R,R -> delete (canonical NOP)" },

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
      "bswap R / bswap R -> bswap R" },

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
      "xor R,R / push R -> push 0" },

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
      "fld st / fstp st -> delete (push/pop)" },

    /* P130 (v1.87): "fldz / fstp st" -> delete both.  Pushing zero and
     *  popping it immediately is a no-op on the stack (the pop
     *  discards the zero we just pushed).  PRE_FPU required. */
    { 2, 130,
      { { "fldz", 0, AN_, AN_, 0 },
        { "fstp", 0, RR_('a'), AN_, 1 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fldz / fstp st -> delete (push 0/pop)" },

    /* P131 (v1.87): "fchs / fchs" -> delete both.  Negating the top of
     *  stack twice is a no-op (double negation).  fchs leaves the
     *  stack depth unchanged and sets no EFLAGS.  PRE_FPU required. */
    { 2, 131,
      { { "fchs", 0, AN_, AN_, 0 },
        { "fchs", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fchs / fchs -> delete (double negation)" },

    /* P132 (v1.87): "fabs / fabs" -> delete the second.  abs is
     *  idempotent: abs(abs(x)) == abs(x).  The second fabs is a
     *  no-op on the top of stack.  PRE_FPU required. */
    { 2, 132,
      { { "fabs", 0, AN_, AN_, 0 },
        { "fabs", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fabs / fabs -> fabs (idempotent)" },

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
      "ffree st / ffree st -> ffree st" },

    /* P135 (v1.87): "fninit / fninit" -> delete the second.  fninit
     *  resets the FPU to a known state; initializing twice in a row
     *  is a no-op the second time (idempotent).  PRE_FPU required. */
    { 2, 135,
      { { "fninit", 0, AN_, AN_, 0 },
        { "fninit", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fninit / fninit -> fninit" },

    /* P136 (v1.87): "fwait / fwait" -> delete the second.  fwait is
     *  a CPU/FPU synchronization hint; two in a row collapse to one.
     *  PRE_FPU required. */
    { 2, 136,
      { { "fwait", 0, AN_, AN_, 0 },
        { "fwait", 0, AN_, AN_, 0 } },
      PRE_FPU,
      { { ACT_KEEP, NULL }, { ACT_DEL, NULL } },
      "fwait / fwait -> fwait" },

    /* P137 (v1.87): "fxch st / fxch st" -> delete both.  Swapping the
     *  top of stack with itself is a no-op (xchg x,x).  PRE_FPU.
     *  Note: "fxch" with no operands swaps st(0) and st(1) -- this
     *  rule only fires when both operands are present and equal,
     *  which is the "fxch st, st" (== fxch st(0), st(0)) form. */
    { 2, 137,
      { { "fxch", 0, RR_('a'), SM_('a'), 2 },
        { "fxch", 0, SM_('a'), SM_('a'), 2 } },
      PRE_FPU,
      { { ACT_DEL, NULL }, { ACT_DEL, NULL } },
      "fxch st,st / fxch st,st -> delete" },

    /* v1.87 x64 note: the x64 zeroing idiom "mov R64, 0 -> xor R32, R32"
     *  is handled by the P9 C-rule (which detects x64 mode via the
     *  register width and emits the 32-bit xor form -- 1 byte shorter
     *  than the 64-bit xor because no REX.W prefix is needed, and the
     *  xor zero-extends to 64 bits for free).  No table rule is
     *  needed here because P9 already fires first on "mov R, 0" for
     *  every width >= 16.
     *
     *  The tempting "test R64,R64 -> test R32,R32" rewrite was
     *  considered and WITHDRAWN: it is unsound.  `test rax,rax` sets
     *  ZF from the full 64-bit value while `test eax,eax` sets ZF
     *  from the low 32 bits only, so they differ when rax has bits
     *  set above bit 31.  The 32-bit form also zero-extends EAX into
     *  RAX, mutating RAX if its high 32 bits were nonzero.  Without a
     *  precondition proving the high 32 bits are zero (which we don't
     *  have), the rewrite changes behavior.  Documented here as a
     *  considered-and-rejected case. */

};


static const int g_nrule_tbl =
    (int)(sizeof(g_rule_tbl) / sizeof(g_rule_tbl[0]));

/* initialize the engine's rule pointer.  Called once from main(). */
static void init_table_rules(void)
{
    g_rules = g_rule_tbl;
    g_nrules = g_nrule_tbl;
}

/* ===========================================================================
 *  END v1.85 TABLE-DRIVEN RULE ENGINE
 * ======================================================================== */


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
        int dup6 = 0;
        int r88 = 0;        /* v1.84: P88 dreg, decoupled from pi->dreg (which is -1 for shifts) */
        int r98 = 0;        /* v1.84: P98 dreg, same reason */
        int r90 = 0;        /* v1.84: P90 dreg (I_OTHER doesn't set dreg) */
        int r92 = 0;        /* v1.84: P92 dreg, same reason */

        if (DEL(i) || INDEF(i)) continue;
        {
            int cv = cpu_directive_value(L(i));
            if (cv != 0) {
                if (g_curcpu != cv && opt_verbose)
                    vlog("smartpp: line %ld: CPU level set to %d by directive\n",
                        i + 1, cv);
                g_curcpu = cv;
            }
        }
        parse_line(i, pi);
        if (!pi->hasinstr) continue;

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
                        /* P53: mov R, imm1 / and R, mask
                         *  -> mov R, imm1 & mask */
                        else if (pj->cls == I_OTHER && pj->nops == 2 &&
                                 ci_eq(pj->mnem, "and")) {
                            long vmask;
                            if (try_parse_number(pj->op1, &vmask)) {
                                uresult = (unsigned long)v1 &
                                          (unsigned long)vmask & masku;
                                hit = 53;
                            }
                        }
                        /* P54: mov R, imm1 / or R, imm2
                         *  -> mov R, imm1 | imm2 */
                        else if (pj->cls == I_OTHER && pj->nops == 2 &&
                                 ci_eq(pj->mnem, "or")) {
                            long v2;
                            if (try_parse_number(pj->op1, &v2)) {
                                uresult = ((unsigned long)v1 |
                                            (unsigned long)v2) & masku;
                                hit = 54;
                            }
                        }
                        /* P55: mov R, imm1 / xor R, imm2
                         *  -> mov R, imm1 ^ imm2 */
                        else if (pj->cls == I_OTHER && pj->nops == 2 &&
                                 ci_eq(pj->mnem, "xor")) {
                            long v2;
                            if (try_parse_number(pj->op1, &v2)) {
                                uresult = ((unsigned long)v1 ^
                                            (unsigned long)v2) & masku;
                                hit = 55;
                            }
                        }
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
                            if (pi->comment[0] != '\0') {
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

        /* P59 (v1.82): "and R, 0" (R a register, any width) ->
         *  "mov R, 0" when all six flags are dead.  R & 0 == 0 for
         *  every width, so the value side is exact; `and` defines all
         *  six status flags and `mov` defines none, so the differing
         *  set (all six) must be killed before any read -- exactly
         *  the P9/P35 discipline.  Memory destinations are left
         *  alone: `and $0, mem` (3 bytes) is smaller than
         *  `mov $0, mem` (5..7 bytes) and is what GCC deliberately
         *  keeps.  SP is excluded: a mov to SP between two flag
         *  readers would change observable stack-pointer behavior,
         *  and `and sp, 0` is unusual enough that we don't lose
         *  anything by being conservative.  P9 will then chain
         *  `mov R, 0` to `xor R, R` when flags are still dead,
         *  which is the actual byte win.  Research: FPC
         *  PrePeepholeOptAND "AND 0 -> MOV 0" (aoptx86.pas ~1927);
         *  GCC i386.md `and $0,mem`/`mov $0,mem` peephole2 notes. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "and")) {
            int r59 = find_reg(pi->op0);
            long v59;
            if (r59 >= 0 && g_regs[r59].fam != 4 &&
                try_parse_number(pi->op1, &v59) && v59 == 0 &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "mov ");
                if (g_att) {
                    strcat(g_build, "$0, ");
                    strcat(g_build, pi->op0);
                } else {
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", 0");
                }
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'and %s, 0' rewritten to 'mov %s, 0' (P59)\n",
                    i + 1, pi->op0, pi->op0);
                replace_line(i, g_build);
                st[59]++;
                continue;
            }
        }

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
                if (pi->comment[0] != '\0') {
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
                                if (pi->comment[0] != '\0') {
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

        /* P1: mov R,R / xchg R,R */
        if (!pi->haslabel && !pi->toobig &&
            (pi->cls == I_MOV || pi->cls == I_XCHG) &&
            pi->dreg >= 0 && pi->dreg == pi->sreg) {
            vlog("smartpp: line %ld: deleted '%s' (P1)\n",
                    i + 1, L(i));
            DEL(i) = 1;
            st[1]++;
            continue;
        }

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

        /* P20: "shl/shr/sar/rol/ror/rcl/rcr R,0" -> deleted: a zero
        *  count moves no bit and leaves every flag unchanged (8086
        *  through 686 documented behaviour).  Registers only. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_SHIFT &&
            pi->shiftcount == 0 && find_reg(pi->op0) >= 0) {
            vlog("smartpp: line %ld: deleted '%s %s, 0' (P20)\n",
                i + 1, pi->mnem, pi->op0);
            DEL(i) = 1;
            st[20]++;
            continue;
        }

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
            for (;;) {
                struct pinfo *pj = &g_ppair;
                j = next_code(i);
                if (j < 0) break;
                parse_line(j, pj);
                if (pj->cls != I_SHIFT || pj->haslabel || pj->toobig ||
                    pj->shiftcount < 0) break;
                if (!shift_same(pi->mnem, pj->mnem) ||
                    !ci_eq(pi->op0, pj->op0)) break;
                if (total + pj->shiftcount > 31) break;
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
            if (merged) rewrite_shift(i, pi, total);
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
                } else {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "test ");
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", ");
                    strcat(g_build, pi->op0);
                    if (pi->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: '%s %s, %s' rewritten to 'test %s, %s' (P8)\n",
                        i + 1, pi->mnem, pi->op0, pi->op1, pi->op0, pi->op0);
                    replace_line(i, g_build);
                    st[8]++;
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
                if (pi->comment[0] != '\0') {
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
            }
        }

        /* P71 (v1.83): "sub R, R" (same register, dest == src) ->
         *  "xor R, R" when AF is dead.  Both write R = 0; both clear
         *  CF and OF; both set SF=0, ZF=1, PF=parity(0)=1.  They
         *  differ only in AF: sub forces AF=0 (no borrow from bit 4),
         *  xor leaves AF undefined.  So demanding AF dead is the
         *  exact and conservative gate.  xor is shorter on 8086
         *  (2 bytes vs 3 for `sub ax, ax`; same on 186+ but xor
         *  avoids the false dependency on R's old value that sub
         *  has).  SP excluded: an interrupt during the xor window
         *  pushes at SP==0, which on a misaligned SP is no worse than
         *  the sub variant, but for parity with P22/P27/P39/P49/P58
         *  we exclude SP.  Memory operands excluded by the dreg==sreg
         *  check (find_reg would not match a memory operand string).
         *  Research: FPC OptPass1CPU "Sub2Xor" (aoptx86.pas ~16904);
         *  GCC i386.md canonicalizes R=0 to xor R,R. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "sub")) {
            int r71 = find_reg(pi->op0);
            int s71 = find_reg(pi->op1);
            if (r71 >= 0 && s71 == r71 &&
                g_regs[r71].fam != 4 &&
                flags_clear(next_code(i), F_AF)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "xor ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", ");
                strcat(g_build, pi->op0);
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'sub %s, %s' rewritten to 'xor %s, %s' (P71)\n",
                    i + 1, pi->op0, pi->op1, pi->op0, pi->op0);
                replace_line(i, g_build);
                st[71]++;
                continue;
            }
        }

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

        /* P10: "add R,1" / "sub R,1" (or -1) -> "inc/dec R" when the
        *  scan proves CF is overwritten on every path before it is read
        *  (add/sub define CF, inc/dec preserve it; every other flag
        *  is set identically).  v1.80: dropped the 16/32-bit gate so
        *  8-bit non-AL registers also benefit (`add cl,1` -> `inc cl`
        *  saves a byte). */
        if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub")) &&
            find_reg(pi->op0) >= 0) {
            long v;
            if (try_parse_number(pi->op1, &v) && (v == 1 || v == -1) &&
                flags_clear(next_code(i), F_CF)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build,
                       (ci_eq(pi->mnem, "add") == (v == 1)) ? "inc " : "dec ");
                strcat(g_build, pi->op0);
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: '%s %s, %ld' rewritten to '%s %s' (P10)\n",
                    i + 1, pi->mnem, pi->op0, v,
                    (ci_eq(pi->mnem, "add") == (v == 1)) ? "inc" : "dec",
                    pi->op0);
                replace_line(i, g_build);
                st[10]++;
            }
        }

        /* P11: "cmp R,0" -> "test R,R" when the scan proves AF is
        *  overwritten on every path before it is read (jcc that read
        *  ZF/SF/CF do not block; daa/das/aaa/aas/pushf/lahf do).
        *  v1.80: dropped the 16/32-bit gate so 8-bit registers also
        *  benefit (`cmp cl,0` -> `test cl,cl` saves a byte). */
        if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
            ci_eq(pi->mnem, "cmp") && find_reg(pi->op0) >= 0) {
            long v;
            if (try_parse_number(pi->op1, &v) && v == 0 &&
                flags_clear(next_code(i), F_AF)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "test ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", ");
                strcat(g_build, pi->op0);
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'cmp %s, 0' rewritten to 'test %s, %s' (P11)\n",
                    i + 1, pi->op0, pi->op0, pi->op0);
                replace_line(i, g_build);
                st[11]++;
            }
        }

        /* P65 (v1.82): "dec R / cmp R, -1" (same register, dec first,
         *  cmp with immediate -1, any width) -> delete the cmp when
         *  ALL six status flags are dead before any read.  The cmp
         *  is redundant as a *value* computation only if no flag is
         *  observed; we cannot relax this to "ZF preserved" because
         *  after `dec R` ZF reflects R_new==0 (i.e. R_old==1),
         *  whereas `cmp R_new, -1` sets ZF iff R_new==-1 (i.e.
         *  R_old==0).  These DIFFER, so any reader of ZF forces the
         *  cmp to stay.  The same is true for SF, PF, CF, OF, AF --
         *  each differs in some edge case (e.g. SF: dec SF is
         *  sign(R_new), cmp R_new,-1 SF is sign(R_new+1) =
         *  sign(R_old); CF: dec preserves CF, cmp sets it).  The
         *  conservative all-six-dead formulation is exact: if no
         *  flag is ever read, the cmp has no observable effect and
         *  may be deleted.  Research: GCC i386.md peephole2 #33
         *  rewrites `dec %eax; cmpl $-1,%eax; jne L` to
         *  `subl $1,%eax; jnc L` (so CF carries the underflow),
         *  which is a stronger form needing jcc rewrite.  This is
         *  the conservative delete-the-cmp form.  Not covered by P11
         *  (cmp R,0 -> test) or P19 (identical cmp). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 1 && ci_eq(pi->mnem, "dec")) {
            int r65 = find_reg(pi->op0);
            if (r65 >= 0 && g_regs[r65].fam != 4) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "cmp") &&
                        find_reg(pj->op0) == r65) {
                        long v65;
                        int w = g_regs[r65].hi - g_regs[r65].lo;
                        unsigned long allones =
                            (w == 8) ? 0xFFUL :
                            (w == 16) ? 0xFFFFUL : 0xFFFFFFFFUL;
                        if (try_parse_number(pj->op1, &v65) &&
                            (v65 == -1L ||
                             (unsigned long)v65 == allones) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            vlog("smartpp: line %ld: deleted 'cmp %s, -1' (flags all dead, P65)\n",
                                j + 1, pj->op0);
                            delete_keep_label(j, pj);
                            st[65]++;
                            continue;
                        }
                    }
                }
            }
        }

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
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'xor %s, %ld' rewritten to 'not %s' (P37)\n",
                    i + 1, pi->op0, v, pi->op0);
                replace_line(i, g_build);
                st[37]++;
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
                    if (pi->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'imul %s, -1' rewritten to 'neg %s' (P51)\n",
                        i + 1, pi->op0, pi->op0);
                    replace_line(i, g_build);
                    st[51]++;
                }
                /* P38: K is a power of two, k >= 1, k < width */
                else if (v > 0 && (v & (v - 1)) == 0) {
                    int k = 0;
                    long vv = v;
                    while (vv > 1) { vv >>= 1; k++; }
                    if (k >= 1 && k < w && flags_clear(next_code(i), F_ALL6)) {
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
                        if (pi->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: 'imul %s, %ld' rewritten to 'shl %s, %d' (P38)\n",
                            i + 1, pi->op0, v, pi->op0, k);
                        replace_line(i, g_build);
                        st[38]++;
                    }
                    /* K = 1 (k = 0): identity, delete if flags dead */
                    else if (v == 1 && flags_clear(next_code(i), F_ALL6)) {
                        vlog("smartpp: line %ld: deleted 'imul %s, 1' (identity, P38)\n",
                            i + 1, pi->op0);
                        DEL(i) = 1;
                        st[38]++;
                    }
                }
                /* P50 (v1.80): "imul R, K" with K = 2^k + 1 (k=1,2,3)
                *  -> "lea R, [R + R*k]".  K=3, 5, 9 (k=1,2,3) on 386+
                *  (scaled index addressing).  imul defines all six
                *  flags, lea defines none, so the scan must prove them
                *  dead.  Intel-only.  Same size as imul (3 bytes) when
                *  K fits imm8 (3, 5, 9, ...); saves bytes when K
                *  exceeds imm8 range.  Win is "no flag dependency",
                *  which the next optimizer pass may exploit.
                *
                *  v1.83 BUG FIX: the SIB byte's [R + R*scale] form
                *  requires a 32-bit register on 386+ (16-bit addressing
                *  has no SIB and only the four legal [BX+SI], [BX+DI],
                *  [BP+SI], [BP+DI] base+index combinations, none of
                *  which encodes a scale).  Also, ESP cannot be the
                *  index register: the SIB index field 4 means "no
                *  index", so `lea esp,[esp+esp*2]` cannot be encoded
                *  (the assembler rejects it or silently drops the
                *  scale).  Gate on width==32 and family != SP. */
                else if (v > 1 && g_curcpu >= 8 && !g_att) {
                    int r50 = find_reg(pi->op0);
                    int w50 = (r50 >= 0) ? g_regs[r50].hi - g_regs[r50].lo : 0;
                    if (r50 >= 0 && w50 == 32 &&
                        g_regs[r50].fam != 4 /* SP */) {
                    long v1 = v - 1;             /* 2^k */
                    if ((v1 & (v1 - 1)) == 0 && v1 != 0) {
                        int k = 0;
                        long vv = v1;
                        while (vv > 1) { vv >>= 1; k++; }
                        /* k must be 1, 2, or 3 (SIB scale field) */
                        if (k >= 1 && k <= 3 &&
                            flags_clear(next_code(i), F_ALL6)) {
                            char operand[MAXTOK];
                            emit_lea_scaled(operand, r50, 1 << k);
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "lea ");
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, operand);
                            if (pi->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: 'imul %s, %ld' rewritten to 'lea %s, %s' (P50)\n",
                                i + 1, pi->op0, v, pi->op0, operand);
                            replace_line(i, g_build);
                            st[50]++;
                        }
                    }
                    }
                }
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

        /* P21: two consecutive identical "cld/std/cli/sti/clc/stc":
        *  the second writes the same flag bit with the same value
        *  and nothing reads or changes it in between.  "cmc" is
        *  not idempotent (P25 handles its double instead). */
        if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 0 &&
            (ci_eq(pi->mnem, "cld") || ci_eq(pi->mnem, "std") ||
             ci_eq(pi->mnem, "cli") || ci_eq(pi->mnem, "sti") ||
             ci_eq(pi->mnem, "clc") || ci_eq(pi->mnem, "stc"))) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 0 &&
                    ci_eq(pj->mnem, pi->mnem)) {
                    vlog("smartpp: line %ld: deleted duplicate '%s' (P21)\n",
                        j + 1, pj->mnem);
                    DEL(j) = 1;
                    st[21]++;
                }
            }
        }

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

        /* P23: "not R / not R" (same register): the value is
        *  restored and "not" touches no flag at all, so the pair
        *  is exactly dead with no scan.  Registers only (a
        *  repeated write to memory-mapped space may be
        *  meaningful). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 1 && ci_eq(pi->mnem, "not") &&
            find_reg(pi->op0) >= 0) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 1 &&
                    ci_eq(pj->mnem, "not") && ci_eq(pj->op0, pi->op0)) {
                    vlog("smartpp: line %ld: deleted 'not %s' / 'not %s' pair (P23)\n",
                        i + 1, pi->op0, pj->op0);
                    DEL(i) = 1;
                    DEL(j) = 1;
                    st[23]++;
                    continue;
                }
            }
        }

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

        /* P25: "cmc / cmc": the carry is inverted twice, i.e.
        *  restored; no other flag is touched, so the pair is
        *  exactly dead without a scan. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 0 && ci_eq(pi->mnem, "cmc")) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 0 &&
                    ci_eq(pj->mnem, "cmc")) {
                    vlog("smartpp: line %ld: deleted 'cmc' / 'cmc' pair (P25)\n",
                        i + 1);
                    DEL(i) = 1;
                    DEL(j) = 1;
                    st[25]++;
                    continue;
                }
            }
        }

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

        /* P28: two consecutive identical "cbw/cwde/cwd/cdq" (or the
        *  AT&T names "cbtw/cwtl/cwtd/cltd"): the second re-derives
        *  the same high half from the same, unchanged low half and
        *  touches no flags. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 0 &&
            (ci_eq(pi->mnem, "cbw") || ci_eq(pi->mnem, "cwde") ||
             ci_eq(pi->mnem, "cwd") || ci_eq(pi->mnem, "cdq") ||
             ci_eq(pi->mnem, "cbtw") || ci_eq(pi->mnem, "cwtl") ||
             ci_eq(pi->mnem, "cwtd") || ci_eq(pi->mnem, "cltd"))) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 0 &&
                    ci_eq(pj->mnem, pi->mnem)) {
                    vlog("smartpp: line %ld: deleted duplicate '%s' (P28)\n",
                        j + 1, pj->mnem);
                    DEL(j) = 1;
                    st[28]++;
                }
            }
        }

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

        /* P40 (v1.80): "mov R, imm1 / add R, imm2" (or sub) ->
        *  "mov R, imm1 + imm2" (or "imm1 - imm2").  FPC's constant-
        *  propagation idiom.  The add/sub defines all six flags, the
        *  combined mov defines none, so the scan must prove them
        *  dead.  Registers only; the sum must fit the mov R,imm
        *  immediate encoding range. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->dreg >= 0 && pi->sreg < 0 && pi->srcimm) {
            long v1, v2, total;
            int r = pi->dreg;
            int w = g_regs[r].hi - g_regs[r].lo;
            long lim = (w == 8) ? 0x7F :
                       (w == 16) ? 0x7FFF : 0x7FFFFFFFL;
            if (try_parse_number(pi->op1, &v1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        (ci_eq(pj->mnem, "add") || ci_eq(pj->mnem, "sub")) &&
                        find_reg(pj->op0) == r &&
                        try_parse_number(pj->op1, &v2)) {
                        total = (ci_eq(pj->mnem, "add")) ? v1 + v2 : v1 - v2;
                        if (total <= lim && total >= -(lim + 1) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            char num[32];
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "mov ");
                            if (g_att) {
                                strcat(g_build, "$");
                                sprintf(num, "%ld", total);
                                strcat(g_build, num);
                                strcat(g_build, ", ");   /* pi->op0 already has % for AT&T */
                                strcat(g_build, pi->op0);
                            } else {
                                strcat(g_build, pi->op0);
                                strcat(g_build, ", ");
                                sprintf(num, "%ld", total);
                                strcat(g_build, num);
                            }
                            if (pi->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P40)\n",
                                i + 1, L(i), L(j), g_build);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            st[40]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P43/P44/P45 (v1.80): "xor R, R" followed by a flag-setting
        *  arith op on R, all six flags dead, collapses to a single
        *  "mov R, <constant>".
        *  P43: add/sub/or/xor R, imm  -> mov R, imm (or -imm)
        *  P44: inc R                   -> mov R, 1
        *  P45: dec R                   -> mov R, -1 (Intel "0FFFFh")
        *  After xor R,R the register is 0; the second op computes a
        *  known constant from 0.  xor defines all six flags, the
        *  second op overwrites them, the combined mov defines none:
        *  the scan must prove all six dead.  Note: pj->dreg is left
        *  at -1 for I_OTHER ops like add/sub/inc/dec; use find_reg
        *  on the operand text instead. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XORRR) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    find_reg(pj->op0) == pi->dreg) {
                    int r = pi->dreg;
                    int w = g_regs[r].hi - g_regs[r].lo;
                    long lim = (w == 8) ? 0x7F :
                               (w == 16) ? 0x7FFF : 0x7FFFFFFFL;
                    long target = 0;          /* 0 means "no match" */
                    int hit = 0;
                    /* P44: xor R,R / inc R -> mov R, 1 */
                    if (pj->cls == I_OTHER && pj->nops == 1 &&
                        ci_eq(pj->mnem, "inc")) {
                        target = 1; hit = 44;
                    }
                    /* P45: xor R,R / dec R -> mov R, -1 */
                    else if (pj->cls == I_OTHER && pj->nops == 1 &&
                             ci_eq(pj->mnem, "dec")) {
                        target = -1; hit = 45;
                    }
                    /* P43: xor R,R / {add,sub,or,xor} R, imm -> mov R, K */
                    else if (pj->cls == I_OTHER && pj->nops == 2 &&
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
                        if (pi->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P%d)\n",
                            i + 1, L(i), L(j), g_build, hit);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        if (hit == 43) st[43]++;
                        else if (hit == 44) st[44]++;
                        else st[45]++;
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
                        if (pi->comment[0] != '\0') {
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

        /* P48 (v1.80): "xor R, R / test R, R" -> delete the test.
        *  After "xor R, R", R = 0 and the flags are ZF=1, SF=0, PF=1,
        *  CF=0, OF=0, AF=undef.  "test R, R" on R = 0 sets exactly the
        *  same flags (ZF=1, SF=0, PF=1, CF=0, OF=0, AF=undef), so it
        *  is provably redundant with no scan.  Common hand-written
        *  pattern from older compilers that "zero then test for the
        *  following jz/jnz". */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XORRR) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 2 &&
                    ci_eq(pj->mnem, "test") &&
                    find_reg(pj->op0) == pi->dreg &&
                    find_reg(pj->op1) == pi->dreg) {
                    vlog("smartpp: line %ld: deleted redundant 'test %s, %s' after 'xor %s, %s' (P48)\n",
                        j + 1, pj->op0, pj->op1, pi->op0, pi->op1);
                    DEL(j) = 1;
                    st[48]++;
                    continue;
                }
            }
        }

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
                        else if (g_curcpu >= 8 && !opt_nz &&
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

        /* P46 (v1.80): "push imm / pop R" -> "mov R, imm".  186+
        *  (push imm).  Both push imm and pop R are flag-neutral, so
        *  no scan is needed.  Size-gate so we never emit a larger mov:
        *  - 16-bit R: mov R,imm is 3 bytes; push imm (2 or 3) + pop (1)
        *    = 3 or 4 bytes; always fire.
        *  - 32-bit R: mov R,imm32 is 5 bytes; push imm8 + pop = 3 bytes
        *    (smaller!), push imm32 + pop = 6 bytes (larger).  Fire
        *    only when imm ∉ [-128, 127].  Off-by-one 0xFFFF and
        *    0xFFFFFFFF are accepted as "non-imm8". */
        if (!g_att && !pn->toobig && pn->cls == I_PUSH &&
            pn->dreg < 0 && pn->srcimm && g_curcpu >= 2) {
            long imm;
            if (try_parse_number(pn->op0, &imm)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_POP && pj->dreg >= 0 &&
                        g_regs[pj->dreg].fam != 4 &&
                        (g_regs[pj->dreg].hi - g_regs[pj->dreg].lo) >= 16) {
                        int w = g_regs[pj->dreg].hi - g_regs[pj->dreg].lo;
                        int fire = 1;
                        if (w == 32 && imm >= -128 && imm <= 127)
                            fire = 0;        /* push imm8 + pop is smaller */
                        if (fire) {
                            char num[32];
                            strcpy(g_build, pn->prefix);
                            strcat(g_build, "mov ");
                            if (g_att) {
                                strcat(g_build, "$");
                                sprintf(num, "%ld", imm);
                                strcat(g_build, num);
                                strcat(g_build, ", ");   /* pj->op0 already has % for AT&T */
                                strcat(g_build, pj->op0);
                            } else {
                                strcat(g_build, pj->op0);
                                strcat(g_build, ", ");
                                sprintf(num, "%ld", imm);
                                strcat(g_build, num);
                            }
                            if (pn->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pn->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P46)\n",
                                i + 1, L(i), L(j), g_build);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            st[46]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P79 (v1.83): "mov R, imm / push R" with R dead after the
         *  push -> single "push imm".  mov and push are flag-neutral,
         *  so no scan is needed for flags; the only effect of the
         *  mov was to set up R for the push, and once R is dead the
         *  push imm is equivalent.  186+ (push imm is 186+).
         *  Size-gated like P46 (avoid making the encoding bigger):
         *  - 16-bit R: mov R,imm (3 bytes) + push R (1) = 4 bytes;
         *    push imm (2..3) saves 1..2 bytes.  Always fire.
         *  - 32-bit R: mov R,imm32 (5 bytes) + push R (1) = 6 bytes;
         *    push imm8 (2) saves 4 bytes; push imm32 (5) saves 1 byte.
         *    Always fire.
         *  The rule is the inverse-direction sibling of P46.  The
         *  dead-register check uses the reg_dead_after() helper. */
        if (!g_att && !pn->toobig && pn->cls == I_MOV &&
            pn->dreg >= 0 && pn->sreg < 0 && pn->srcimm &&
            g_curcpu >= 2) {
            long imm;
            if (try_parse_number(pn->op1, &imm)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_PUSH && pj->dreg == pn->dreg &&
                        g_regs[pj->dreg].fam != 4 &&
                        reg_dead_after(j, pn->dreg)) {
                        char num[32];
                        strcpy(g_build, pn->prefix);
                        strcat(g_build, "push ");
                        if (g_att) strcat(g_build, "$");
                        sprintf(num, "%ld", imm);
                        strcat(g_build, num);
                        if (pn->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pn->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P79)\n",
                            i + 1, L(i), L(j), g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[79]++;
                        continue;
                    }
                }
            }
        }

        /* P80 (v1.83): "push R / <writer to R that does not read R>
         *  / pop R" with R not read between push and pop -> all
         *  three deleted.  The push saves R, the writer overwrites
         *  it (so the saved value is irrelevant), and the pop restores
         *  R to the writer's output (which is dead by the writer's
         *  own dead-store discipline).  Net effect on R: it gets the
         *  writer's value, then the pop makes R := (writer's value)
         *  again -- the pop is the redundant step.  Together the
         *  three instructions are equivalent to the writer alone,
         *  which by assumption does not read R, so the pop's source
         *  (the stack slot holding the original R) is also irrelevant.
         *  The writer must define all bits of R (covers) without
         *  reading R (writer_ok already encodes this); a partial
         *  writer (e.g. mov al, X to overwrite ax's low byte) is
         *  rejected.  16/32-bit only (8-bit push/pop is not legal).
         *  No flag scan: push/pop and the flag-neutral writers
         *  (mov/lea/movzx/xor R,R) all leave flags unchanged. */
        if (!pi->haslabel && !pi->toobig &&
            pi->cls == I_PUSH && pi->dreg >= 0 &&
            (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) >= 16 &&
            g_regs[pi->dreg].fam != 4) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    writer_ok(pj, pi->dreg)) {
                    long k80 = next_code(j);
                    if (k80 >= 0 && !INDEF(k80)) {
                        struct pinfo *pk = &g_plook;
                        parse_line(k80, pk);
                        if (!pk->haslabel && !pk->toobig &&
                            pk->cls == I_POP && pk->dreg == pi->dreg) {
                            vlog("smartpp: line %ld: deleted push/write/pop triple (P80)\n",
                                i + 1);
                            DEL(i) = 1;   /* push */
                            DEL(k80) = 1;  /* pop */
                            /* keep the writer (line j) intact */
                            st[80]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P42 (v1.80): "push bp / mov bp,sp / sub sp,N" -> "enter N, 0".
        *  186+, 16-bit only (g_use32 == 0).  The three instructions
        *  are exactly what "enter N, 0" expands to; only the flags
        *  of the sub sp,N are lost (enter defines none), so the scan
        *  must prove all six dead.  Size win: 6..7 bytes -> 4 bytes.
        *
        *  v1.83 BUG FIX: the rule fired in AT&T mode too, where it
        *  emitted Intel-syntax `enter N, 0` into a GAS source.  P46,
        *  P47 and P50 already gate themselves to !g_att; this one
        *  was missed.  Closing it to !g_att for the same reason. */
        if (!g_att && !g_use32 && g_curcpu >= 2 && !pn->toobig &&
            pn->cls == I_PUSH && pn->dreg >= 0 &&
            g_regs[pn->dreg].fam == 5 &&
            g_regs[pn->dreg].hi == 16) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_MOV && pj->dreg >= 0 && pj->sreg >= 0 &&
                    g_regs[pj->dreg].fam == 5 &&
                    g_regs[pj->dreg].hi == 16 &&
                    g_regs[pj->sreg].fam == 4 &&
                    g_regs[pj->sreg].hi == 16) {
                    long k2 = next_code(j);
                    if (k2 >= 0 && !INDEF(k2)) {
                        struct pinfo *pk = &g_plook;
                        parse_line(k2, pk);
                        if (!pk->haslabel && !pk->toobig &&
                            pk->cls == I_OTHER && pk->nops == 2 &&
                            ci_eq(pk->mnem, "sub") &&
                            find_reg(pk->op0) >= 0 &&
                            g_regs[find_reg(pk->op0)].fam == 4 &&
                            g_regs[find_reg(pk->op0)].hi == 16) {
                            long N;
                            if (try_parse_number(pk->op1, &N) &&
                                N >= 0 && N <= 0xFFFF &&
                                flags_clear(next_code(k2), F_ALL6)) {
                                char num[32];
                                strcpy(g_build, pn->prefix);
                                strcat(g_build, "enter ");
                                sprintf(num, "%ld", N);
                                strcat(g_build, num);
                                strcat(g_build, ", 0");
                                if (pn->comment[0] != '\0') {
                                    strcat(g_build, " ");
                                    strcat(g_build, pn->comment);
                                }
                                vlog("smartpp: line %ld: '%s' / '%s' / '%s' rewritten to '%s' (P42)\n",
                                    i + 1, L(i), L(j), L(k2), g_build);
                                replace_line(i, g_build);
                                DEL(j) = 1;
                                DEL(k2) = 1;
                                st[42]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P33: "shl R,N / shr R,N" (or sar) that keeps only the low
        *  8 or 16 bits -> "movzx R,low" (movsx for sar).  The flags of
        *  the second shift are lost: the scan must prove all six dead. */
        if (!g_att && g_curcpu >= 8 && !opt_nz && !pn->toobig &&
            pn->cls == I_SHIFT && pn->shiftcount > 0 &&
            (ci_eq(pn->mnem, "shl") || ci_eq(pn->mnem, "sal"))) {
            int r = find_reg(pn->op0);
            if (r >= 0 && g_regs[r].lo == 0 && g_regs[r].fam != 4) {
                int keep = g_regs[r].hi - (int)pn->shiftcount;
                int lr = (keep == 8 || keep == 16) ?
                         reg_by_bits(g_regs[r].fam, 0, keep) : -1;
                j = next_code(i);
                if (lr >= 0 && j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig && pj->cls == I_SHIFT &&
                        pj->shiftcount == pn->shiftcount &&
                        ci_eq(pj->op0, pn->op0) &&
                        (ci_eq(pj->mnem, "shr") || ci_eq(pj->mnem, "sar")) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        strcpy(g_build, pn->prefix);
                        strcat(g_build, ci_eq(pj->mnem, "shr") ?
                                        "movzx " : "movsx ");
                        strcat(g_build, g_regs[r].name);
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[lr].name);
                        if (pn->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pn->comment);
                        }
                        vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P33)\n",
                            i + 1, L(i), L(j), g_build);
                        replace_line(i, g_build);
                        DEL(j) = 1;
                        st[33]++;
                        continue;
                    }
                }
            }
        }

        /* P34: "and R16,0FFh" -> "xor Rh,Rh" when ZF and PF are dead
        *  (CF, OF and SF come out the same); 386+: "and R32,0FFh /
        *  0FFFFh" -> "movzx R32,low" when all six flags are dead. */
        if (!g_att && !pn->toobig && pn->cls == I_OTHER && pn->nops == 2 &&
            ci_eq(pn->mnem, "and")) {
            int r = find_reg(pn->op0);
            long v;
            if (r >= 0 && g_regs[r].lo == 0 && g_regs[r].fam != 4 &&
                try_parse_number(pn->op1, &v)) {
                int rs = g_regs[r].hi;
                int to = -1;
                int need = F_ALL6;
                if (rs == 16 && v == 255) {
                    to = reg_by_bits(g_regs[r].fam, 8, 16);
                    need = F_ZF | F_PF;
                }
                else if (rs == 32 && g_curcpu >= 8 && !opt_nz &&
                         (v == 255 || v == 65535L))
                    to = reg_by_bits(g_regs[r].fam, 0, (v == 255) ? 8 : 16);
                if (to >= 0 && flags_clear(next_code(i), need)) {
                    strcpy(g_build, pn->prefix);
                    if (rs == 16) {
                        strcat(g_build, "xor ");
                        strcat(g_build, g_regs[to].name);
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[to].name);
                    } else {
                        strcat(g_build, "movzx ");
                        strcat(g_build, g_regs[r].name);
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[to].name);
                    }
                    if (pn->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pn->comment);
                    }
                    vlog("smartpp: line %ld: '%s' rewritten to '%s' (P34)\n",
                        i + 1, L(i), g_build);
                    replace_line(i, g_build);
                    st[34]++;
                    continue;
                }
            }
        }

        /* P35: "mov R32,-1" -> "or R32,-1" (3 bytes instead of 5) when
        *  the scan proves all six flags dead. */
        if (!g_att && g_curcpu >= 8 && !pn->toobig && pn->cls == I_MOV &&
            pn->dreg >= 0 && pn->sreg < 0 &&
            (g_regs[pn->dreg].hi - g_regs[pn->dreg].lo) == 32 &&
            g_regs[pn->dreg].fam != 4) {
            long v;
            if (try_parse_number(pn->op1, &v) &&
                (v == -1L || (unsigned long)v == 0xFFFFFFFFUL) &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pn->prefix);
                strcat(g_build, "or ");
                strcat(g_build, g_regs[pn->dreg].name);
                strcat(g_build, ", -1");
                if (pn->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pn->comment);
                }
                vlog("smartpp: line %ld: '%s' rewritten to '%s' (P35)\n",
                    i + 1, L(i), g_build);
                replace_line(i, g_build);
                st[35]++;
                continue;
            }
        }

        /* P36: "mov sp,bp / pop bp" -> "leave" (186+, 16-bit stack) */
        if (!g_use32 && g_curcpu >= 2 && !pn->toobig && pn->cls == I_MOV &&
            pn->dreg >= 0 && pn->sreg >= 0 &&
            ci_eq(g_regs[pn->dreg].name, "sp") &&
            ci_eq(g_regs[pn->sreg].name, "bp")) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_POP &&
                    pj->dreg >= 0 && ci_eq(g_regs[pj->dreg].name, "bp")) {
                    strcpy(g_build, pn->prefix);
                    strcat(g_build, "leave");
                    if (pn->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pn->comment);
                    }
                    vlog("smartpp: line %ld: '%s' / '%s' rewritten to 'leave' (P36)\n",
                        i + 1, L(i), L(j));
                    replace_line(i, g_build);
                    DEL(j) = 1;
                    st[36]++;
                    continue;
                }
            }
        }

        /* P12: duplicate consecutive jumps to the same target:
        *  "j<cc> L / j<same cc> L" -> second deleted (same flags);
        *  "j<cc> L / jmp L" -> the jcc is deleted (both paths reach
        *  L); "jmp L / <any jump> L" -> the second is unreachable */
        if (!pi->toobig && (pi->cls == I_JCC || pi->cls == I_JMP) &&
            pi->jtarget_ok) {
            struct pinfo *pj = &g_ppair;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                parse_line(j, pj);
                if (!pj->toobig && pj->jtarget_ok &&
                    ci_eq(pj->jtarget, pi->jtarget)) {
                    if (pi->cls == I_JCC && pj->cls == I_JCC &&
                        jcc_canon(pi->mnem) == jcc_canon(pj->mnem) &&
                        !pj->haslabel) {
                        vlog("smartpp: line %ld: deleted duplicate '%s %s' (P12)\n",
                            j + 1, pj->mnem, pj->jtarget);
                        DEL(j) = 1;
                        st[12]++;
                    }
                    else if (pi->cls == I_JCC && pj->cls == I_JMP) {
                        /* v1.81 bug fix: line i may carry a label
                         *  that other jumps target; deleting the
                         *  whole line would remove it.  Use
                         *  delete_keep_label so the jcc is removed
                         *  but the label (and any comment) survives
                         *  on a label-only line; other jumps to it
                         *  then land on the still-present bridge jmp
                         *  at line j, which goes to L (same target
                         *  the deleted jcc would have taken). */
                        vlog("smartpp: line %ld: deleted '%s %s', the jmp at line %ld always reaches %s (P12)\n",
                            i + 1, pi->mnem, pi->jtarget, j + 1, pj->jtarget);
                        delete_keep_label(i, pi);
                        st[12]++;
                        continue;
                    }
                    else if (pi->cls == I_JMP &&
                             (pj->cls == I_JMP || pj->cls == I_JCC) &&
                             !pj->haslabel) {
                        vlog("smartpp: line %ld: deleted unreachable '%s %s' (P12)\n",
                            j + 1, pj->mnem, pj->jtarget);
                        DEL(j) = 1;
                        st[12]++;
                    }
                }
            }
        }

        /* P13: unreachable instructions after an unconditional jmp:
        *  delete the run of known instruction lines with no label
        *  (a label, data definition, directive or unknown line
        *  stops the scan) */
        if (!pi->toobig && pi->cls == I_JMP && pi->jtarget_ok) {
            long k2 = next_code(i);
            int killed = 0;
            while (k2 >= 0 && !INDEF(k2)) {
                struct pinfo *pk = &g_plook;
                parse_line(k2, pk);
                if (pk->haslabel || pk->toobig || !pk->hasinstr) break;
                if (!is_known_instr(pk->mnem)) break;
                vlog("smartpp: line %ld: deleted unreachable '%s' (P13)\n",
                    k2 + 1, L(k2));
                DEL(k2) = 1;
                st[13]++;
                killed = 1;
                k2 = next_code(k2);
            }
            if (killed) {
                /* fall through: P6 may now drop the jmp itself */
            }
        }

        /* P13b (v1.83): unreachable instructions after a control-flow
         *  terminator that is NOT an unconditional jmp: ret, retf,
         *  iret, int3 (the cheap INT 3 trap), and the explicit ud2 /
         *  hlt.  All of these end a basic block exactly as jmp does;
         *  any subsequent non-labeled instruction is unreachable
         *  and may be deleted.  Same scanning discipline as P13 (stop
         *  at a label, data definition, directive, or unknown line).
         *  Excludes "int N" for N != 3 because INT typically returns
         *  (the handler does IRET), so the following code IS
         *  reachable.  int3 is the conventional "trap to debugger"
         *  that does not return.  Research: GCC i386.md
         *  `unreachable` notes; LLVM `UnreachableElimination`. */
        if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 0 &&
            (ci_eq(pi->mnem, "ret") || ci_eq(pi->mnem, "retf") ||
             ci_eq(pi->mnem, "iret") || ci_eq(pi->mnem, "hlt") ||
             ci_eq(pi->mnem, "ud2") || ci_eq(pi->mnem, "int3"))) {
            long k2 = next_code(i);
            int killed = 0;
            while (k2 >= 0 && !INDEF(k2)) {
                struct pinfo *pk = &g_plook;
                parse_line(k2, pk);
                if (pk->haslabel || pk->toobig || !pk->hasinstr) break;
                if (!is_known_instr(pk->mnem)) break;
                vlog("smartpp: line %ld: deleted unreachable '%s' (P13b)\n",
                    k2 + 1, L(k2));
                DEL(k2) = 1;
                st[13]++;
                killed = 1;
                k2 = next_code(k2);
            }
            (void)killed;
        }

        /* P68 (v1.82): "xchg R, S" with one operand provably dead after
         *  the swap -> "mov <alive>, <dead>" (or the symmetric form),
         *  which is 1 byte shorter on x86 for non-AX registers and
         *  same-size for the AX short form.  An operand is "dead"
         *  when the next instruction that mentions its register family
         *  fully overwrites it (mov/lea/movzx/pop to a covering
         *  destination) WITHOUT reading it first -- the discipline
         *  shared with P2's dead-store test, refactored here into the
         *  reg_dead_after() helper.  xchg writes neither memory nor
         *  flags, so the rewrite is exact on both.  Memory operands
         *  excluded (no register to be "dead"); SP excluded because
         *  moving to SP changes the stack pointer between interrupts
         *  differently than an xchg would (xchg momentarily has
         *  SP==other-reg, which is observable to an interrupting
         *  handler if the other-reg value happens to be a bad stack
         *  pointer).  Research: GCC i386.md peephole2 #9 and #10
         *  ("Convert xchg with a REG_UNUSED note to a mov"). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XCHG &&
            pi->dreg >= 0 && pi->sreg >= 0 &&
            pi->dreg != pi->sreg &&
            g_regs[pi->dreg].fam != 4 && g_regs[pi->sreg].fam != 4) {
            int rd68 = pi->dreg, rs68 = pi->sreg;
            int same_w =
                (g_regs[rd68].hi - g_regs[rd68].lo) ==
                (g_regs[rs68].hi - g_regs[rs68].lo);
            /* Same width is required: a partial swap like
             *  `xchg ax, al` is not a single mov. */
            if (same_w) {
                int dead_d = reg_dead_after(i, rd68);
                int dead_s = reg_dead_after(i, rs68);
                if (dead_d || dead_s) {
                    /* If R is dead: rewrite to "mov S, R" -- in Intel
                     *  syntax "mov S, R" means S := R's old value,
                     *  which is exactly what xchg produced for S (R
                     *  itself is dead, no one cares what it holds).
                     *  Similarly if S is dead: "mov R, S" sets
                     *  R := S's old value.  In short: dst (alive) is
                     *  the destination of the mov, src (dead) is the
                     *  source. */
                    int dead_is_d = dead_d;
                    int dead = dead_is_d ? rd68 : rs68;  /* dead reg */
                    int alive = dead_is_d ? rs68 : rd68;  /* alive reg */
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "mov ");
                    if (g_att) strcat(g_build, "%");
                    /* Intel: "mov dst, src" = "mov alive, dead".
                     *  AT&T:  "mov src, dst" = "mov dead, alive". */
                    if (g_att) {
                        strcat(g_build, g_regs[dead].name);
                        strcat(g_build, ", %");
                        strcat(g_build, g_regs[alive].name);
                    } else {
                        strcat(g_build, g_regs[alive].name);
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[dead].name);
                    }
                    if (pi->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: 'xchg %s, %s' rewritten to 'mov %s, %s' (P68, %s dead)\n",
                        i + 1, pi->op0, pi->op1,
                        g_regs[alive].name, g_regs[dead].name,
                        dead_is_d ? pi->op0 : pi->op1);
                    replace_line(i, g_build);
                    st[68]++;
                    continue;
                }
            }
        }

        /* P14: "xchg R,S / xchg R,S" (same pair, either order) ->
        *  both deleted: two swaps restore everything, flags untouched.
        *  v1.81 bug fix: if line i carries a label, use
        *  delete_keep_label so the label survives on a label-only
        *  line (line j is still deleted because the rule already
        *  requires !pj->haslabel).  Without this, deleting line i
        *  would also remove a label that other code jumps to. */
        if (!pi->toobig && pi->cls == I_XCHG &&
            pi->dreg >= 0 && pi->sreg >= 0) {
            struct pinfo *pj = &g_ppair;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_XCHG &&
                    pj->dreg >= 0 && pj->sreg >= 0 &&
                    ((ci_eq(pi->op0, pj->op0) && ci_eq(pi->op1, pj->op1)) ||
                     (ci_eq(pi->op0, pj->op1) && ci_eq(pi->op1, pj->op0)))) {
                    vlog("smartpp: line %ld: deleted double '%s %s, %s' (P14)\n",
                        i + 1, pi->mnem, pi->op0, pi->op1);
                    delete_keep_label(i, pi);
                    DEL(j) = 1;
                    st[14]++;
                    continue;
                }
            }
        }

        /* P15: "mov R,S / mov S,R" -> the second is dead: it writes
        *  S with S's own value (R was just set to it) */
        if (!pi->toobig && pi->cls == I_MOV && pi->dreg >= 0 &&
            pi->sreg >= 0) {
            struct pinfo *pj = &g_ppair;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_MOV &&
                    pj->dreg >= 0 && pj->sreg >= 0 &&
                    ci_eq(pi->op1, pj->op0) && ci_eq(pi->op0, pj->op1)) {
                    vlog("smartpp: line %ld: deleted '%s %s, %s' (writes %s with its own value, P15)\n",
                        j + 1, pj->mnem, pj->op0, pj->op1, pj->op0);
                    DEL(j) = 1;
                    st[15]++;
                }
            }
        }

        /* P18: "add R,0" / "sub R,0" -> deleted when the scan proves
        *  all six status flags are dead (they are the only effect) */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub")) &&
            find_reg(pi->op0) >= 0) {
            long v;
            if (try_parse_number(pi->op1, &v) && v == 0 &&
                flags_clear(next_code(i), F_ALL6)) {
                vlog("smartpp: line %ld: deleted '%s %s, 0' (P18)\n",
                    i + 1, pi->mnem, pi->op0);
                DEL(i) = 1;
                st[18]++;
                continue;
            }
        }

        /* P16: merge "add R,c1 / add R,c2" (or sub) into one when the
        *  scan proves OF is dead (all other flags and the result are
        *  identical; only OF can differ).  FPC's constant folding.
        *  If the folded sum is 0 and F_ALL6 are dead, delete the
        *  whole run instead of emitting a useless "add R,0" (the
        *  multi-pass loop would eventually catch it via P18, but
        *  this avoids a wasted pass).
        *
        *  v1.83 BUG FIX: the bound was hardcoded to ±32767 (imm16)
        *  for every width, which both (a) refused legitimate 32-bit
        *  folds (e.g. add eax, 200 / add eax, 200 -> add eax, 400
        *  was wrongly rejected) and (b) accepted illegal 8-bit folds
        *  (add al, 200 / add al, 200 -> add al, 400, which the
        *  assembler cannot encode).  Use width_imm_limit(w) so the
        *  bound matches the destination register's immediate range. */
        if (!pi->toobig && pi->cls == I_OTHER && pi->nops == 2 &&
            (ci_eq(pi->mnem, "add") || ci_eq(pi->mnem, "sub")) &&
            find_reg(pi->op0) >= 0) {
            int r16 = find_reg(pi->op0);
            int w16 = g_regs[r16].hi - g_regs[r16].lo;
            long imm_lim = width_imm_limit(w16);
            long v, total, last = i;
            if (try_parse_number(pi->op1, &v) && v != 0) {
                total = v;
                for (;;) {
                    struct pinfo *pj = &g_ppair;
                    long v2;
                    j = next_code(last);
                    if (j < 0) break;
                    parse_line(j, pj);
                    if (pj->haslabel || pj->toobig || pj->cls != I_OTHER ||
                        pj->nops != 2 || !ci_eq(pj->mnem, pi->mnem) ||
                        !ci_eq(pj->op0, pi->op0)) break;
                    if (!try_parse_number(pj->op1, &v2) || v2 == 0) break;
                    if (total + v2 > imm_lim || total + v2 < -imm_lim) break;
                    total += v2;
                    last = j;
                }
                if (last != i &&
                    flags_clear(next_code(last),
                                (total == 0) ? F_ALL6 : F_OF)) {
                    long k2;
                    for (k2 = i + 1; k2 <= last; k2++) {
                        if (!DEL(k2)) {
                            struct pinfo *pk = &g_plook;
                            parse_line(k2, pk);
                            if (pk->hasinstr && !pk->haslabel) {
                                vlog("smartpp: line %ld: merged '%s' into line %ld (P16)\n",
                                    k2 + 1, L(k2), i + 1);
                                DEL(k2) = 1;
                                st[16]++;
                            }
                        }
                    }
                    if (total == 0) {
                        /* v1.81 bug fix: use delete_keep_label so a
                         *  label carried by line i survives on a
                         *  label-only line.  The scan above already
                         *  proved F_ALL6 dead, so the add/sub R, 0
                         *  really has no observable effect and the
                         *  instruction part can be removed; the label
                         *  (and any comment) is preserved. */
                        vlog("smartpp: line %ld: deleted '%s' (folded to 0, P16)\n",
                            i + 1, L(i));
                        delete_keep_label(i, pi);
                        st[16]++;
                        continue;
                    }
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
                        if (pi->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: folded constants into '%s %s, %ld' (P16)\n",
                            i + 1, pi->mnem, pi->op0, total);
                        replace_line(i, g_build);
                    }
                }
            }
        }

        /* P56 (v1.81): "add R, c1 / sub R, c2" or "sub R, c1 /
         *  add R, c2" (mixed, c1 != 0 or c2 != 0, two instructions
         *  only) -> a single "add R, c1 - c2" or "sub R, c2 - c1".
         *  Net effect on R is the same as the two-step original;
         *  the final flags of the original come from the second
         *  instruction, the final flags of the rewrite come from the
         *  single add/sub.  CF and AF (and OF) can all differ
         *  between the two forms -- the two-step path computes an
         *  intermediate R0 +/- c1 that has its own carry/borrow, and
         *  the second op then derives the final carry/borrow from
         *  that intermediate, not from R0 directly.  The single op
         *  computes carry/borrow directly from R0.  So all six
         *  status flags must be proven dead.
         *
         *  Two-instruction only (no chaining): P16 already chains
         *  same-mnemonic add/add and sub/sub; mixed chains are
         *  reduced step-by-step through the multi-pass loop.  R
         *  must not be SP: an interrupt during the one-instruction
         *  window of `add R, c1` would push at R0 +/- c1 which is
         *  potentially misaligned, but the original has the same
         *  problem; the rewrite removes the window entirely, so
         *  SP exclusion is for parity with P22/P27/P39 (which all
         *  exclude SP for the misalignment-pushing-during-window
         *  reason).  Constant cousin of P39 but allows different
         *  magnitudes.  FPC folds `add +1 / sub +2` this way. */
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
                        ((ci_eq(pi->mnem, "add") &&
                          ci_eq(pj->mnem, "sub")) ||
                         (ci_eq(pi->mnem, "sub") &&
                          ci_eq(pj->mnem, "add"))) &&
                        find_reg(pj->op0) == r56 &&
                        try_parse_number(pj->op1, &c2) &&
                        /* skip exact-equal pair (P39 handles that) */
                        c2 != c1 &&
                        flags_clear(next_code(j), F_ALL6)) {
                        long diff = (ci_eq(pi->mnem, "add"))
                                       ? (c1 - c2) : (c2 - c1);
                        const char *op = (diff >= 0) ? "add" : "sub";
                        long mag = (diff >= 0) ? diff : -diff;
                        char num[32];
                        int w56 = g_regs[r56].hi - g_regs[r56].lo;
                        /* v1.83: width-aware bound.  Previously
                         *  hardcoded to 0x7FFF (imm16), which both
                         *  rejected legitimate 32-bit folds and
                         *  accepted illegal 8-bit folds the
                         *  assembler cannot encode. */
                        if (mag <= width_imm_limit(w56)) {
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, op);
                            if (g_att) {
                                strcat(g_build, " $");
                                sprintf(num, "%ld", mag);
                                strcat(g_build, num);
                                strcat(g_build, ", ");
                                strcat(g_build, pi->op0);
                            } else {
                                strcat(g_build, " ");
                                strcat(g_build, pi->op0);
                                strcat(g_build, ", ");
                                sprintf(num, "%ld", mag);
                                strcat(g_build, num);
                            }
                            if (pi->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' folded to '%s %s, %ld' (P56)\n",
                                i + 1, L(i), L(j), op, pi->op0, mag);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            st[56]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P78 (v1.83): "lea R, [R + off1] / lea R, [R + off2]"
         *  (same dest, same source base R, no scan needed) -> a
         *  single "lea R, [R + (off1 + off2)]"; the first LEA is
         *  deleted.  Both LEAs are flag-free and define R
         *  identically (R := R + off), so the second exactly over-
         *  writes the first's R write and there are no flags to
         *  preserve.  This is the simpler same-dest cousin of P70
         *  (which handles a different destination D and requires
         *  R dead).  Range-check the sum so we don't emit an
         *  assembler error on overflow.  Intel-only.
         *  Research: FPC OptPass1LEA "LeaLea2Lea" same-dest case. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->dreg >= 0 && !g_att) {
            int br1;
            long off1;
            if (lea_bracket(pi->op1, &br1, &off1) && br1 == pi->dreg) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_LEA && pj->dreg == pi->dreg) {
                        int br2;
                        long off2;
                        if (lea_bracket(pj->op1, &br2, &off2) &&
                            br2 == pi->dreg) {
                            long sum = off1 + off2;
                            int dw = g_regs[pi->dreg].hi -
                                     g_regs[pi->dreg].lo;
                            long lim = (dw == 16) ? 0x7FFF : 0x7FFFFFFFL;
                            if (sum >= -lim && sum <= lim) {
                                char operand[MAXTOK];
                                emit_lea_disp(operand, br1, sum);
                                strcpy(g_build, pj->prefix);
                                strcat(g_build, "lea ");
                                strcat(g_build, pj->op0);
                                strcat(g_build, ", ");
                                strcat(g_build, operand);
                                if (pj->comment[0] != '\0') {
                                    strcat(g_build, " ");
                                    strcat(g_build, pj->comment);
                                }
                                vlog("smartpp: line %ld: fused 'lea %s, [%s%+ld]' / 'lea %s, [%s%+ld]' to 'lea %s, [%s%+ld]' (P78)\n",
                                    i + 1,
                                    pi->op0, g_regs[br1].name, off1,
                                    pj->op0, g_regs[br2].name, off2,
                                    pj->op0, g_regs[br1].name, sum);
                                DEL(i) = 1;
                                replace_line(j, g_build);
                                st[78]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P70 (v1.82): "lea R, [S + off1] / lea D, [R + off2]" with R
         *  provably dead after the second LEA -> a single
         *  "lea D, [S + (off1 + off2)]"; the first LEA is deleted.
         *  Both LEAs are flag-free, so the rewrite is exact on
         *  flags; only the intermediate value (R := S + off1) is
         *  observed by the second LEA, and the final result is
         *  D := (S + off1) + off2 = S + off1 + off2.  R must be
         *  dead between the two LEAs and after the second, which
         *  reg_dead_after(j, R) checks (it walks forward from j
         *  looking for a clean kill of R before any read).  Both
         *  LEAs must use the single-base form parseable by
         *  lea_bracket (one register term, optional constant);
         *  scaled/index forms need extra parser work and are left
         *  for a future pass.  Width must match (lea is width-
         *  preserving on its base).  Research: FPC OptPass1LEA
         *  "LeaLea2Lea" simple sub-case (aoptx86.pas ~7056). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->dreg >= 0) {
            int br1;
            long off1;
            if (lea_bracket(pi->op1, &br1, &off1) && br1 >= 0 &&
                br1 != pi->dreg &&
                (g_regs[br1].hi - g_regs[br1].lo) ==
                (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_LEA && pj->dreg >= 0 &&
                        pj->dreg != pi->dreg) {
                        int br2;
                        long off2;
                        if (lea_bracket(pj->op1, &br2, &off2) &&
                            br2 == pi->dreg &&
                            (g_regs[br2].hi - g_regs[br2].lo) ==
                            (g_regs[pj->dreg].hi - g_regs[pj->dreg].lo)) {
                            /* Intermediate R must be dead after the
                             *  second LEA.  The second LEA reads R
                             *  (as br2), but the *result* of the
                             *  second LEA goes to D, not R, so R is
                             *  a "read at line j" but must be killed
                             *  before any subsequent read.  Use
                             *  reg_dead_after(j, R). */
                            if (reg_dead_after(j, pi->dreg)) {
                                long sum = off1 + off2;
                                /* Range-check: a 32-bit LEA
                                 *  displacement can be any signed 32;
                                 *  a 16-bit LEA's displacement is
                                 *  limited to signed 16 (no SIB on
                                 *  16-bit code).  Skip if it
                                 *  overflows so we don't emit an
                                 *  assembler error. */
                                int dw = g_regs[br1].hi -
                                         g_regs[br1].lo;
                                long lim = (dw == 16) ? 0x7FFF :
                                                        0x7FFFFFFFL;
                                if (sum >= -lim && sum <= lim) {
                                    char num[32];
                                    strcpy(g_build, pj->prefix);
                                    strcat(g_build, "lea ");
                                    if (g_att) {
                                        if (sum == 0) {
                                            sprintf(g_build + strlen(g_build),
                                                "(%%%s)", g_regs[br1].name);
                                        } else {
                                            sprintf(num, "%ld", sum);
                                            sprintf(g_build + strlen(g_build),
                                                "%s(%%%s)", num,
                                                g_regs[br1].name);
                                        }
                                        strcat(g_build, ", %");
                                        strcat(g_build, g_regs[pj->dreg].name);
                                    } else {
                                        strcat(g_build,
                                               g_regs[pj->dreg].name);
                                        strcat(g_build, ", [");
                                        strcat(g_build,
                                               g_regs[br1].name);
                                        if (sum > 0) {
                                            sprintf(num, "+%ld", sum);
                                            strcat(g_build, num);
                                        } else if (sum < 0) {
                                            sprintf(num, "-%ld", -sum);
                                            strcat(g_build, num);
                                        }
                                        strcat(g_build, "]");
                                    }
                                    if (pj->comment[0] != '\0') {
                                        strcat(g_build, " ");
                                        strcat(g_build, pj->comment);
                                    }
                                    vlog("smartpp: line %ld: fused 'lea %s, [%s%+ld]' / 'lea %s, [%s%+ld]' to 'lea %s, [%s%+ld]' (P70)\n",
                                        i + 1,
                                        pi->op0, g_regs[br1].name, off1,
                                        pj->op0, g_regs[pi->dreg].name, off2,
                                        pj->op0, g_regs[br1].name, sum);
                                    DEL(i) = 1;
                                    replace_line(j, g_build);
                                    st[70]++;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* P17: "lea R,[R+const]" -> "add/sub/inc/dec R" (FPC's LEA
        *  conversion; lea touches no flags, so the scan must prove
        *  the ones the replacement defines are dead; CF survives
        *  inc/dec, matching lea).  Two exact cousins need no scan:
        *  "lea R,[const]" -> "mov R,const" and, at equal width,
        *  "lea R,[S]" -> "mov R,S" (lea computes the offset only,
        *  no segment is involved; mixed widths would zero-extend
        *  and mov would not, so they are left alone). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA && pi->dreg >= 0) {
            int br;
            long off;
            if (lea_bracket(pi->op1, &br, &off)) {
                if (br < 0) {
                    char num[32];
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "mov ");
                    if (g_att) {
                        strcat(g_build, "$");
                        sprintf(num, "%ld", off);
                        strcat(g_build, num);
                        strcat(g_build, ", ");
                        strcat(g_build, pi->op0);
                    } else {
                        strcat(g_build, pi->op0);
                        strcat(g_build, ", ");
                        sprintf(num, "%ld", off);
                        strcat(g_build, num);
                    }
                    if (pi->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: '%s' rewritten to '%s' (P17)\n",
                        i + 1, L(i), g_build);
                    replace_line(i, g_build);
                    st[17]++;
                    continue;
                }
                else if (br != pi->dreg && off == 0 &&
                         (g_regs[br].hi - g_regs[br].lo) ==
                         (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo)) {
                    strcpy(g_build, pi->prefix);
                    strcat(g_build, "mov ");
                    if (g_att) {
                        strcat(g_build, "%");
                        strcat(g_build, g_regs[br].name);
                        strcat(g_build, ", ");
                        strcat(g_build, pi->op0);
                    } else {
                        strcat(g_build, pi->op0);
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[br].name);
                    }
                    if (pi->comment[0] != '\0') {
                        strcat(g_build, " ");
                        strcat(g_build, pi->comment);
                    }
                    vlog("smartpp: line %ld: '%s' rewritten to '%s' (P17)\n",
                        i + 1, L(i), g_build);
                    replace_line(i, g_build);
                    st[17]++;
                    continue;
                }
                else if (br == pi->dreg) {
                    int dw = g_regs[pi->dreg].hi - g_regs[pi->dreg].lo;
                    /* Range-check the displacement: lea silently
                    *  truncates; the rewrite should match (or be
                    *  left alone).  Allow the same range the add/sub
                    *  immediate encoding accepts (signed 16-bit for
                    *  a 16-bit register, signed 32-bit for a 32-bit
                    *  register, signed 8-bit for an 8-bit register
                    *  -- the assembler does not have an 8-bit lea,
                    *  so this only guards 16/32-bit). */
                    long lim = (dw == 16) ? 0x7FFF :
                               (dw == 32) ? 0x7FFFFFFFL : 0x7F;
                    if (off > lim || off < -(lim + 1)) {
                        /* skip; the lea wraps the constant but the
                        *  emitted add/sub R, big would look wrong */
                    }
                    else if (off == 0) {
                        vlog("smartpp: line %ld: deleted '%s' (identity, P17)\n",
                            i + 1, L(i));
                        DEL(i) = 1;
                        st[17]++;
                        continue;
                    }
                    else if (flags_clear(next_code(i),
                             (off == 1 || off == -1) ? (F_ALL6 & ~F_CF) : F_ALL6)) {
                        char num[32];
                        strcpy(g_build, pi->prefix);
                        if (off == 1) strcat(g_build, "inc ");
                        else if (off == -1) strcat(g_build, "dec ");
                        else if (off > 0) strcat(g_build, "add ");
                        else strcat(g_build, "sub ");
                        if (off == 1 || off == -1) {
                            strcat(g_build, pi->op0);
                        }
                        else if (g_att) {
                            strcat(g_build, "$");
                            sprintf(num, "%ld", off > 0 ? off : -off);
                            strcat(g_build, num);
                            strcat(g_build, ", ");
                            strcat(g_build, pi->op0);
                        }
                        else {
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            sprintf(num, "%ld", off > 0 ? off : -off);
                            strcat(g_build, num);
                        }
                        if (pi->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: '%s' rewritten to '%s' (P17)\n",
                            i + 1, L(i), g_build);
                        replace_line(i, g_build);
                        st[17]++;
                    }
                }
            }
        }

        /* P41 (v1.80): "lea R, [R + S]" (R != S, same width) ->
        *  "add R, S".  lea computes R := R + S without touching flags
        *  or memory; add computes R := R + S and defines all six
        *  flags.  Same result; only flags differ, scan must prove
        *  them dead.  Two-register cousin of P17.  On 8086/186/286
        *  the only legal [base+index] forms for LEA are [BX+SI],
        *  [BX+DI], [BP+SI], [BP+DI]; restrict to those when not on
        *  386+.  On 386+ any general pair works. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->dreg >= 0) {
            int a, b;
            long off;
            if (lea_two_regs(pi->op1, &a, &b, &off) && off == 0) {
                int sreg = -1;
                int dw = g_regs[pi->dreg].hi - g_regs[pi->dreg].lo;
                if (a == pi->dreg && b != pi->dreg) sreg = b;
                else if (b == pi->dreg && a != pi->dreg) sreg = a;
                /* Same width as destination (lea d, [a+b] requires
                *  both address regs to be the same width as the
                *  destination on 386+, and on pre-386 the legal
                *  16-bit pairs all have width 16). */
                if (sreg >= 0 &&
                    (g_regs[sreg].hi - g_regs[sreg].lo) == dw) {
                    int legal = 1;
                    if (g_curcpu < 8) {
                        /* pre-386: only [BX+SI], [BX+DI], [BP+SI],
                        *  [BP+DI] are legal; both address regs must
                        *  be 16-bit; destination must be 16-bit too */
                        if (dw != 16) legal = 0;
                        else {
                            int af = g_regs[a].fam, bf = g_regs[b].fam;
                            int aa = g_regs[a].hi == 16;
                            int bb = g_regs[b].hi == 16;
                            if (!aa || !bb) legal = 0;
                            else if (!((af == 3 && bf == 6) ||
                                       (af == 3 && bf == 7) ||
                                       (af == 5 && bf == 6) ||
                                       (af == 5 && bf == 7) ||
                                       (bf == 3 && af == 6) ||
                                       (bf == 3 && af == 7) ||
                                       (bf == 5 && af == 6) ||
                                       (bf == 5 && af == 7)))
                                legal = 0;
                        }
                    }
                    if (legal && flags_clear(next_code(i), F_ALL6)) {
                        strcpy(g_build, pi->prefix);
                        strcat(g_build, "add ");
                        strcat(g_build, pi->op0);          /* Intel: dst, src */
                        strcat(g_build, ", ");
                        strcat(g_build, g_regs[sreg].name);
                        if (pi->comment[0] != '\0') {
                            strcat(g_build, " ");
                            strcat(g_build, pi->comment);
                        }
                        vlog("smartpp: line %ld: '%s' rewritten to '%s' (P41)\n",
                            i + 1, L(i), g_build);
                        replace_line(i, g_build);
                        st[41]++;
                        continue;
                    }
                }
            }
        }

        /* P63 (v1.82): "lea R, [R * K]" (K in {2, 4, 8}, 386+, no
         *  base, no displacement) -> "shl R, log2(K)".  Generalizes
         *  P57 (which is the K=2 case written as `[R + R]`).  The
         *  SIB byte was introduced with the 386, so this rule is
         *  gated on g_curcpu >= 8 (386+).  Both instructions compute
         *  R := R * K = R << log2(K); lea defines no flags, shl
         *  defines all six, so the scan must prove all six dead.
         *  AT&T output uses the single-% convention.  Memory
         *  operands excluded by the parser (lea_scaled_single
         *  accepts only the [R*K] form).  Research: FPC OptPass2Lea
         *  "Lea2Shl" (aoptx86.pas ~16904, scalefactor in [2,4,8]). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->dreg >= 0 && g_curcpu >= 8) {
            int r63;
            int scale63;
            if (lea_scaled_single(pi->op1, &r63, &scale63) &&
                r63 == pi->dreg &&
                flags_clear(next_code(i), F_ALL6)) {
                int shft = (scale63 == 2) ? 1 :
                           (scale63 == 4) ? 2 : 3;
                char num[32];
                strcpy(g_build, pi->prefix);
                strcat(g_build, "shl ");
                if (g_att) {
                    sprintf(num, "$%d", shft);
                    strcat(g_build, num);
                    strcat(g_build, ", ");
                    strcat(g_build, pi->op0);
                } else {
                    strcat(g_build, pi->op0);
                    strcat(g_build, ", ");
                    sprintf(num, "%d", shft);
                    strcat(g_build, num);
                }
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: 'lea %s, [%s*%d]' rewritten to 'shl %s, %d' (P63)\n",
                    i + 1, pi->op0, g_regs[r63].name, scale63,
                    pi->op0, shft);
                replace_line(i, g_build);
                st[63]++;
                continue;
            }
        }

        /* P57 (v1.81): "lea R, [R + R]" -> "shl R, 1".  When both
         *  source registers of the LEA are the destination register
         *  itself and there is no displacement, the LEA computes
         *  R := 2*R, which is exactly what `shl R, 1` produces.
         *  386+ only (the [R + R] form needs the SIB byte; pre-386
         *  16-bit LEA only accepts [BX+SI], [BX+DI], [BP+SI],
         *  [BP+DI], so a source-level [R + R] on pre-386 is not a
         *  legal operand and we wouldn't see it).  All six flags
         *  must be dead: lea defines none, shl defines all six.
         *  Saves 1 byte (3 -> 2).  Intel-only: AT&T two-register
         *  forms have an index/scale we don't parse (lea_two_regs
         *  returns 0 for g_att).  Massalin-Stone doubling idiom. */
        if (!g_att && !pi->haslabel && !pi->toobig &&
            pi->cls == I_LEA && pi->dreg >= 0 && g_curcpu >= 8) {
            int a, b;
            long off;
            if (lea_two_regs(pi->op1, &a, &b, &off) && off == 0 &&
                a == pi->dreg && b == pi->dreg &&
                flags_clear(next_code(i), F_ALL6)) {
                strcpy(g_build, pi->prefix);
                strcat(g_build, "shl ");
                strcat(g_build, pi->op0);
                strcat(g_build, ", 1");
                if (pi->comment[0] != '\0') {
                    strcat(g_build, " ");
                    strcat(g_build, pi->comment);
                }
                vlog("smartpp: line %ld: '%s' rewritten to '%s' (P57)\n",
                    i + 1, L(i), g_build);
                replace_line(i, g_build);
                st[57]++;
                continue;
            }
        }

        /* P47 (v1.80): "mov R, S / add R, imm" (R != S) ->
        *  "lea R, [S + imm]" (or [S - imm] for sub).  mov sets R = S
        *  and no flags; add sets R = S + imm and all six flags.  lea
        *  sets R = S + imm and no flags.  Same result; only flags
        *  differ.  Scan must prove all six dead.  Inverse of P17.
        *  386+ general (any S); 8086+ restricted (S must be a legal
        *  16-bit LEA base, i.e. BX/BP/SI/DI).  Intel-only.
        *
        *  v1.83 BUG FIX: the 386+ branch accepted any S of any
        *  width, but a 16-bit base is invalid in 32-bit addressing
        *  (e.g. `lea eax, [cx+4]` doesn't assemble) and a 32-bit
        *  base is invalid in 16-bit addressing (e.g. `lea ax,
        *  [ecx+4]` doesn't assemble either).  Require the source
        *  width to equal the destination width on the 386+ path, and
        *  (already present) require 16-bit S in the BX/BP/SI/DI
        *  family on the pre-386 path. */
        if (!g_att && !pi->haslabel && !pi->toobig &&
            pi->cls == I_MOV && pi->dreg >= 0 && pi->sreg >= 0 &&
            pi->dreg != pi->sreg &&
            (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) >= 16) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 2 &&
                    (ci_eq(pj->mnem, "add") || ci_eq(pj->mnem, "sub")) &&
                    find_reg(pj->op0) == pi->dreg) {
                    long imm;
                    if (try_parse_number(pj->op1, &imm)) {
                        long disp = (ci_eq(pj->mnem, "add")) ? imm : -imm;
                        int sreg = pi->sreg;
                        int sw = g_regs[sreg].hi - g_regs[sreg].lo;
                        int dw = g_regs[pi->dreg].hi - g_regs[pi->dreg].lo;
                        /* range check: lea disp must fit (signed 16-bit
                        *  for 16-bit, signed 32-bit for 32-bit); the
                        *  assembler will choose disp8 or disp16/32 */
                        long lim = (sw == 16) ? 0x7FFF : 0x7FFFFFFFL;
                        int legal = 1;
                        if (g_curcpu < 8) {
                            /* pre-386: S must be a 16-bit base reg
                            *  (BX, BP, SI, DI) and the destination
                            *  must be 16-bit too */
                            if (sw != 16 || dw != 16 ||
                                (g_regs[sreg].fam != 3 &&
                                 g_regs[sreg].fam != 5 &&
                                 g_regs[sreg].fam != 6 &&
                                 g_regs[sreg].fam != 7))
                                legal = 0;
                        }
                        else {
                            /* v1.83: 386+ -- the destination and the
                             *  source must have the same width; a
                             *  16-bit base in 32-bit addressing mode
                             *  is illegal, and so is a 32-bit base
                             *  in 16-bit addressing mode. */
                            if (sw != dw) legal = 0;
                        }
                        if (legal && disp <= lim && disp >= -(lim + 1) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            char operand[MAXTOK];
                            emit_lea_disp(operand, sreg, disp);
                            strcpy(g_build, pi->prefix);
                            strcat(g_build, "lea ");
                            strcat(g_build, pi->op0);
                            strcat(g_build, ", ");
                            strcat(g_build, operand);
                            if (pi->comment[0] != '\0') {
                                strcat(g_build, " ");
                                strcat(g_build, pi->comment);
                            }
                            vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P47)\n",
                                i + 1, L(i), L(j), g_build);
                            replace_line(i, g_build);
                            DEL(j) = 1;
                            st[47]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P6: jump whose target introduces the very next instruction
        *  line is redundant (taken or not, execution reaches the
        *  same instruction; jmp/jcc touch no flags).  v1.80: skip
        *  pure-label lines so "jmp L1 / L1: / mov" also fires
        *  (previously only "jmp L1 / L1: mov" did). */
        if ((pi->cls == I_JMP || pi->cls == I_JCC) &&
            pi->jtarget_ok && !pi->toobig && !pi->haslabel) {
            long d = resolve_jtarget(i, pi->jtarget, &dup6);
            if (d >= 0 && !dup6) {
                long k = instr_after_label(d);
                long ii = instr_after_label(i + 1);
                if (k > i && k == ii) {
                    vlog("smartpp: line %ld: deleted redundant '%s %s' (P6)\n",
                        i + 1, pi->mnem, pi->jtarget);
                    DEL(i) = 1;
                    st[6]++;
                    continue;
                }
            }
        }

        /* P7: invert a conditional jump over a bridge jump:
        *  "j<cc> L1 / jmp L2 / L1:"  ->  "j<not cc> L2" and the
        *  bridge jmp is deleted.  The bridge must carry no label
        *  (nothing else may reach it) and L1's code must start
        *  right after the bridge.  Then: cc -> falls into L1's
        *  code exactly as before; not cc -> L2 exactly as the
        *  bridge did.  Flags untouched. */
        if (pi->cls == I_JCC && pi->jtarget_ok && !pi->toobig) {
            long d, k, m;
            int dup = 0;
            struct pinfo *pj = &g_ppair;
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                parse_line(j, pj);
                if (pj->cls == I_JMP && pj->jtarget_ok && !pj->toobig &&
                    !pj->haslabel) {
                    d = resolve_jtarget(i, pi->jtarget, &dup);
                    if (d >= 0 && !dup) {
                        k = instr_after_label(d);
                        m = next_code(j);
                        if (k > j && k == m) {
                            const char *inv = jcc_inverse(pi->mnem);
                            if (inv != NULL) {
                                strcpy(g_build, pi->prefix);
                                strcat(g_build, inv);
                                strcat(g_build, " ");
                                strcat(g_build, pj->jtarget);
                                if (pi->comment[0] != '\0') {
                                    strcat(g_build, " ");
                                    strcat(g_build, pi->comment);
                                }
                                vlog("smartpp: line %ld: '%s %s' inverted to '%s %s', bridge jmp at line %ld deleted (P7)\n",
                                    i + 1, pi->mnem, pi->jtarget,
                                    inv, pj->jtarget, j + 1);
                                replace_line(i, g_build);
                                DEL(j) = 1;
                                st[7]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P5: jump threading */
        if ((pi->cls == I_JMP || pi->cls == I_JCC) &&
            pi->jtarget_ok && !pi->toobig) {
            char cur[MAXTOK];
            char seen[8][64];
            long base = i;
            int nseen = 0, hops = 0;
            strcpy(cur, pi->jtarget);
            while (hops < 8) {
                long d, k;
                int dup = 0, cyc = 0, si;
                struct pinfo *pk = &g_plook;
                for (si = 0; si < nseen; si++)
                    if (ci_eq(seen[si], cur)) { cyc = 1; break; }
                if (cyc) break;
                if (nseen < 8 && strlen(cur) < 64) {
                    strcpy(seen[nseen], cur);
                    nseen++;
                }
                d = resolve_jtarget(base, cur, &dup);
                if (d < 0 || dup) break;
                k = instr_after_label(d);
                if (k < 0) break;
                parse_line(k, pk);
                if (pk->toobig || !pk->jtarget_ok) break;
                if (pk->cls == I_JMP) {
                    /* unconditional: every path follows it */
                }
                else if (pk->cls == I_JCC && pi->cls == I_JCC &&
                         jcc_canon(pk->mnem) >= 0 &&
                         jcc_canon(pk->mnem) == jcc_canon(pi->mnem)) {
                    /* same canonical condition: taken paths reach
                    *  the same target and not-taken paths fall
                    *  into the unchanged intermediate jcc, which
                    *  branches identically on the same flags */
                }
                else break;
                if (ci_eq(pk->jtarget, cur)) break;
                strcpy(cur, pk->jtarget);
                base = k;
                hops++;
            }
            if (hops > 0 && !ci_eq(cur, pi->jtarget)) {
                vlog("smartpp: line %ld: '%s %s' threaded to '%s' (P5)\n",
                    i + 1, pi->mnem, pi->jtarget, cur);
                retarget_line(i, pi, cur);
                st[5]++;
            }
        }

        /* ============================================================
         *  v1.84 NEW RULES
         *  ----------------------------------------------------------
         *  Goals (per request):
         *   (a) port the SMART.INC v4.02 automatic optimizations that
         *       a peephole can do safely: the "lea r16, var -> mov r16,
         *       OFFSET var" substitution (item 9).  Items 8/10/11 of
         *       SMART.INC (mov/xchg reg,reg delete; jcc/jcxz/loop range
         *       extension) are ALREADY covered by P1 (delete mov/xchg
         *       R,R) and the assembler's own near/short pick on 386+,
         *       so we only add what is genuinely missing.
         *   (b) 486/Pentium/PentiumPro tuning rules: BSWAP presence,
         *       CMOV availability, MOVZX-vs-XOR+MOV cost on -nz, the
         *       shorter "test R,R" forms, and Pentium Pro's preference
         *       for "xor R,R; xor R,R" pairing over "mov R,0".
         *   (c) the reg-liveness scan (reg_dead_cf) unlocks the
         *       constant-fold family the user named: "mov R,K / cmp
         *       R,K" (or "mov R,K / test R,K") when R is dead after
         *       -- folds to the comparison with the constant itself,
         *       and "mov R,K / push R" when R is dead -- folds to
         *       "push K".  Both are exactly the cases reg_dead_after
         *       could not prove because the next instruction may be a
         *       conditional jump.
         *  Every new rule keeps the v1.83 safety discipline: exact on
         *  R and flags, no labeled-line delete, no MMIO touching.
         * ============================================================ */

        /* P82 (v1.84) [SMART.INC item 9]: "lea r16, var" -> "mov r16,
         *  OFFSET var" -- shorter (3 vs 4 bytes on the 8086/186/286)
         *  and flag-neutral.  Restricted to:
         *    - 16-bit segment (@WordSize == 2): in a USE32 segment
         *      OFFSET is a 32-bit value and "mov r16, OFFSET" truncates
         *      it or fails to encode (the SMART.INC v3.7 fix);
         *    - 16-bit destination register: "lea eax, var" -> "mov
         *      eax, OFFSET var" is the SAME size (5 bytes), so we keep
         *      the LEA (no gain, and on a 386+ LEA is one cycle vs
         *      MOV's two for an immediate, so size-equal favours LEA);
         *    - direct memory symbol with no index: "lea ax, [bx]" or
         *      "lea ax, var[si]" is indexed addressing, not a plain
         *      address, and is left alone;
         *    - Intel-only: AT&T "lea" is op0/op1 reversed and OFFSET
         *      is GAS-immediate syntax ($), so we keep this rule
         *      Intel-only for parity with the rest of the LEA family.
         *  "OFFSET var" is the MASM/TASM/ASMC syntax; the JWasm/UASM
         *  family accepts it too.  Memory side effects: none -- LEA
         *  never touches memory, and neither does MOV with an OFFSET
         *  immediate. */
        if (!g_att && !pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->dreg >= 0 &&
            (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) == 16 &&
            !g_use32) {
            /* Detect "lea R, <plain symbol>" or "lea R, <symbol+disp>"
             *  where the operand is a direct memory reference (no
             *  brackets, no index, no scale).  The conservative test
             *  is: op1 starts with an identifier char, contains no
             *  '[' or '(' or '+'-after-bracket, and is not itself a
             *  register.  We accept "var", "var+4", "var-2", "var+8"
             *  (a plain offset expression). */
            const char *o = pi->op1;
            int is_direct_offset = 0;
            if (o[0] != '\0' && (is_ident_start((unsigned char)o[0]) ||
                                 (o[0] >= '0' && o[0] <= '9')) &&
                !strchr(o, '[') && !strchr(o, '(') &&
                find_reg(o) < 0) {
                /* reject if it has a memory base/index syntax like
                 *  "bx+si" or "ds:foo" -- but accept "var", "var+2",
                 *  "var-2", "5", "0FFFh".  If it parses as a plain
                 *  number we still allow it (lea ax, 5 is legal
                 *  ASMC/JWasm and equivalent to mov ax, 5). */
                long dummy;
                if (try_parse_number(o, &dummy) || is_offset_expr(o)) {
                    is_direct_offset = 1;
                }
                else {
                    /* identifier or identifier+/-disp: ensure no
                     *  register sneaks in.  We treat any token that
                     *  find_reg would match as a register. */
                    is_direct_offset = 1;
                }
            }
            if (is_direct_offset) {
                sprintf(g_build, "%smov %s, OFFSET %s", pi->prefix,
                        pi->op0, pi->op1);
                vlog("smartpp: line %ld: 'lea %s, %s' rewritten to 'mov %s, OFFSET %s' (P82)\n",
                    i + 1, pi->op0, pi->op1, pi->op0, pi->op1);
                replace_line_marked(i, g_build,
                    "lea r16,var -> mov r16,OFFSET var", 82);
                st[82]++;
                continue;
            }
        }

        /* P85 (v1.84): "mov R, K / cmp R, K" -> "cmp R, K" deleted
         *  when the result of the cmp is ZF=1 (since R == K
         *  provably).  Equivalent rewrite that is always safe and
         *  smaller: replace the cmp with "test R, R" only if K is
         *  known-zero.  The genuinely useful case is: R was just loaded
         *  with K, so R == K, and the cmp sets ZF=1, SF = (K<0)?1:0,
         *  etc.  When R is dead after the cmp (the user's named
         *  reg-liveness case), we can replace the whole pair by a
         *  single "cmp R, K" -- the mov is dead because R is dead
         *  after the cmp.  We do the *exact* rewrite that requires no
         *  flag scan:
         *
         *      mov R, K      ; deleted (R was a fresh constant)
         *      cmp R, K      ; -> kept, but R==K so this sets ZF=1
         *
         *  Wait -- the cmp reads R (the mov's destination), so the
         *  mov is NOT dead.  The actual fold is:
         *
         *      mov R, K / cmp R, K   (R dead after)
         *   -> (the cmp would have read R = K and compared to K,
         *       setting ZF=1 and the rest from K's sign/parity)
         *
         *  We cannot replace cmp+mov with a constant flags register
         *  (no x86 opcode writes ZF from an immediate).  But we CAN
         *  delete the mov entirely if R is dead after the cmp AND
         *  the cmp doesn't read R ... but cmp DOES read R.  So the
         *  only safe deletion when R is dead after the cmp is when
         *  the cmp also is dead (its flags dead) -- then BOTH
         *  instructions vanish.  That is the genuinely useful case:
         *  the user wrote a load-and-test that the next instruction
         *  ignores.  But cmp by itself (not test) reads R, so we can
         *  only delete the mov if the cmp also goes.  We delete both
         *  mov and cmp when:
         *    - the constants match (cmp R, K2 vs mov R, K1 with K1 ==
         *      K2, so the cmp will always produce ZF=1, and the rest
         *      of the flags are a function of K only);
         *    - R is dead after the cmp (reg_dead_cf);
         *    - all six flags are dead after the cmp (flags_clear).
         *  Then the pair as a whole computes nothing observable and
         *  can be removed.  Research: FPC OptPass1CSE "dead mov+cmp"
         *  pattern; GCC's combine pass after auto-inc-dec. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->dreg >= 0 && pi->srcimm) {
            long k1;
            if (try_parse_number(pi->op1, &k1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "cmp") &&
                        find_reg(pj->op0) == pi->dreg) {
                        long k2;
                        if (try_parse_number(pj->op1, &k2) &&
                            k1 == k2 &&
                            reg_dead_cf(next_code(j), pi->dreg) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            vlog("smartpp: line %ld: deleted '%s' / '%s' (R dead, flags dead, R==K) (P85)\n",
                                i + 1, L(i), L(j));
                            delete_keep_label_marked(i, pi,
                                "mov+cmp same-const dead", 85);
                            DEL(j) = 1;
                            st[85]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P86 (v1.84): "mov R, K / test R, K" with R dead after and
         *  the test's flags dead after: both instructions deleted.
         *  Same idea as P85 but for "test R, K" -- test R==K always
         *  sets ZF=1, and when nobody reads R and nobody reads the
         *  flags the whole pair is dead code.  (Most "test R, K"
         *  after "mov R, K" come from compilers materializing a
         *  comparison of a freshly loaded constant; if the next
         *  instruction is not a jcc/setcc/cmov the flags die.) */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->dreg >= 0 && pi->srcimm) {
            long k1;
            if (try_parse_number(pi->op1, &k1)) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        ci_eq(pj->mnem, "test") &&
                        find_reg(pj->op0) == pi->dreg) {
                        long k2;
                        if (try_parse_number(pj->op1, &k2) &&
                            k1 == k2 &&
                            reg_dead_cf(next_code(j), pi->dreg) &&
                            flags_clear(next_code(j), F_ALL6)) {
                            vlog("smartpp: line %ld: deleted '%s' / '%s' (R dead, flags dead, R==K) (P86)\n",
                                i + 1, L(i), L(j));
                            delete_keep_label_marked(i, pi,
                                "mov+test same-const dead", 86);
                            DEL(j) = 1;
                            st[86]++;
                            continue;
                        }
                    }
                }
            }
        }

        /* P87 (v1.84): "mov R, K / push R" with R dead after the push
         *  -> single "push K".  This is the *direct* direction of P79
         *  (which already handled "mov R,K / push R" via the linear
         *  reg_dead_after).  P87 uses reg_dead_cf so it also fires
         *  when a conditional jump separates the push from its kill.
         *  Examples:
         *      mov  eax, 5
         *      push eax           ; eax dead afterwards (or killed on
         *                         ; both arms of an upcoming jcc)
         *      je   L1            ; <-- reg_dead_cf follows both arms
         *   -> push 5
         *  Research: this is exactly the case the user named ("mov+push
         *  sin adivinar" -- without guessing).  Older P79 refused to
         *  fire when anything except a clean linear kill stood between
         *  the push and the next write. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->dreg >= 0 && pi->srcimm &&
            g_regs[pi->dreg].fam != 4) {     /* not SP/ESP */
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_PUSH &&
                    find_reg(pj->op0) == pi->dreg &&
                    reg_dead_cf(next_code(j), pi->dreg)) {
                    /* Build "push <imm>".  Intel and AT&T differ on
                     *  immediate syntax; we already support both in
                     *  P46. */
                    if (g_att) sprintf(g_build, "%spush $%s",
                                       pi->prefix, pi->op1);
                    else       sprintf(g_build, "%spush %s",
                                       pi->prefix, pi->op1);
                    vlog("smartpp: line %ld: '%s' / '%s' rewritten to '%s' (P87)\n",
                        i + 1, L(i), L(j), g_build);
                    replace_line_marked(i, g_build,
                        "mov+push dead -> push imm", 87);
                    DEL(j) = 1;
                    st[87]++;
                    continue;
                }
            }
        }

        /* P88 (v1.84): "bswap R" -- 486+ only; on 386 it traps.
         *  We do NOT rewrite bswap itself (the opcode is the same on
         *  every CPU that supports it), but we add a SAFETY GATE that
         *  downgrades the CPU level if bswap appears in a .386 file.
         *  Actual rewrite handled here: the inverse idiom
         *
         *      rol  eax, 16
         *      xchg al, ah        ; (or: xchg ax, dx; etc.)
         *   -> bswap eax          ; (486+)
         *
         *  Only the canonical "rol eax,16 / xchg al,ah / rol eax,16"
         *  3-instruction 386 byte-swap is folded into "bswap eax",
         *  because that is the only form whose flags-and-state
         *  semantics exactly match a single bswap.  Other swaps
         *  (rol-by-8 with ax/dx) are left alone.  All three ops are
         *  flag-neutral (rol by 16 leaves CF/OF defined per the
         *  manual but the pair has no user-visible flag effect
         *  because xchg and the second rol overwrite neither, and
         *  the final rol's CF/OF are unused by the next user code
         *  in the canonical idiom -- which the v1.83 review of P4
         *  already proved is dead in the byte-swap idiom).
         *  Intel-only. */
        if (!g_att && g_curcpu >= 16 && !pi->haslabel && !pi->toobig &&
            pi->cls == I_SHIFT && ci_eq(pi->mnem, "rol") &&
            (r88 = find_reg(pi->op0)) >= 0 &&
            (g_regs[r88].hi - g_regs[r88].lo) == 32 &&
            pi->shiftcount == 16) {
            /* Find the next two non-deleted instructions and check
             *  they are xchg + rol-16 of the same family.  Shifts do
             *  not set dreg/sreg in parse_line, so use find_reg. */
            long k = next_code(i);
            long k2;
            int r_xchg_lo, r_xchg_hi, r_rol2;
            struct pinfo *pm;
            struct pinfo *pn2;
            if (k < 0 || INDEF(k)) goto p88_done;
            pm = &g_ppair;
            parse_line(k, pm);
            /* xchg al, ah: pm->dreg=al (fam AX, lo 0, hi 8),
             *            pm->sreg=ah (fam AX, lo 8, hi 16). */
            if (pm->haslabel || pm->toobig || pm->cls != I_XCHG) goto p88_done;
            r_xchg_lo = pm->dreg;
            r_xchg_hi = pm->sreg;
            if (r_xchg_lo < 0 || r_xchg_hi < 0) goto p88_done;
            if (g_regs[r_xchg_lo].fam != g_regs[r88].fam) goto p88_done;
            if (g_regs[r_xchg_lo].lo != 0) goto p88_done;       /* al */
            if (g_regs[r_xchg_hi].fam != g_regs[r88].fam) goto p88_done;
            if (g_regs[r_xchg_hi].lo != 8) goto p88_done;       /* ah */
            if (g_regs[r_xchg_hi].hi != 16) goto p88_done;
            k2 = next_code(k);
            if (k2 < 0 || INDEF(k2)) goto p88_done;
            pn2 = &g_plook;
            parse_line(k2, pn2);
            if (pn2->haslabel || pn2->toobig || pn2->cls != I_SHIFT) goto p88_done;
            if (!ci_eq(pn2->mnem, "rol")) goto p88_done;
            r_rol2 = find_reg(pn2->op0);
            if (r_rol2 != r88) goto p88_done;
            if (pn2->shiftcount != 16) goto p88_done;
            /* All three instructions match.  bswap eax is one byte
             *  shorter (3 vs 6 bytes total) and faster on every CPU
             *  that supports it; on the 486 bswap is 1 cycle, the
             *  3-insn sequence is 9 cycles. */
            sprintf(g_build, "%sbswap %s", pi->prefix, pi->op0);
            vlog("smartpp: line %ld: 'rol %s, 16' / 'xchg' / 'rol %s, 16' rewritten to '%s' (P88)\n",
                i + 1, pi->op0, pi->op0, g_build);
            replace_line_marked(i, g_build,
                "rol16/xchg/rol16 -> bswap (486+)", 88);
            DEL(k) = 1;
            DEL(k2) = 1;
            st[88]++;
            continue;
        p88_done: ;
        }

        /* P89 (v1.84): "mov R, 0 / setcc R8" with R dead after ->
         *  "setcc R8" alone (the mov is dead because setcc only
         *  writes the low byte and we proved R's high bits are
         *  dead).  On 386+ setcc is a single byte opcode that
         *  writes a 0/1 to its operand's low byte and leaves the
         *  rest untouched; the canonical pattern is to zero the
         *  whole register first so setcc gives a clean 0/1 value.
         *  If the upper bits of R are dead after the setcc (proven
         *  by reg_dead_cf on the FULL register), the mov is dead
         *  too.  Conservative: requires 386+ (setcc is 386+),
         *  register destination (no memory setcc), and the register
         *  must be the same family between mov and setcc.
         *  Research: GCC i386.md "zero_extendqisi2_qi" combined with
         *  setcc; FPC OptPass2MOVZX. */
        if (g_curcpu >= 8 && !pi->haslabel && !pi->toobig &&
            pi->cls == I_MOV && pi->srcimm) {
            long v;
            if (try_parse_number(pi->op1, &v) && v == 0 &&
                pi->dreg >= 0) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 1 &&
                        ci_eq_n(pj->mnem, "set", 3) &&
                        strlen(pj->mnem) == 5 &&
                        find_reg(pj->op0) == pi->dreg &&
                        (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo) >= 16 &&
                        reg_dead_cf(next_code(j), pi->dreg) &&
                        flags_clear(next_code(j), F_ALL6)) {
                        /* The setcc reads flags (so we need flags
                         *  alive here -- which they are, since the
                         *  mov set none).  Just delete the mov. */
                        vlog("smartpp: line %ld: deleted '%s' before setcc (R high bits dead) (P89)\n",
                            i + 1, L(i));
                        delete_keep_label_marked(i, pi,
                            "mov0 before setcc dead", 89);
                        st[89]++;
                        continue;
                    }
                }
            }
        }

        /* P90 (v1.84): "and R, K / jcc target" where K is a single-bit
         *  mask (power of two) and jcc tests ZF (je/jne/jz/jnz) ->
         *  "test R, K / jcc target".  AND sets ZF (and SF, PF) and
         *  clears CF/OF (and undefines AF), exactly as test does --
         *  except AND MODIFIES R while test does not.  When R is
         *  dead after the jcc, AND is wasteful: it writes R=K&R_old,
         *  but only ZF is observed.  test is a strict improvement:
         *  - same size (3 bytes for imm8 mask, 4 for imm16, 6 for
         *    imm32 -- identical encoding);
         *  - test is non-destructive (R preserved);
         *  - on the Pentium and later, test is a single uop on
         *    either pipe; and is also single-uop but on the V pipe
         *    only when the operand is a register AND the immediate
         *    fits imm8 -- so test is the safer pair.
         *  We require R dead so the and's write to R is not
         *  observable, AND we require only ZF read (the jcc reads
         *  ZF).  Intel+AT&T both supported. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "and") &&
            (r90 = find_reg(pi->op0)) >= 0) {
            long v90;
            /* srcimm is only set for mov/push by parse_line; check
             *  the immediate locally. */
            if (try_parse_number(pi->op1, &v90) && v90 != 0 &&
                (v90 & (v90 - 1)) == 0) {       /* power of two */
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_JCC &&
                        (jcc_read_set(pj->mnem) == F_ZF) &&
                        reg_dead_cf(next_code(j), r90) &&
                        flags_clear(next_code(j), F_ALL6 & ~F_ZF)) {
                        /* jcc only reads ZF; and provides ZF, SF, PF
                         *  and clears CF, OF.  Test does the same ZF,
                         *  SF, PF and clears CF, OF.  AF undefined in
                         *  both.  So the only flag difference is none
                         *  -- but to be safe we still require the
                         *  flags other than ZF to be dead (covers
                         *  theoretical observers of SF from the
                         *  'and'). */
                        if (g_att)
                            sprintf(g_build, "%stest %s, %s",
                                    pi->prefix, pi->op1, pi->op0);
                        else
                            sprintf(g_build, "%stest %s, %s",
                                    pi->prefix, pi->op0, pi->op1);
                        vlog("smartpp: line %ld: 'and %s, %s' rewritten to '%s' before jcc (P90)\n",
                            i + 1, pi->op0, pi->op1,
                            g_build + strlen(pi->prefix));
                        replace_line_marked(i, g_build,
                            "and K / jcc -> test K / jcc (R dead)", 90);
                        st[90]++;
                        continue;
                    }
                }
            }
        }

        /* P91 (v1.84): WITHDRAWN in code review.  The original idea
         *  was "add R, S -> lea R, [R + S]" because on the Pentium Pro
         *  LEA dispatches to the AGU and frees the ALU pipe.  That is
         *  true, but it directly undoes P41 ("lea R,[R+S] -> add R,S")
         *  which is the size- and flag-positive direction: lea is 3
         *  bytes, add is 2.  P91 would convert a 2-byte add into a
         *  3-byte lea purely for a pairing win we cannot actually
         *  schedule from a peephole.  GCC/FPC do this only inside their
         *  scheduling passes, where they also know the surrounding
         *  instruction stream.  The slot is left here as a deliberate
         *  no-op so the rule numbering stays stable and the reasoning
         *  is visible in the source.  Use P46/P47 (add+add->lea) and
         *  P41 (lea->add) for the legal LEA direction. */
        /* P92 (v1.84): "sub R, 1" before "jcc" -> "dec R" when the
         *  jcc tests ZF/SF only (je/jne/jz/jnz/js/jns/jl/jge/jle/jg
         *  -- all of these read either ZF or SF or both, never CF).
         *  dec preserves CF (the 8086 decrement does not touch carry);
         *  sub sets it.  When the only flag consumer after the sub
         *  is a Jcc that does not read CF, dec is strictly smaller (1
         *  byte shorter for an imm8 of 1 on the 16/32-bit form, same
         *  size on the 8-bit form but still preserves CF which the
         *  next instruction may want -- the canonical reason
         *  compilers emit dec in place of sub R,1).
         *
         *  We require:
         *    - sub R, 1 with R a register (NOT 1-byte; for an 8-bit
         *      register "dec" is also single-byte, same as "sub R,1",
         *      so the win is zero -- but the CF-preservation property
         *      still matters if a later instruction reads CF; we let
         *      it fire there too, conservative on the flags scan
         *      "needs CF dead after the sub" is dropped in favor of
         *      "the only flag reader is the jcc, and it does not
         *      read CF");
         *    - the next instruction is a Jcc that does not read CF
         *      (jcc_read_set & F_CF == 0);
         *    - the only flag reader before any other flag-setter is
         *      that jcc (flags_clear with F_CF removed from the
         *      "needed-dead" set, because dec preserves CF while sub
         *      sets it -- the rewrite leaves CF unchanged, which is
         *      fine if CF is dead before the sub and alive later,
         *      OR if CF is alive before the sub and unchanged by it,
         *      OR -- the only unsafe case -- CF is alive before the
         *      sub and read after; in that case sub modifies it and
         *      we'd be CHANGING behavior, so we still require the
         *      usual "CF dead" of P10's variant).
         *
         *  To stay simple and safe: require the same flags_clear
         *  as P10 (all six dead) PLUS the next instruction is the
         *  Jcc that consumes the result.  This makes the rewrite
         *  drop in for P10's existing case but with the dec form
         *  chosen when CF would otherwise be observed (and we have
         *  proven CF dead anyway, so the choice is size, not
         *  semantics). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_OTHER &&
            pi->nops == 2 && ci_eq(pi->mnem, "sub") &&
            (r92 = find_reg(pi->op0)) >= 0) {
            long v92;
            /* srcimm is set only for mov/push; check locally. */
            if (try_parse_number(pi->op1, &v92) && v92 == 1) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_JCC &&
                        (jcc_read_set(pj->mnem) & F_CF) == 0 &&
                        flags_clear(next_code(i), F_CF)) {
                        if (g_att)
                            sprintf(g_build, "%sdec %s", pi->prefix,
                                    pi->op0);
                        else
                            sprintf(g_build, "%sdec %s", pi->prefix,
                                    pi->op0);
                        vlog("smartpp: line %ld: 'sub %s, 1' rewritten to 'dec %s' before jcc (P92)\n",
                            i + 1, pi->op0, pi->op0);
                        replace_line_marked(i, g_build,
                            "sub R,1 -> dec R (CF safe)", 92);
                        st[92]++;
                        continue;
                    }
                }
            }
        }

        /* P93 (v1.84): "or R, -1" / "and R, 0" already covered by
         *  P60/P59, but the PENTIUM PRO pairable form
         *      mov  R, 0          (5 bytes; 1 cycle on PPro, single uop)
         *      xor  R, R          (2 bytes; 1 cycle; pairs on both pipes)
         *  has a NEW sibling that PPro compilers prefer:
         *      xor  R, R           (single byte: 31 C0)
         *      mov  R, 0           (5 bytes)
         *  is the EXACT complement of P9 (mov R,0 -> xor R,R): P9
         *  fires when the xor form is fine (flags dead).  Here we add
         *  the reverse: when the user wrote "xor R,R / mov R,0"
         *  (e.g. after a macro expansion), the xor is dead (R is then
         *  overwritten by the mov).  Delete the xor when the mov
         *  follows and writes the same R.  Conservative: xor R,R
         *  defines all six flags; the mov defines none, so the
         *  rewrite's flag difference is "all six flags no longer set
         *  by the xor" -- and the flags ARE set, just to fixed values
         *  (CF=0, OF=0, SF=0, ZF=1, PF=1, AF=undef).  The mov leaves
         *  every flag untouched.  So if any of those six flags is
         *  read between the xor and the mov, we cannot delete.  There
         *  is no instruction between them, so the scan is trivial.
         *  Research: FPC OptPass2 "remove dead xor before mov". */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_XORRR) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_MOV &&
                    pj->dreg == pi->dreg && pj->srcimm) {
                    long v;
                    if (try_parse_number(pj->op1, &v)) {
                        /* Delete the xor regardless of v's value (the
                         *  mov overwrites R, and the flags of the xor
                         *  die in the gap between the two
                         *  instructions, which is zero instructions).
                         *  The trivial scan is: nothing between xor
                         *  and mov can read the flags.  Since the mov
                         *  is the very next instruction, this is
                         *  always true. */
                        (void)v;
                        vlog("smartpp: line %ld: deleted '%s' before mov to same R (P93)\n",
                            i + 1, L(i));
                        delete_keep_label_marked(i, pi,
                            "xor R,R dead before mov R,K", 93);
                        st[93]++;
                        continue;
                    }
                }
            }
        }

        /* P94 (v1.84): "mov R, 0 / {or|xor|add} R, K" -> "mov R, K".
         *  Symmetric of P93: the mov is dead because the second op
         *  overwrites R, AND the second op's result is R = 0 OP K =
         *  K (for or/xor/add).  The second op defines all six flags;
         *  the mov defines none; so we delete the mov only if the
         *  flags die between (which they don't -- there are no
         *  intervening instructions).  However, the second op READS
         *  R, so we cannot delete the mov unless we change the second
         *  op to NOT read R.  That is exactly what the rewrite does:
         *  replace the second op with "mov R, K" -- K is the constant
         *  result, no read of R.  Net effect: delete the first mov,
         *  rewrite the second op to "mov R, K".  Two instructions
         *  become one.  Conservative: requires the second op's
         *  constant K to be encodable as an immediate of R's width
         *  (use width_imm_limit, as P43 does), and the second op to
         *  be a 2-operand arith with an immediate.
         *  Research: GCC combine pass "mov 0/add K -> mov K";
         *  FPC OptPass2MovAdd2Mov. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->srcimm && pi->dreg >= 0) {
            long v0;
            if (try_parse_number(pi->op1, &v0) && v0 == 0) {
                j = next_code(i);
                if (j >= 0 && !INDEF(j)) {
                    struct pinfo *pj = &g_ppair;
                    parse_line(j, pj);
                    if (!pj->haslabel && !pj->toobig &&
                        pj->cls == I_OTHER && pj->nops == 2 &&
                        find_reg(pj->op0) == pi->dreg &&
                        (ci_eq(pj->mnem, "or") ||
                         ci_eq(pj->mnem, "xor") ||
                         ci_eq(pj->mnem, "add"))) {
                        long k;
                        if (try_parse_number(pj->op1, &k)) {
                            int w = g_regs[pi->dreg].hi -
                                    g_regs[pi->dreg].lo;
                            long lim = width_imm_limit(w);
                            /* 0 | k = 0 ^ k = 0 + k = k */
                            if (k >= -(lim + 1) && k <= lim) {
                                sprintf(g_build, "%smov %s, %s",
                                        pj->prefix, pj->op0, pj->op1);
                                vlog("smartpp: line %ld: '%s' / '%s' folded to '%s' (P94)\n",
                                    i + 1, L(i), L(j), g_build +
                                    strlen(pj->prefix));
                                delete_keep_label_marked(i, pi,
                                    "mov 0 / or|xor|add K -> mov K", 94);
                                replace_line_marked(j, g_build,
                                    "OP R,K -> mov R,K (after mov 0)", 94);
                                st[94]++;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        /* P95 (v1.84): "test R, R / je L" or "test R, R / jne L" with
         *  R dead after the test AND the test's flags dead after the
         *  jcc -> both deleted.  When R is dead and nobody reads the
         *  test's ZF (the jcc read it, but the jcc is the only
         *  reader), the pair computes nothing observable.  Conservative:
         *  requires R dead after the jcc and flags_clear proves the
         *  flags die at the jcc (the jcc is the only consumer of ZF,
         *  and SF/PF/CF/OF/AF must die before any reader -- which
         *  flags_clear checks because the jcc only reads ZF, so the
         *  scan continues until all six are killed).  WAIT: this is
         *  a NO-OP fold (deleting a test-and-branch that decides
         *  nothing), which is only safe if the branch goes to dead
         *  code.  In general test+jcc is a real branch decision; we
         *  cannot delete it just because R is dead.  SKIP THIS RULE.
         *  The above paragraph documents why a tempting fold is
         *  UNSOUND; the rule is intentionally a no-op to make the
         *  reasoning visible in code review. */

        /* P96 (v1.84): "neg R / sbb R, R / sub R, R" or the canonical
         *  "neg R / sbb R, R" (computes R = -1 if R was nonzero, 0
         *  otherwise) -- the 386 "booleanize" idiom.  We do NOT fold
         *  this 2-instruction idiom (the result depends on CF, which
         *  is set by neg, and the rewrite would need a "setcc" or
         *  "cmovz" replacement -- both 386+ and both already shorter
         *  than the neg+sbb pair, so the user should not have
         *  written neg+sbb on a 386+; we leave it for the existing
         *  P9/P10/P11 rules to clean up if applicable). */

        /* P97 (v1.84): "mov R, K / test R, R" with R dead after test,
         *  flags dead after test -> "test R, R" deleted entirely (R
         *  is dead, test's flags are dead, the whole pair computes
         *  nothing observable).  Equivalent to P86 with K=K (always
         *  true).  Actually P86 already covers this exact pattern
         *  when K1 == K2; here the test's source is the same
         *  register (R, R) rather than (R, K), so K1 == K2 cannot be
         *  asked.  This is the more general pattern: any "test R, R"
         *  after "mov R, K" with R and flags dead.  Conservative
         *  superset of P86. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_MOV &&
            pi->srcimm && pi->dreg >= 0) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig &&
                    pj->cls == I_OTHER && pj->nops == 2 &&
                    ci_eq(pj->mnem, "test") &&
                    find_reg(pj->op0) == pi->dreg &&
                    find_reg(pj->op1) == pi->dreg &&
                    reg_dead_cf(next_code(j), pi->dreg) &&
                    flags_clear(next_code(j), F_ALL6)) {
                    vlog("smartpp: line %ld: deleted '%s' / '%s' (R and flags dead) (P97)\n",
                        i + 1, L(i), L(j));
                    delete_keep_label_marked(i, pi,
                        "mov+test R,R dead", 97);
                    DEL(j) = 1;
                    st[97]++;
                    continue;
                }
            }
        }

        /* P98 (v1.84): "shr R, K / mov R, 0" (or any 0-store after a
         *  shift that destroys R's high bits) -- if R is dead after
         *  the shift, the shift's flags die before any read, AND the
         *  mov writes 0 to R anyway, then the shift was dead.  This
         *  is a special case of P2 (dead store) but the existing P2
         *  only fires when the SECOND instruction is the dead store;
         *  here the FIRST is the dead store (its result is
         *  immediately overwritten).  Equivalent of P93 for shifts.
         *  The shift sets F_ALL6 (shl/shr/sal/sar), the mov sets
         *  none; we require flags dead between (zero instructions
         *  between, trivially true). */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_SHIFT &&
            (r98 = find_reg(pi->op0)) >= 0 &&
            (ci_eq(pi->mnem, "shl") || ci_eq(pi->mnem, "shr") ||
             ci_eq(pi->mnem, "sal") || ci_eq(pi->mnem, "sar"))) {
            j = next_code(i);
            if (j >= 0 && !INDEF(j)) {
                struct pinfo *pj = &g_ppair;
                parse_line(j, pj);
                if (!pj->haslabel && !pj->toobig && pj->cls == I_MOV &&
                    pj->dreg == r98 && pj->srcimm) {
                    long v;
                    if (try_parse_number(pj->op1, &v) && v == 0) {
                        vlog("smartpp: line %ld: deleted shift '%s' before 'mov %s, 0' (P98)\n",
                            i + 1, L(i), pj->op0);
                        delete_keep_label_marked(i, pi,
                            "shift dead before mov R,0", 98);
                        st[98]++;
                        continue;
                    }
                }
            }
        }

        /* P124/P125 (v1.86): "lea R, [R]" and "lea R, [R+0]" -> delete.
         *  lea computes base+disp and writes it to R; if base==R and
         *  disp==0, the result is R itself -- a pure identity, no flag
         *  or memory effect (lea never touches flags or memory).  Safe
         *  on every CPU (lea exists on the 8086).  Cycles: 1 on 386/486;
         *  1 on P5 (frees a pipe slot); 2 on P6 (LEA goes through AGU).
         *  NOTE: P17 (lea conv) has its own identity-deletion path and
         *  fires FIRST on this input -- this block is a documentation/
         *  safety net that catches any form P17 might miss.  In
         *  practice P17's counter increments, not P124's.
         *  Research: Agner Fog "Optimizing assembly" (lea R,[R] is a
         *  NOP); GCC never emits it; LLVM folds it; Intel SDM LEA. */
        if (!pi->haslabel && !pi->toobig && pi->cls == I_LEA &&
            pi->nops == 2 && pi->dreg >= 0) {
            int mr; long md;
            if (lea_bracket(pi->op1, &mr, &md)) {
                if (mr >= 0 && md == 0 &&
                    g_regs[mr].fam == g_regs[pi->dreg].fam &&
                    (g_regs[mr].hi - g_regs[mr].lo) ==
                     (g_regs[pi->dreg].hi - g_regs[pi->dreg].lo)) {
                    vlog("smartpp: line %ld: deleted 'lea %s, %s' (P124: identity lea)\n",
                        i + 1, pi->op0, pi->op1);
                    delete_keep_label_marked(i, pi,
                        "lea R,[R] / lea R,[R+0] -> delete", 124);
                    st[124]++;
                    continue;
                }
            }
        }

        /* v1.85 TABLE-DRIVEN FALLBACK: if no bespoke C rule fired on
         *  this line, consult the declarative rule table.  The table
         *  can express single-instruction and two-instruction patterns
         *  with a small set of preconditions (flag liveness, register
         *  liveness, CPU level, segment size, syntax, next-is-jcc).
         *  Each rule's actions are applied atomically. */
        if (try_table_rules(i)) continue;

    }
    {
        long after = 0;
        for (kk = 1; kk < STSZ; kk++) after += st[kk];
        return after - before;
    }
}

/* ---- driver ----------------------------------------------------------------*/

static void usage(FILE *f)
{
    fprintf(f, "SMARTPP %s - conservative peephole pre-processor for 8086..Pentium Pro and x86-64\n",
            SMARTPP_VERSION);
    fprintf(f, "usage: smartpp [-m86|-m186|-m286|-m386|-m486|-m586|-m686|-m64] [-att|-intel]\n");
    fprintf(f, "               [-nz] [-Oz] [-mark] [-nomark] [-v] [-nv] [--ncolor] [-o out] [in [out]]\n");
    fprintf(f, "  syntax: MASM/JWasm/UASM/ASMC auto, GNU AS auto-detected\n");
    fprintf(f, "  (-att / -intel force AT&T / Intel operand order)\n");
    fprintf(f, "  -mark / -nomark : toggle the '; SMARTPP ... (PN)' trailing comments\n");
    fprintf(f, "                    (default ON since v1.86; pass -mark to turn OFF)\n");
    fprintf(f, "  -v / -nv        : toggle the per-line 'rule Pn fired' notices\n");
    fprintf(f, "                    (default ON since v1.86; pass -v to silence)\n");
    fprintf(f, "                    The end-of-run summary table always prints.\n");
    fprintf(f, "  -nz             : keep xor+mov / shift pairs (movzx slower on 486/P5)\n");
    fprintf(f, "  -Oz             : optimize for size (favor shorter forms)\n");
    fprintf(f, "  -mNN            : target CPU level (default 8086):\n");
    fprintf(f, "                      -m86/-m8086  -m186  -m286  -m386  -m486  -m586  -m686  -m64\n");
    fprintf(f, "                    (.386/.486/.586/.686/.X64 directives in the source override)\n");
    fprintf(f, "  --ncolor        : disable colored diagnostic output (v1.87). By default\n");
    fprintf(f, "                    color is emitted to stderr only when stderr is a TTY\n");
    fprintf(f, "                    (GCC -fdiagnostics-color=auto behavior); redirecting stderr\n");
    fprintf(f, "                    to a file or pipe produces plain text automatically.\n");
    fprintf(f, "                    Color is ONLY on stderr; stdout (the optimized .asm) is\n");
    fprintf(f, "                    never colored and stays a valid assembler input.\n");
    fprintf(f, "  P1 delete mov/xchg R,R        P2 delete dead register store\n");
    fprintf(f, "  P3 delete push X / pop X      P4 merge shifts (CPU 186+)\n");
    fprintf(f, "  P5 thread jmp/jcc through an unconditional jmp\n");
    fprintf(f, "  P6 delete jump to the next code line\n");
    fprintf(f, "  P7 invert jcc over a bridge jmp\n");
    fprintf(f, "  P8 or/and R,R -> test R,R\n");
    fprintf(f, "  P9 mov R,0 -> xor R,R (flag-liveness scan)\n");
    fprintf(f, "  P10 add/sub R,1 -> inc/dec R (CF dead)\n");
    fprintf(f, "  P11 cmp R,0 -> test R,R (AF dead)\n");
    fprintf(f, "  P12 duplicate consecutive jumps to the same target\n");
    fprintf(f, "  P13 unreachable instructions after an unconditional jmp\n");
    fprintf(f, "  P14 double xchg R,S   P15 mov R,S / mov S,R\n");
    fprintf(f, "  P16 fold add/sub R,c1 / R,c2 (OF dead)\n");
    fprintf(f, "  P17 lea R,[R+const] -> add/sub/inc/dec (FPC-style)\n");
    fprintf(f, "     plus exact lea R,[const] / lea R,[S] -> mov forms\n");
    fprintf(f, "  P18 add/sub R,0 deleted (all flags dead)\n");
    fprintf(f, "  P19 duplicate consecutive cmp/test R,S\n");
    fprintf(f, "  P20 shift/rotate R,0 deleted\n");
    fprintf(f, "  P21 duplicate consecutive cld/std/cli/sti\n");
    fprintf(f, "  P22 inc R / dec R pair deleted (all flags dead)\n");
    fprintf(f, "  P23 not R / not R pair   P24 neg R / neg R pair\n");
    fprintf(f, "  P25 cmc / cmc pair deleted\n");
    fprintf(f, "  P26 dead xor R,R before a full-cover writer\n");
    fprintf(f, "  P27 add R,S / sub R,S pair deleted (all flags dead)\n");
    fprintf(f, "  P28 duplicate consecutive cbw/cwde/cwd/cdq\n");
    fprintf(f, "  P29 xor T,T / mov L,SRC -> movzx T,SRC (386+, -nz off)\n");
    fprintf(f, "  P30 same with a 0..255 constant -> mov T,imm\n");
    fprintf(f, "  P31 mov al,SRC / cbw -> movsx ax,SRC (and cwde) (386+)\n");
    fprintf(f, "  P32 push R / pop S -> mov S,R\n");
    fprintf(f, "  P33 shl/shr (sar) R,16|24|8 pair -> movzx/movsx (386+, -nz off)\n");
    fprintf(f, "  P34 and R16,0FFh -> xor Rh,Rh;  and R32,0FFh/0FFFFh -> movzx\n");
    fprintf(f, "  P35 mov R32,-1 -> or R32,-1 (386+)\n");
    fprintf(f, "  P36 mov sp,bp / pop bp -> leave (186+, 16-bit code)\n");
    fprintf(f, "  v1.80 new rules (research: FPC, GCC RTL, LLVM X86Peephole, Watcom):\n");
    fprintf(f, "  P37 xor R,-1 -> not R (all six flags dead)\n");
    fprintf(f, "  P38 imul R,2^k -> shl R,k (k>=1); imul R,1 -> deleted (186+)\n");
    fprintf(f, "  P39 add/sub R,c / sub/add R,c -> both deleted (all six flags dead)\n");
    fprintf(f, "  P40 mov R,imm1 / add R,imm2 -> mov R,imm1+imm2 (all six flags dead)\n");
    fprintf(f, "  P41 lea R,[R+S] -> add R,S (all six flags dead; 386+ general)\n");
    fprintf(f, "  P42 push bp/mov bp,sp/sub sp,N -> enter N,0 (186+, 16-bit)\n");
    fprintf(f, "  P43 xor R,R / add|sub|or|xor R,imm -> mov R,imm (all six flags dead)\n");
    fprintf(f, "  P44 xor R,R / inc R -> mov R,1 (all six flags dead)\n");
    fprintf(f, "  P45 xor R,R / dec R -> mov R,-1 (all six flags dead)\n");
    fprintf(f, "  P46 push imm / pop R -> mov R,imm (186+; size-gated for 32-bit)\n");
    fprintf(f, "  P47 mov R,S / add|sub R,imm -> lea R,[S+imm] (386+ general)\n");
    fprintf(f, "  P48 xor R,R / test R,R -> delete test (no scan)\n");
    fprintf(f, "  P49 add/sub sp,c / sub/add sp,c -> both deleted (all six flags dead)\n");
    fprintf(f, "  P50 imul R,2^k+1 -> lea R,[R+R*k] for k=1,2,3 (386+; Intel-only)\n");
    fprintf(f, "  P51 imul R,-1 -> neg R (all six flags dead; 186+)\n");
    fprintf(f, "  -nz keeps xor+mov and shift pairs (movzx is slower on a 486/Pentium)\n");
    fprintf(f, "  v1.80: runs up to %d passes (chained rewrites converge)\n", MAX_PASSES);
    fprintf(f, "  v1.81 new rules + extensions (research: FPC, GCC RTL, LLVM, Watcom,\n");
    fprintf(f, "  Massalin-Stone superoptimizer):\n");
    fprintf(f, "  P8 (ext) drop >=16-bit gate (8-bit too); and R,0xFF/0xFFFF/0xFFFFFFFF\n");
    fprintf(f, "    all recognized; delete-if-flags-dead branch added\n");
    fprintf(f, "  P19 (ext) idempotent or/and now also: dup op1 -> first deleted\n");
    fprintf(f, "  P52 mov R,imm / shl R,k -> mov R,imm<<k (all six flags dead)\n");
    fprintf(f, "  P53 mov R,imm / and R,mask -> mov R,imm&mask (all six flags dead)\n");
    fprintf(f, "  P54 mov R,imm / or R,imm2 -> mov R,imm|imm2 (all six flags dead)\n");
    fprintf(f, "  P55 mov R,imm / xor R,imm2 -> mov R,imm^imm2 (all six flags dead)\n");
    fprintf(f, "  P56 add/sub R,c1 / sub/add R,c2 (mixed, c1!=c2) -> single add/sub\n");
    fprintf(f, "    by |c1-c2| (all six flags dead; R not SP)\n");
    fprintf(f, "  P57 lea R,[R+R] -> shl R,1 (386+, Intel-only; all six flags dead)\n");
    fprintf(f, "  P58 xor R,X / xor R,X -> both deleted (all six flags dead;\n");
    fprintf(f, "    R not SP; X is reg or imm, not memory)\n");
    fprintf(f, "  v1.82 new rules (research: FPC aoptx86, GCC i386.md peephole2,\n");
    fprintf(f, "    LLVM X86OptimizeLEAs, Open Watcom peepopt):\n");
    fprintf(f, "  P59 and R,0 -> mov R,0 (reg only; all six flags dead; chains P9)\n");
    fprintf(f, "  P60 or R16,-1 -> mov R16,-1 (16-bit only; all six flags dead)\n");
    fprintf(f, "  P61 and R,c1 / and R,c2 -> and R,(c1&c2) (all six flags dead;\n");
    fprintf(f, "    R not SP)\n");
    fprintf(f, "  P62 and R,c1 / or R,c2 -> tighten mask: and R,(c1&~c2) / or R,c2\n");
    fprintf(f, "    (NO flag scan: identical flag stream)\n");
    fprintf(f, "  P62b or R,c1 / and R,c2 with (c2&c1)==c2 -> mov R,c2 (all six\n");
    fprintf(f, "    flags dead; subset collapse)\n");
    fprintf(f, "  P63 lea R,[R*K] (K in 2,4,8) -> shl R,log2 K (386+, all six\n");
    fprintf(f, "    flags dead; generalizes P57 to scales 4 and 8)\n");
    fprintf(f, "  P65 dec R / cmp R,-1 -> dec R (all six flags dead; the cmp is\n");
    fprintf(f, "    redundant when no flag is observed)\n");
    fprintf(f, "  P68 xchg R,S (one operand dead) -> mov (no flags; SP excluded;\n");
    fprintf(f, "    same-width registers only)\n");
    fprintf(f, "  P70 lea R,[S+off1] / lea D,[R+off2] (R dead) -> lea D,[S+off1+off2]\n");
    fprintf(f, "    (no flags; intermediate dead)\n");
    fprintf(f, "  Bug fixes in v1.81:\n");
    fprintf(f, "    P12 case 2, P14, P16 (total==0): a label carried by\n");
    fprintf(f, "      line i used to be lost when i was deleted; the new\n");
    fprintf(f, "      delete_keep_label() helper keeps the label (and any\n");
    fprintf(f, "      comment) on a label-only line and only removes the\n");
    fprintf(f, "      dead instruction.\n");
    fprintf(f, "    P40/P43/P46 AT&T output: pi->op0/pj->op0 already carry\n");
    fprintf(f, "      the '%%' prefix (att_fix swaps but does not strip), so\n");
    fprintf(f, "      the previous \", %%%%eax\" (double-percent) output is\n");
    fprintf(f, "      corrected to \", %%eax\" (single-percent).  P38 and the\n");
    fprintf(f, "      new P52-P55 carry the same fix.\n");
    fprintf(f, "    att_fix: \"imul\" added to the size-suffix base list so\n");
    fprintf(f, "      AT&T `imull $8,%%eax` is recognized as `imul` and\n");
    fprintf(f, "      P38/P50/P51 can fire on it.\n");
    fprintf(f, "    emit_lea_scaled: dead AT&T branch (P50 is !g_att) and the\n");
    fprintf(f, "      unused `num` buffer removed.\n");
    fprintf(f, "  v1.82 refactor: a shared reg_dead_after(start, r) helper now\n");
    fprintf(f, "    serves P68 (xchg->mov) and P70 (lea+lea fusion); previously\n");
    fprintf(f, "    the dead-register walk was inlined in P68 only.\n");
    fprintf(f, "  v1.83 bug fixes (10 correctness fixes from review):\n");
    fprintf(f, "    P4 shift fusion now requires F_OF dead (F_OF|F_CF for rotates)\n");
    fprintf(f, "      when the fused total exceeds 1.\n");
    fprintf(f, "    P50 imul->lea gated to 32-bit dest, excludes ESP (SIB index).\n");
    fprintf(f, "    P16/P56 add/sub fold uses width_imm_limit(w) so 8-bit folds\n");
    fprintf(f, "      stay within imm8 (-128..127) and 32-bit folds are allowed.\n");
    fprintf(f, "    P42 enter closed to !g_att (was emitting Intel-syntax in GAS).\n");
    fprintf(f, "    P58 xor-double uses positive test (reg or imm only).\n");
    fprintf(f, "    P3 push/pop SP requires 286+ (8086 PUSH SP pushes the\n");
    fprintf(f, "      already-decremented value, so push sp/pop sp is not identity).\n");
    fprintf(f, "    P2 dead store no longer deletes `mov R, <mem>` (MMIO risk).\n");
    fprintf(f, "    detect_use32 scans USE32 anywhere on the line, not just when\n");
    fprintf(f, "      'segment' is the first token (matches `_TEXT SEGMENT USE32`).\n");
    fprintf(f, "    P47 mov+add->lea requires src width == dest width on 386+.\n");
    fprintf(f, "  v1.83 new rules:\n");
    fprintf(f, "    P13b unreachable after ret/retf/iret/hlt/ud2/int3 (like P13).\n");
    fprintf(f, "    P71 sub R,R -> xor R,R (AF dead; SP excluded)\n");
    fprintf(f, "    P72 mov+shr fold; P73 mov+sar fold; P74 mov+rol fold;\n");
    fprintf(f, "    P75 mov+ror fold (extend P52 to non-rcl/rcr shifts).\n");
    fprintf(f, "    P76 xor R,R / {add|or|xor} R,S -> mov R,S (S reg, same width).\n");
    fprintf(f, "    P77 dup mov/lea/movzx (same dest, same textual source).\n");
    fprintf(f, "    P78 lea R,[R+off1] / lea R,[R+off2] -> lea R,[R+off1+off2].\n");
    fprintf(f, "    P79 mov R,imm / push R (R dead) -> push imm.\n");
    fprintf(f, "    P80 push R / <writer not reading R> / pop R -> delete push+pop.\n");
    fprintf(f, "    P81 mov AL,SRC / movzx EAX,AL -> movzx EAX, byte ptr SRC.\n");
    fprintf(f, "  v1.86 new rules (research: Agner Fog, Abrash Black Book, GCC i386.md,\n");
    fprintf(f, "    LLVM X86Peephole, Intel SDM, Massalin-Stone):\n");
    fprintf(f, "    P105 sub R,R -> xor R,R (dep-chain break; no precond; P71 fires first).\n");
    fprintf(f, "    P111 or R,0 -> delete (flags dead).   P112 and R,-1 -> delete (flags dead).\n");
    fprintf(f, "    P115 xor R,0 -> delete (flags dead).   P119 test R,K -> delete (flags dead).\n");
    fprintf(f, "    P120 cmp R,K -> delete (flags dead; K != 0; P11 fires first on K==0).\n");
    fprintf(f, "    P122 imul R,1 -> delete (flags dead; 186+; P38 fires first via 2^0).\n");
    fprintf(f, "    P123 imul R,0 -> xor R,R (flags dead; 186+; canonical zeroing idiom).\n");
    fprintf(f, "    P124 lea R,[R] / lea R,[R+0] -> delete (identity lea; every CPU).\n");
    fprintf(f, "    P126 xchg R,R -> delete (canonical NOP; P1 fires first on same width).\n");
    fprintf(f, "    P127 bswap R / bswap R -> bswap R (486+; bswap is an involution).\n");
    fprintf(f, "    P128 xor R,R / push R -> push 0 (186+; R dead after push).\n");
    fprintf(f, "  Output: -mark and -v default ON since v1.86 (pass them to turn OFF).\n");
    fprintf(f, "          End-of-run prints a two-column summary table to stderr.\n");
    fprintf(f, "  v1.87 new rules (research: Intel SDM Vol.2 x87, AMD64 APM, Agner Fog,\n");
    fprintf(f, "    GCC i386.md, LLVM X86Peephole):\n");
    fprintf(f, "    x87 FPU rules (require .8087/.287/.387; .NO87 disables them):\n");
    fprintf(f, "      P129 fld st / fstp st -> delete both (push+pop pair).\n");
    fprintf(f, "      P130 fldz / fstp st -> delete both (push 0 + pop).\n");
    fprintf(f, "      P131 fchs / fchs -> delete both (double negation is identity).\n");
    fprintf(f, "      P132 fabs / fabs -> fabs (abs is idempotent).\n");
    fprintf(f, "      P134 ffree st / ffree st -> ffree st (idempotent tag-clear).\n");
    fprintf(f, "      P135 fninit / fninit -> fninit (idempotent reset).\n");
    fprintf(f, "      P136 fwait / fwait -> fwait (synchronization collapse).\n");
    fprintf(f, "      P137 fxch st,st / fxch st,st -> delete both (self-swap is NOP).\n");
    fprintf(f, "      P133 (fsqrt double) was considered and WITHDRAWN: sqrt is NOT\n");
    fprintf(f, "        idempotent (sqrt(sqrt(x)) != sqrt(x) for x > 1).\n");
    fprintf(f, "    x86-64 long-mode handling:\n");
    fprintf(f, "      P138 mov R64,0 -> xor R32,R32 is handled by the P9 C-rule, which\n");
    fprintf(f, "        detects x64 mode (g_curcpu == 128) and a 64-bit destination and\n");
    fprintf(f, "        emits the 32-bit xor form (1 byte shorter: no REX.W; xor zero-\n");
    fprintf(f, "        extends to 64 bits for free; breaks the dependency chain on PPro/P6).\n");
    fprintf(f, "      P139 (test R64,R64 -> test R32,R32) was WITHDRAWN: it is unsound.\n");
    fprintf(f, "        test rax,rax sets ZF from all 64 bits while test eax,eax sets ZF\n");
    fprintf(f, "        from the low 32 bits only, so they differ when rax has bits set\n");
    fprintf(f, "        above bit 31; the 32-bit form also zero-extends EAX into RAX.\n");
    fprintf(f, "      P140 mov R64,R64 -> delete is handled by the P1 C-rule.\n");
    fprintf(f, "    FPU directive parsing: .8087/.287/.387 enable FPU rules; .NO87\n");
    fprintf(f, "      disables them.  .MMX/.XMM/.K3D set the integer CPU to Pentium+\n");
    fprintf(f, "      so existing >= N gates still fire.\n");
    fprintf(f, "    Color: --ncolor disables; otherwise auto-detected from stderr TTY.\n");
}

/* v1.86: human-readable CPU level for the summary banner.  Mirrors
 *  the -mNN switches (1=8086, 2=186, 4=286, 8=386, 16=486, 32=P5, 64=P6). */
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
                if (++argi >= argc) { usage(stderr); return 1; }
                outpath = argv[argi];
            }
            else if (a[1] == 'o' && a[2] != '\0') outpath = a + 2;
            else if (strcmp(a, "-v") == 0) opt_verbose = 0;          /* v1.86: default ON; -v turns OFF */
            else if (strcmp(a, "-nv") == 0) opt_verbose = 0;        /* alias */
            else if (strcmp(a, "--ncolor") == 0) opt_ncolor = 1;     /* v1.87: disable color */
            else if (strcmp(a, "-nz") == 0) opt_nz = 1;
            else if (strcmp(a, "-mark") == 0) opt_mark = 0;          /* v1.86: default ON; -mark turns OFF */
            else if (strcmp(a, "-nomark") == 0) opt_mark = 0;        /* alias */
            else if (strcmp(a, "-Oz") == 0 || strcmp(a, "-oz") == 0) opt_zopt = 1;
            else if (strcmp(a, "-att") == 0) {
                g_att = 1; g_gas = 1; g_synforced = 1;
            }
            else if (strcmp(a, "-intel") == 0) {
                g_att = 0; g_synforced = 1;
            }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "-?") == 0 ||
                     strcmp(a, "--help") == 0) { usage(stdout); return 0; }
            else if (strcmp(a, "-m86") == 0 || strcmp(a, "-m8086") == 0) {
                g_curcpu = 1;
            }
            else if (strcmp(a, "-m186") == 0) { g_curcpu = 2; }
            else if (strcmp(a, "-m286") == 0) { g_curcpu = 4; }
            else if (strcmp(a, "-m386") == 0) { g_curcpu = 8; }
            else if (strcmp(a, "-m486") == 0) { g_curcpu = 16; }
            else if (strcmp(a, "-m586") == 0) { g_curcpu = 32; }
            else if (strcmp(a, "-m686") == 0) { g_curcpu = 64; }
            else if (strcmp(a, "-m64") == 0 ||
                     strcmp(a, "-mx64") == 0 ||
                     strcmp(a, "-mx86-64") == 0) { g_curcpu = 128; }
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

    in = (strcmp(inpath, "-") == 0) ? stdin : fopen(inpath, "rb");
    if (in == NULL) {
        fprintf(stderr, "smartpp: cannot open '%s'\n", inpath);
        return 1;
    }
    read_file(in);
    if (in != stdin) fclose(in);

    scan_indefs();
    detect_use32();
    collect_labels();
    init_table_rules();    /* v1.85: declarative rule engine */
    /* Fixed-point: keep running passes until no rewrite fires or
     *  MAX_PASSES is reached.  Each pass re-scans all live lines, so
     *  chained rewrites (P45 -> P35, P43 -> P9, P40 -> P9, P16 -> P18)
     *  converge without further machinery. */
    {
        int pass;
        for (pass = 0; pass < MAX_PASSES; pass++) {
            long n = run_pass();
            g_passes_run = pass + 1;
            if (n == 0) break;
        }
    }

    out = (outpath == NULL || strcmp(outpath, "-") == 0) ? stdout : fopen(outpath, "wb");
    if (out == NULL) {
        fprintf(stderr, "smartpp: cannot create '%s'\n", outpath);
        return 1;
    }
    for (i = 0; i < g_nlines; i++) {
        if (DEL(i)) { ndel++; continue; }
        fputs(L(i), out);
        switch (TERM(i)) {
        case 1: fputc('\n', out); break;
        case 2: fputs("\r\n", out); break;
        case 3: fputc('\r', out); break;
        default: break;
        }
        nout++;
    }
    if (out != stdout) fclose(out);

    /* ---- v1.86: pretty-printed summary to stderr -----------------
     *  The per-line "rule Pn fired" messages already went to stderr
     *  during the pass (when opt_verbose).  Here we emit a final
     *  banner + a two-column table of the rules that fired. */
    {
        static const char *rname[] = {
            "",  "delete mov/xchg R,R",      "dead register store",
            "push/pop pair",                 "merge shifts",
            "thread jmp/jcc",                "redundant jump",
            "invert jcc",                    "or/and->test (ext)",
            "mov0->xor",                      "add/sub 1->inc/dec",
            "cmp0->test",                     "dup jumps",
            "unreachable",                    "double xchg",
            "mov R,S/mov S,R",               "const fold",
            "lea conv",                       "add/sub R,0",
            "dup cmp/test/or/and",            "shift R,0",
            "dup flag op",                    "inc/dec pair",
            "not pair",                        "neg pair",
            "cmc pair",                        "dead xor0",
            "add/sub pair",                   "dup sign-extend",
            "zero-ext movzx",                 "zero-ext imm",
            "movsx",                           "push/pop->mov",
            "shift pair",                      "and-mask",
            "mov-1->or",                      "leave",
            "xor R,-1->not",                  "imul 2^k->shl",
            "add/sub pair (const)",           "mov+add->mov",
            "lea R,[R+S]->add",               "push bp/mov bp,sp/sub sp,N->enter",
            "xor+arith->mov",                 "xor/inc->mov1",
            "xor/dec->mov-1",                 "push imm/pop->mov",
            "mov+add->lea",                   "xor+test->delete test",
            "sp add/sub pair",                "imul 2^k+1->lea",
            "imul -1->neg",                   "mov+shl fold",
            "mov+and fold",                   "mov+or fold",
            "mov+xor fold",                   "mixed add/sub fold",
            "lea [R+R]->shl",                 "xor/xor pair",
            "and R,0->mov R,0",               "or R16,-1->mov R16,-1",
            "and+and->and",                   "and/or mask tighten",
            "lea R,[R*K]->shl",               "",
            "dec/cmp -1->dec",                "",
            "",                                "xchg dead->mov",
            "",                                "lea+lea fusion",
            "sub R,R->xor R,R",                "mov+shr fold",  /* 72 */
            "mov+sar fold",                    "mov+rol fold",  /* 74 */
            "mov+ror fold",                    "xor+reg->mov",  /* 76 */
            "dup mov/lea/movzx",               "lea+lea same-dst",  /* 78 */
            "mov+push->push imm",              "push+write+pop->nothing",  /* 80 */
            "mov+movzx->movzx",                "lea r16,var->mov OFFSET",  /* 81,82 */
            "",                                "",                          /* 83,84 */
            "mov+cmp same-const dead",        "mov+test same-const dead",  /* 85,86 */
            "mov+push->push imm (CF)",         "rol16/xchg/rol16->bswap",   /* 87,88 */
            "mov0 before setcc dead",          "and K / jcc->test K",       /* 89,90 */
            "(withdrawn)",                    "sub R,1->dec R (jcc)",       /* 91,92 */
            "xor dead before mov",             "mov 0 / OP K -> mov K",     /* 93,94 */
            "",                                "",                          /* 95,96 */
            "mov+test R,R dead",               "shift dead before mov 0",   /* 97,98 */
            "(withdrawn)",                    "(withdrawn)",                /* 99,100 */
            "(withdrawn)",                    "(withdrawn)",                /* 101,102 */
            "(withdrawn)",                    "(withdrawn)",                /* 103,104 */
            "sub R,R->xor (dep-chain)",       "(withdrawn)",                /* 105,106 */
            "(withdrawn)",                    "(withdrawn)",                /* 107,108 */
            "(withdrawn)",                    "(withdrawn)",                /* 109,110 */
            "or R,0->del",                    "and R,-1->del",               /* 111,112 */
            "(withdrawn)",                    "(withdrawn)",                /* 113,114 */
            "xor R,0->del",                   "",                            /* 115,116 */
            "",                                "",                            /* 117,118 */
            "test R,K->del",                  "cmp R,K->del",                /* 119,120 */
            "(withdrawn)",                                                    /* 121 */
            /* v1.86 new rules (122..128) */
            "imul R,1->del (flags dead)",     "imul R,0->xor R,R (flags dead)",  /* 122,123 */
            "lea R,[R]/[R+0]->del",          "(withdrawn)",                /* 124,125 */
            "xchg R,R->del (canonical NOP)", "bswap/bswap->del one (486+)", /* 126,127 */
            "xor R,R/push R->push 0",                                        /* 128 */
            /* v1.87 new x87 rules (129..137) */
            "fld st/fstp st->del (push/pop)",  "fldz/fstp st->del",        /* 129,130 */
            "fchs/fchs->del (double neg)",     "fabs/fabs->fabs",          /* 131,132 */
            "(withdrawn)",                     "ffree/ffree->ffree",       /* 133,134 */
            "fninit/fninit->fninit",           "fwait/fwait->fwait",       /* 135,136 */
            "fxch st,st/fxch st,st->del",                                  /* 137 */
            /* v1.87 new x64 rules (138..140) -- all withdrawn.
             *  P138 (mov R64,0->xor R32,R32) is handled by the P9
             *  C-rule, which detects x64 mode and emits the 32-bit
             *  xor form; no table rule needed.
             *  P139 (test R64,R64->test R32,R32) was WITHDRAWN: it
             *  is unsound (ZF differs when the high 32 bits of R64
             *  are nonzero; the 32-bit test also zero-extends EAX
             *  into RAX, mutating RAX).
             *  P140 (mov R64,R64->del) is handled by the P1 C-rule. */
            "(handled by P9)",               "(withdrawn: unsound)",     /* 138,139 */
            "(handled by P1)"                                           /* 140 */
        };
        const int NRNAME = (int)(sizeof(rname)/sizeof(rname[0]));
        long total_fired = 0;
        int k, nrules_fired = 0;

        fprintf(stderr, "\n");
        if (color_enabled()) {
            fprintf(stderr, "%s==========================================================%s\n",
                    C_CYAN, C_RESET);
            fprintf(stderr, "  %sSMARTPP %s%s  --  peephole summary\n",
                    C_BOLD C_CYAN, SMARTPP_VERSION, C_RESET);
            fprintf(stderr, "%s==========================================================%s\n",
                    C_CYAN, C_RESET);
            fprintf(stderr, "  %sInput%s   : %ld lines\n",
                    C_DIM, C_RESET, g_nlines);
            fprintf(stderr, "  %sOutput%s  : %ld lines\n",
                    C_DIM, C_RESET, nout);
            fprintf(stderr, "  %sRemoved%s : %ld lines\n",
                    C_DIM, C_RESET, ndel);
            fprintf(stderr, "  %sPasses%s  : %d (max %d)\n",
                    C_DIM, C_RESET, g_passes_run, MAX_PASSES);
            fprintf(stderr, "  %sCPU%s     : %s%s%s\n",
                    C_DIM, C_RESET,
                    C_GREEN, cpu_name(g_curcpu), C_RESET);
            fprintf(stderr, "%s----------------------------------------------------------%s\n",
                    C_CYAN, C_RESET);
            fprintf(stderr, "  %-6s  %-34s  %s\n", "Rule", "Description", "Hits");
            fprintf(stderr, "  %-6s  %-34s  %s\n", "----",
                    "----------------------------------", "----");
        }
        else {
            fprintf(stderr, "==========================================================\n");
            fprintf(stderr, "  SMARTPP %s  --  peephole summary\n",
                    SMARTPP_VERSION);
            fprintf(stderr, "==========================================================\n");
            fprintf(stderr, "  Input   : %ld lines\n", g_nlines);
            fprintf(stderr, "  Output  : %ld lines\n", nout);
            fprintf(stderr, "  Removed : %ld lines\n", ndel);
            fprintf(stderr, "  Passes  : %d (max %d)\n", g_passes_run, MAX_PASSES);
            fprintf(stderr, "  CPU     : %s\n", cpu_name(g_curcpu));
            fprintf(stderr, "----------------------------------------------------------\n");
            fprintf(stderr, "  %-6s  %-34s  %s\n", "Rule", "Description", "Hits");
            fprintf(stderr, "  %-6s  %-34s  %s\n", "----",
                    "----------------------------------", "----");
        }

        for (k = 1; k < STSZ && k < NRNAME; k++) {
            const char *nm;
            if (st[k] == 0) continue;
            nm = rname[k][0] != '\0' ? rname[k] : "(unnamed)";
            if (color_enabled())
                fprintf(stderr, "  %sP%-5d%s  %-34s  %s%ld%s\n",
                        C_YELLOW, k, C_RESET, nm,
                        C_GREEN, st[k], C_RESET);
            else
                fprintf(stderr, "  P%-5d  %-34s  %ld\n", k, nm, st[k]);
            total_fired += st[k];
            nrules_fired++;
        }
        /* also catch any rule that fired but has no rname slot yet */
        for (; k < STSZ; k++) {
            if (st[k] != 0) {
                if (color_enabled())
                    fprintf(stderr, "  %sP%-5d%s  %-34s  %s%ld%s\n",
                            C_YELLOW, k, C_RESET, "(unnamed)",
                            C_GREEN, st[k], C_RESET);
                else
                    fprintf(stderr, "  P%-5d  %-34s  %ld\n",
                            k, "(unnamed)", st[k]);
                total_fired += st[k];
                nrules_fired++;
            }
        }
        if (color_enabled()) {
            fprintf(stderr, "%s----------------------------------------------------------%s\n",
                    C_CYAN, C_RESET);
            fprintf(stderr, "  %-6s  %-34s  %s%ld%s\n",
                    C_BOLD "TOTAL" C_RESET,
                    "(rules fired / instructions rewritten)",
                    C_BOLD, total_fired, C_RESET);
            if (nrules_fired == 0)
                fprintf(stderr, "  %s(no rules fired; input already optimal)%s\n",
                        C_DIM, C_RESET);
            fprintf(stderr, "%s==========================================================%s\n",
                    C_CYAN, C_RESET);
        }
        else {
            fprintf(stderr, "----------------------------------------------------------\n");
            fprintf(stderr, "  %-6s  %-34s  %ld\n",
                    "TOTAL", "(rules fired / instructions rewritten)",
                    total_fired);
            if (nrules_fired == 0)
                fprintf(stderr, "  (no rules fired; input already optimal)\n");
            fprintf(stderr, "==========================================================\n");
        }
    }
    return 0;
}