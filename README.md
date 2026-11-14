# SMART.INC & SMARTPP

**Copyright (c) Javier Gutiérrez Chamorro (Guti)**

Two complementary tools for classic x86 assembly (8086 through 386+, with limited x86-64 and x87 support):

| Component | Role |
| --- | --- |
| **[SMART.INC](SMART.INC)** | Include file: macros that rewrite instructions *at assembly time* inside a macro expansion. |
| **[SMARTPP.C](SMARTPP.C)** | External one-file C tool: reads `.asm` source (following INCLUDE), applies provably-safe peephole rewrites *across* consecutive instructions, writes the result. |

Target assemblers for SMART.INC: **[ASMC](https://github.com/nidud/asmc)**, **JWasm**, **UASM**.
SMARTPP also accepts GNU AS / AT&T syntax (`-att`).

---

## SMARTPP

### What it is

SMARTPP is a **conservative peephole pre-processor**. It is not a compiler backend: it only rewrites sequences that are **provably equivalent** under explicit flag/register liveness and CPU gates. If a transform could change observable behaviour (flags, SP interrupt window, MMIO, far jumps), it is refused.

Typical use:

```sh
gcc -O2 -o smartpp SMARTPP.C
# or: wcl386 -w3 -oneatx ... SMARTPP.C
smartpp -m386 -o out.asm in.asm
smartpp -m86 -Oz -v -o out.asm in.asm
```

### Options

| Option | Meaning |
| --- | --- |
| `-m86` ... `-m686` / `-m64` | Initial CPU level (default 8086). Source directives may raise or lower it. |
| `-att` / `-intel` | Force AT&T or Intel syntax. |
| `-I DIR` | Include search path (repeatable). |
| `-noinclude` | Do not expand INCLUDE. |
| `-Os` / `-Oz` | Prefer speed (default) or size. |
| `-Ox` | Aggressive folds that are **not** 100% safe (warned under `-w`). |
| `-mark` / `-nomark` | Leave rewrite markers as comments in output (default: on). |
| `-v` / `-nv` | Per-line rule notices on stderr (use `-v` when auditing). |
| `-w` / `-nw` | Warnings (CPU directives, `-Ox` rules, ...). Default: **on**. |
| `-color` / `-ncolor` | Colored diagnostics on/off. |
| `-o FILE` | Output file (`-` = stdout). |

### INCLUDE handling

INCLUDE / include / .include are **expanded by default**. Search order: directory of the including file, then `-I` paths, then CWD. Missing files warn and leave the directive. Expanded regions are marked with SMARTPP include begin/end comments. Cycles are detected.

### How the engine works

1. **Load** the source (and includes) into a line store.
2. **Scan** labels, USE16/USE32, CPU directives, .NO87.
3. **Multi-pass** (max 4): for each live line, run **bespoke C rules** in `run_pass`, then the **table-driven** rule engine.
4. Stop a pass when no rule fires; stop overall when a pass is idle or the pass limit is hit.
5. Print a **summary** (rules and hit counts), then write the output.

**Table rules** (`g_rule_tbl[]`) match 1-4 instruction patterns with operand captures, preconditions (flags dead, register dead, CPU level, `-Oz` only, ...), and actions (delete / rewrite template).
**C rules** handle control flow, multi-path liveness, cost models, and patterns that do not fit the table cleanly.

### Safety model

- Flag-gated rewrites use a path-sensitive walk (`flags_clear` / `reg_dead_cf`). ret/retf kill status flags (ABI).
- Transforms that replace a flag-setting instruction with a non-setter (e.g. loop, jcxz) require flags dead on **both** the fall-through and the branch target (`flags_dead_after_jcc`).
- SP/ESP/RSP is excluded from several pair-deletes (interrupt window between two short ops).
- Memory that might be MMIO is treated conservatively.
- Short-only encodings (loop, jcxz, jecxz) assume near targets in range (same assumption as classic DOS tools).

### Rule families (catalogue)

**Identity / redundancy:** P1 mov/xchg R,R delete; P3 push/pop same; P8 or/and identity; P14 double xchg; P15 mov swap; P18 add/sub 0; P20 shift 0; P21 duplicate cld/std/cli/sti/clc/stc; P22 inc/dec cancel; P23-P25 not/neg/cmc pairs; P28 duplicate cbw/cwd/cdq; P58 double xor.

**Strength reduction:** P9 mov0->xor; P10 add/sub +/-1 -> inc/dec; P11 cmp0->test; P17 lea->[add/sub]; P32 push/pop->mov; P35 mov-1->or; P36 leave (186+); P37 xor-1->not; P38/P149 imul power2->shl; P50/P380 imul LEA tree; P51 imul-1->neg; P59 and0->mov0; P71 sub R,R->xor; P141-P142 not/inc <-> neg/dec; P143/P450 add R,R->shl 1.

**Constant folding:** P16 combined add/sub imm; P40 mov+add/sub; P52-P55/P72-P75 mov+shift/logic; P144-P145 mov+not/neg.

**Control flow:** P5 multi-hop jmp thread; P6 jmp to next; P7 jcc/jmp invert; P12 duplicate jumps; P13 dead after jmp/ret.

**Widening (386+):** P29-P31 movzx/movsx idioms; P33-P34 and/shift zero-extend; P757 and mask->movzx.

**Size (`-Oz`):** P427 dec cx/jnz->loop (not jz); P850 jcxz; P851 jecxz (386+); P830-P832 cdq/cwd zeroing.

**Bit ops (386+):** P852 bt/jcc->test/jcc; P854 bts/btr pair->or/and.

**Other:** P47/P812-P813 mov+inc/dec->lea; P48/P802-P808 redundant test after ALU; P496-P497 add/sub 2->inc/inc (pre-386); P480-P481 reverse (386+, not -Oz); P511 stack store forward; P531-P534 stack/LEA/push-mov-pop; P750-P757 copy-prop, zero+branch, empty frame, LEAx3, cmp R,R, x87, and->movzx; P800 byte pair->word mov; P801 sar31->cdq; P853 x64 xor r32 zeroing.

### Build notes (portability)

| Toolchain | Stack / notes |
| --- | --- |
| **Watcom** | `unsigned _STACKSIZE = 2MiB` (flat); `stackavail()` guard; keep MAXLINE temps off the stack (g_tmpa/g_tmpb / heap). |
| **MSVC** | `#pragma comment(linker, "/STACK:2097152")`. |
| **GCC/MinGW** | `-Wl,--stack,2097152` on Windows; Unix stacks usually large enough. |

```sh
gcc -O2 -Wall -o smartpp SMARTPP.C
```

### Adding a table rule (sketch)

```c
{ 1, 146,
  { { "shl", 0, RR_('a'), IV_(0), 2 } },
  0,
  { { ACT_DEL, NULL } },
  "shl R,0 -> delete", NULL },
```

Operand macros: RR_('a'), SM_('a'), DF_('a'), IM_, IV_(n), PW2_, AN_.
Preconditions: PRE_FLAGS_DEAD_ALL, PRE_REG_DEAD_RA, PRE_CPU_386, PRE_OZ, PRE_NOT_SP, ...
Templates: $a, $K, $Knot, $Kneg, $Klog2, ...

Keep multi-path control flow and deep liveness in **C** (`run_pass`).

---

## SMART.INC

### What it is

SMART.INC is a **macro library** that renames selected mnemonics (OPTION RENAMEKEYWORD) and re-implements them so that:

- Constant shifts work on the **8086** (hardware only allows 1 or CL).
- movzx / movsx are emulated below the **386**.
- Multi-operand push/pop, bit helpers, and fast constant multiplies are available.
- Under **SMART** mode (default), redundant mov/xchg, short lea->mov OFFSET, and short conditional jumps are rewritten automatically.

**Requirements:** ASMC, JWasm, or UASM with OPTION RENAMEKEYWORD.
**Not supported:** Microsoft MASM (NOKEYWORD deletes the mnemonic), TASM.

Include **after** the processor directive and **before** any instruction the file rewrites:

```asm
    .8086
    .MODEL tiny
    include SMART.INC
```

Protected against multiple inclusion. Default CPU is 8086; with .186 or higher the shift macros and movzx/movsx emulations are omitted because native forms exist.

**SMART / NOSMART:** SMART (default) enables automatic eliminations and jump extension. NOSMART turns those off; explicit helpers (FastIMul, setflag, ...) remain available.
Force the original instruction with the `??` prefix: `??mov`, `??shl`, `??je`, `??jcxz`, ...

Unless stated otherwise, macros may destroy the flags. Counts and constants must be assembly-time constant expressions.

---

### 1. Constant shifts and rotates (8086)

On the 8086, shifts only accept count 1 or CL. These macros expand a constant count into repeated 1-bit instructions (or use the native form from .186 up).

| Macro | Behaviour |
| --- | --- |
| shl / shr / sal / sar | Logical/arithmetic shift; constant count unrolled on 8086 |
| rol / ror | Rotate without carry |
| rcl / rcr | Rotate through carry |

**Example:**

```asm
    mov  al, 01h
    shl  al, 4          ; 8086: four "shl al, 1"; 186+: one "shl al, 4"
    ; AL = 10h
```

Internal helper __SHx builds the stream. Expression operators that shared the SHL/SHR tokens are compensated via __Pow2(n).

---

### 2. movzx / movsx emulation (pre-386)

| Macro | Behaviour |
| --- | --- |
| movzx reg, src | Zero-extend; below 386 expands to xor-high + mov (or equivalent). On 386+ the native instruction is used. |
| movsx reg, src | Sign-extend; below 386 uses cbw / cwd-style sequences where applicable. |

**Example:**

```asm
    mov   bl, 0FFh
    movzx ax, bl        ; 8086: xor ah,ah / mov al,bl -> AX=00FFh
                        ; 386+:  native movzx ax, bl
```

On **486 / original Pentium**, some paths prefer xor+mov over movzx for clocks; on **386** and **P6+/x64**, movzx is preferred. The choice follows the active CPU level.

---

### 3. Multi-operand push / pop

TASM 4 style, comma-separated:

```asm
    push ax, bx, cx     ; push ax / push bx / push cx
    pop  cx, bx, ax     ; reverse order
```

Empty operand lists are rejected (.ERRB).

---

### 4. FastIMul dest, src, const

Signed multiply by a **constant** using only shifts, adds, LEAs and (when profitable) native imul.

| CPU / shape | Strategy |
| --- | --- |
| Power of two | mov (if needed) + shl + optional neg; **in-place** when dest = src (including memory on 186+) |
| 386+ 32-bit regs, odd factors 3..21, 25, 27, 37, 41, 45, 73, 81 | One or two LEAs |
| Remaining constants | Horner chain of shifts/adds, or a single three-operand imul when shorter/faster (186+) |
| Byte destinations / no in-place form | Assembly error instead of silent wrong code |

**Example:**

```asm
    mov   ax, 7
    FastIMul ax, ax, 10     ; AX = 70
    FastIMul bx, ax, 3      ; 386+: often lea bx,[ax+ax*2]
```

dest and src may be the same register when the expansion never re-reads the source after the first write. ESP as destination is guarded.

---

### 5. FastMul const

Computes **unsigned** DX:AX = AX * const (like mul r16).

| Path | Notes |
| --- | --- |
| Power of two | Short shl/rcl sequence (8086) or faster 186+ form |
| Mersenne factors (2^k - 1) | Shift-and-add when the cost model wins vs mul |
| 386+ | movzx + LEA tree on EAX (EDX scratch) or one native imul |
| Otherwise | Horner chain or mul according to CPU cycle model |

**Example:**

```asm
    mov    ax, 1000
    FastMul 7              ; DX:AX = 7000
```

---

### 6. Single-bit helpers

| Macro | Effect |
| --- | --- |
| setflag rm, bit | Set bit in register/memory |
| clrflag rm, bit | Clear bit (masks fitted to operand size) |
| flipflag rm, bit | Toggle bit |
| testflag rm, bit | Test bit (test with mask) |
| maskflag rm, bit | Isolate bit |

**Example:**

```asm
    setflag ax, 5          ; or  ax, 0020h
    clrflag ax, 5          ; and ax, not 0020h
    testflag ax, 5         ; test ax, 0020h
    ; ZF=0 -> bit was set
```

Out-of-range bit indices on registers raise .ERR.

---

### 7. Bit-field helpers

Compatible with MASM-style RECORD / WIDTH.

| Macro | Effect |
| --- | --- |
| setfield rm, lo, width, val | Insert val into bits [lo, lo+width). Full-width field -> one MOV. |
| getfield dest, src, lo, width | Extract field with zero-extension. On 386+, lo=0 and width 8/16 can collapse to one movzx. |

**Example:**

```asm
    mov     ax, 0
    setfield ax, 4, 3, 5   ; AX bits 4..6 = 5 -> AX = 0050h
    getfield bx, ax, 4, 3  ; BX = 0005h
```

Range: lo + width <= 32. Below 386, fields that do not fit 16 bits are errors.

---

### 8. Redundant mov / xchg (SMART mode)

| Form | SMART | NOSMART / force |
| --- | --- | --- |
| mov reg, reg (same register) | Assembles to nothing | ??mov emits the real instruction |
| xchg reg, reg | Assembles to nothing | ??xchg or plain nop for padding |

**Example:**

```asm
    mov  ax, ax            ; SMART: no bytes emitted
    ??mov ax, ax           ; forced 2-byte mov (or use nop for 90h)
    mov  ax, bx            ; always real mov
    mov  ax, 0             ; NOT turned into xor (flags must stay intact)
```

**Caution:** the 1-byte xchg ax,ax (90h) is the classic NOP for alignment -- SMART removes it; pad with ??xchg ax,ax or nop.

---

### 9. lea reg16, var -> mov reg, OFFSET var (SMART)

When the source is a direct memory variable (no index/base), the destination is a 16-bit register, and the segment is use16, the shorter mov reg, OFFSET var is emitted.

**Example:**

```asm
    lea  ax, myVar         ; -> mov ax, OFFSET myVar  (3 bytes vs 4)
    lea  ax, [bx]          ; indexed: unchanged
    lea  eax, myVar        ; 32-bit dest: unchanged
    ??lea ax, myVar        ; force real lea
```

---

### 10. Extended conditional jumps (SMART)

Pre-386, short-only Jcc cannot reach beyond +/-127. The macros:

- **Backward, in range:** keep the 2-byte short form.
- **Backward, out of range / forward / external:** emit j<inverse> over / jmp target / over:.
- **@F / @B:** pass through unchanged.
- **386+:** pass through; the assembler picks short or near itself.

Covers all 30 mnemonics (je/jz, jne/jnz, ja/jnbe, ...).

**Example (8086):**

```asm
    je   far_label         ; if far: jne short over / jmp far_label / over:
    ??je near_ok           ; force short form
```

---

### 11. Extended jcxz / loop (SMART)

These never gained a long encoding. Out-of-range targets use a trampoline that preserves flags and the CX=0 -> 0FFFFh wrap of loop. In-range backward targets keep the native 2-byte form.

**Example:**

```asm
    mov  cx, 100
@@l: dec  bx
    loop @@l               ; short if in range; else trampoline
    ??loop @@l             ; force native short loop
```

LOOPE/LOOPNE stay native (flag-safe long form is not worth the cost).

---

### Internal helpers (not for general use)

__Pow2, __IMag / __ISgn, __TZ / __Ones / __Hibit, __Horn, __RegBits, __FieldRange, __GFTail, __LeaOddX, __IsLeaOddD, __Jcc, __SExt, etc. drive the expansions above.

---

## Safety notes (both tools)

- Flag-gated rewrites use path-sensitive liveness; ret/retf kill status flags.
- sub R,R -> xor R,R requires **AF dead** (sub forces AF=0; xor leaves AF undefined).
- Memory that might be MMIO is treated conservatively.
- SP is excluded from several pair-deletes (interrupt window).
- SMART.INC does **not** turn mov reg,0 into xor (flags).

---

## Analysis: 4VIEW.ASM vs SMARTPP

Hand-written, already tight DOS code. On a full unit with labels kept, expect **small** hit rates (a few dozen rewrites per several thousand lines).

### Likely hits with current SMARTPP

| Pattern in 4VIEW | Rule | Notes |
| --- | --- | --- |
| dec cx / jnz ... (tight loops in paint/hex) | **P427** (`-Oz`) | Several sites (@@pp, @@p, RdLine tails) |
| test ... / jz/jnz | liveness only | No change unless flags dead for a fold |
| add/sub reg,1 | **P10** | CF must be dead |
| xor reg,reg / following use | **P9** chain / zero idioms | Often already written as xor |
| push dx / push ax / pop ebx | partial | Builds 32-bit values; not a classic dead push/pop |
| cmp cCnt,0 / je | **P11** only if reg form | Memory cmp is not cmp R,0 |

### Gaps / candidates SMARTPP does not (or only partially) cover

1. **cmp mem,0 / jcc** (e.g. cmp cCnt,0, cmp isFile,0, cmp hFull,0)
   P11 is register-only (cmp R,0 -> test R,R). On 8086 there is no cheaper test mem,mem. Leave as-is unless a 386+ encoding-proof rule is added.

2. **push imm16 / push imm16 / pop reg32** (386: packing DX:AX into EBX)
   Correct as written; rewriting to movzx/shl/or is a size/speed trade -- needs an explicit 386+ cost-checked rule.

3. **push es / push ds / pop es** (segment load)
   Needs precise segment liveness; easy to get wrong with interrupts / ASSUME.

4. **HLL helpers (.if / .endif / .case)**
   Expanded by ASMC depending on pipeline. Jump threading (P5-P7) helps expanded jcc/jmp; directives themselves are skipped.

5. **SWAR / magic constants** (lea edx,[eax-01010101h])
   Intentional; must not be simplified.

6. **loop vs dec cx/jnz in 386 builds**
   4VIEW uses dec/jnz under USE386 for speed. P427 is **`-Oz` only** -- correct.

7. **Cross-block / global**
   No global copy-prop, no dead store across calls, no whole-function frame removal -- out of scope for a local peephole tool.

8. **mov mem,0 / add reg,1 mixed pairs**
   Not a single-register chain; correctly ignored.

### Practical takeaway for 4VIEW

- Run with **`-m86 -Oz`** and **`-m386 -Os`** separately; expected wins: **P10**, **P427** (8086/`-Oz`), identity deletes, occasional **P9/P11** on register forms.
- CountFull SWAR, search, and hex paint are already idiomatic; SMARTPP should not invent clever rewrites there.
- Highest-value *new* rules if 4VIEW is the benchmark: careful **386 push/push/pop r32 packing**, and optionally **cmp reg,0/jcc** only where encoding does not grow and flags are dead on both arms (same discipline as P850/P851).

---

## License / provenance

SMART.INC is based on earlier work by Javier Gutiérrez Chamorro (Guti). Both components stay dependency-free and easy to vendor.
