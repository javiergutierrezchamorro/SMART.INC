# SMART.INC & SMARTPP

**Copyright (c) Javier Gutiérrez Chamorro (Guti)**

Two complementary tools for classic x86 assembly (8086 through 386+, with limited x86-64 and x87 support):

| Component | Role |
|-----------|------|
| **[SMART.INC](SMART.INC)** | Include file of macros that rewrite instructions *at assembly time* (inside macro expansion). |
| **[SMARTPP.C](SMARTPP.C)** | External single-file C tool. Reads `.asm` source (following `INCLUDE`), applies provably-safe peephole rewrites *across* consecutive instructions, and writes the result. |

**Target assemblers for SMART.INC:** [ASMC](https://github.com/nidud/asmc), JWasm, UASM.  
**SMARTPP** also accepts GNU AS / AT&T syntax (`-att`).

---

## SMARTPP

### What it is

SMARTPP is a **conservative peephole pre-processor**. It is not a compiler backend. It only rewrites sequences that are **provably equivalent** under explicit flag/register liveness analysis and CPU gates. If a transform could change observable behaviour (flags, the SP interrupt window, MMIO side-effects, far jumps, etc.) it is refused.

Typical usage:

```sh
gcc -O2 -Wall -o smartpp SMARTPP.C
# or Watcom: wcl386 -w3 -oneatx ... SMARTPP.C

smartpp -m386 -o out.asm in.asm
smartpp -m86 -Oz -v -o out.asm in.asm
smartpp -m64 -Os -mark -o out.asm in.asm
```

### Command-line options

| Option | Meaning |
|--------|---------|
| `-m86` … `-m686` / `-m64` | Initial CPU level (default 8086). Source directives (`.386`, `P386`, etc.) may raise or lower it. |
| `-att` / `-intel` | Force AT&T or Intel syntax (default: auto-detect). |
| `-I DIR` | Add an include search path (repeatable). |
| `-noinclude` | Do not expand `INCLUDE` / `include` / `.include`. |
| `-Os` | Optimise for speed (default). |
| `-Oz` | Optimise for size. |
| `-Ox` | Enable aggressive folds that are **not** 100 % safe (each firing is warned under `-w`). |
| `-mark` / `-nomark` | Leave `; SMARTPP … (Pn)` markers on rewritten lines (default: on). |
| `-v` / `-nv` | Per-line rule notices on stderr (default: off; use `-v` when auditing). |
| `-w` / `-nw` | Warnings (CPU directives, `-Ox` rules, …). Default: **on**. |
| `-color` / `-ncolor` | Coloured diagnostics on/off. |
| `-o FILE` | Output file (`-` = stdout). |
| `-V` / `--version` | Detailed version, build and rule catalogue. |
| `-h` / `--help` | Help text. |

### INCLUDE handling

`INCLUDE` / `include` / `.include` are expanded by default.  
Search order: directory of the including file → `-I` paths → current working directory.  
Missing files produce a warning and leave the directive untouched. Expanded regions are marked with begin/end comments. Include cycles are detected.

### How the engine works

1. Load the source (and includes) into a line store.
2. Scan labels, `USE16`/`USE32`, CPU directives, `.NO87`, etc.
3. Multi-pass (maximum 4): for every live line run the **bespoke C rules** in `run_pass`, then the **table-driven** rule engine.
4. A pass stops when no rule fires; the whole process stops when a pass is idle or the pass limit is reached.
5. Print a summary (rules + hit counts) on stderr, then write the output.

**Table rules** (`g_rule_tbl[]`) match 1–4 instruction patterns with operand captures, preconditions (flags dead, register dead, CPU level, `-Oz` only, stack memory, …) and actions (delete / rewrite via template).  
**C rules** handle control-flow, multi-path liveness, cost models and patterns that do not fit the table cleanly.

### Safety model

- Flag-gated rewrites use a path-sensitive walk (`flags_clear` / `reg_dead_cf`). `ret`/`retf` kill the status flags (ABI).
- Transforms that replace a flag-setting instruction with a non-setter (e.g. `loop`, `jcxz`) require the flags to be dead on **both** the fall-through and the branch target (`flags_dead_after_jcc`).
- SP/ESP/RSP is excluded from several pair-deletes (interrupt window between two short operations).
- Memory that might be MMIO is treated conservatively (only pure stack slots `[bp/ebp/rbp±N]` are considered side-effect-free for certain folds).
- Short-only encodings (`loop`, `jcxz`, `jecxz`) assume near targets in range (the same assumption classic DOS tools make).

### Rule families (high-level catalogue)

- **Identity / redundancy** — delete `mov/xchg R,R`, push/pop of the same register, double xchg, duplicate flag ops, shift-by-0, add/sub 0, not/neg/cmc pairs, etc.
- **Strength reduction** — `mov R,0` → `xor`, `add/sub ±1` → `inc/dec`, `cmp R,0` → `test`, LEA → add/sub/inc/dec, `imul` power-of-two → `shl`, `imul` odd factors → LEA trees (P380), `sub R,R` → `xor`, etc.
- **Constant folding** — combined add/sub immediates, `mov`+shift/logic, `mov`+not/neg, …
- **Control flow** — jump threading, redundant jumps, branch inversion, dead code after unconditional jumps/returns.
- **Widening (386+)** — `movzx`/`movsx` idioms, and-mask → `movzx`, zero/sign-extend cleanup.
- **Size (`-Oz`)** — `dec cx/jnz` → `loop`, `jcxz`/`jecxz`, compact dual-zero sequences with `cdq`/`cwd`.
- **Bit operations (386+)** — `bt`/`bts`/`btr`/`btc` folds when profitable and safe.
- **x64** — canonical `xor r32,r32` zeroing, redundant 32→64 zero-extends, etc.
- **Stack / LEA / copy-prop** — store-forwarding on pure stack slots, limited copy propagation, empty frame elimination, LEA fusion.

The full numbered catalogue (P1 … P899+) is printed by `smartpp -V`.

### Build notes

| Toolchain | Notes |
|-----------|-------|
| **GCC / Clang** | `gcc -O2 -Wall -o smartpp SMARTPP.C` |
| **Watcom** | Large stack (`_STACKSIZE`); keep large temporaries off the stack. |
| **MSVC** | `#pragma comment(linker, "/STACK:2097152")` on Windows. |

---

## SMART.INC

### What it is

SMART.INC is a **macro library** that renames selected mnemonics (`OPTION RENAMEKEYWORD`) and re-implements them so that:

- Constant shifts work on the **8086** (hardware only accepts 1 or CL).
- `movzx` / `movsx` are emulated below the **386**.
- Multi-operand `push`/`pop`, bit helpers and fast constant multiplies are available.
- Under **SMART** mode (the default) redundant `mov`/`xchg`, short `lea`→`mov OFFSET` and short conditional jumps are rewritten automatically.

**Requirements:** ASMC, JWasm or UASM with `OPTION RENAMEKEYWORD`.  
**Not supported:** Microsoft MASM (`NOKEYWORD` deletes the mnemonic), TASM.

Include **after** the processor directive and **before** any instruction the file rewrites:

```asm
    .8086
    .MODEL tiny
    include SMART.INC
```

The file is protected against multiple inclusion. Default CPU is 8086; with `.186` or higher the shift macros and the `movzx`/`movsx` emulations are omitted because native forms already exist.

**SMART / NOSMART**

- `SMART` (default) enables the automatic eliminations and jump extension.
- `NOSMART` turns those automatic optimisations off.
- Explicit helpers (`FastIMul`, `setflag`, …) remain available in both modes.
- Force the original instruction with the `??` prefix: `??mov`, `??shl`, `??je`, `??jcxz`, …

Unless stated otherwise, macros may destroy the flags. Counts and constants must be assembly-time constant expressions.

---

### 1. Constant shifts and rotates (8086)

On the 8086, shifts only accept count 1 or CL. These macros expand a constant count into repeated 1-bit instructions (or use the native form from `.186` upward).

| Macro | Behaviour |
|-------|-----------|
| `shl` / `shr` / `sal` / `sar` | Logical / arithmetic shift; constant count unrolled on 8086 |
| `rol` / `ror` | Rotate without carry |
| `rcl` / `rcr` | Rotate through carry |

**Example:**

```asm
    mov  al, 01h
    shl  al, 4          ; 8086: four "shl al,1" ; 186+: one "shl al,4"
    ; AL = 10h
```

Internal helper `__SHx` builds the stream. Expression operators that shared the `SHL`/`SHR` tokens are compensated via `__Pow2(n)`.

---

### 2. `movzx` / `movsx` emulation (pre-386)

| Macro | Behaviour |
|-------|-----------|
| `movzx reg, src` | Zero-extend. Below 386 expands to `xor`-high + `mov` (or equivalent). On 386+ the native instruction is used. |
| `movsx reg, src` | Sign-extend. Below 386 uses `cbw`/`cwd`-style sequences where applicable. |

**Supported destinations (pre-386):** `AX`, `BX`, `CX`, `DX` only.

**Important limitation:** the pre-386 `movsx` expansion for `BX`/`CX`/`DX` **clobbers `AX`**.

**Example:**

```asm
    mov   bl, 0FFh
    movzx ax, bl        ; 8086: xor ah,ah / mov al,bl  → AX = 00FFh
                        ; 386+:  native movzx ax, bl
```

On 486 / original Pentium some paths prefer `xor`+`mov` over `movzx` for clocks; on 386 and P6+/x64 `movzx` is preferred. The choice follows the active CPU level.

---

### 3. Multi-operand `push` / `pop`

TASM 4 style, comma-separated:

```asm
    push ax, bx, cx     ; push ax / push bx / push cx
    pop  cx, bx, ax     ; reverse order
```

Empty operand lists are rejected (`.ERRB`).

---

### 4. `FastIMul dest, src, const`

Signed multiply by a **constant** using only shifts, adds, LEAs and (when profitable) native `imul`.

| CPU / shape | Strategy |
|-------------|----------|
| Power of two | `mov` (if needed) + `shl` + optional `neg`; **in-place** when `dest = src` (including memory on 186+) |
| 386+ 32-bit registers, odd factors 3…21, 25, 27, 37, 41, 45, 73, 81 | One or two LEAs |
| Remaining constants | Horner chain of shifts/adds, or a single three-operand `imul` when shorter/faster (186+) |
| Byte destinations / no in-place form | Assembly error instead of silent wrong code |

**Example:**

```asm
    mov     ax, 7
    FastIMul ax, ax, 10     ; AX = 70
    FastIMul bx, ax, 3      ; 386+: often lea bx,[ax+ax*2]
```

`dest` and `src` may be the same register when the expansion never re-reads the source after the first write. ESP as destination is guarded.

---

### 5. `FastMul const`

Computes **unsigned** `DX:AX = AX * const` (like `mul r16`).

| Path | Notes |
|------|-------|
| Power of two | Short `shl`/`rcl` sequence (8086) or faster 186+ form |
| Mersenne factors (`2^k-1`) | Shift-and-add when the cost model wins versus `mul` |
| 386+ | `movzx` + LEA tree on EAX (EDX scratch) or one native `imul` |
| Otherwise | Horner chain or `mul` according to the CPU cycle model |

**Example:**

```asm
    mov    ax, 1000
    FastMul 7              ; DX:AX = 7000
```

---

### 6. Single-bit helpers

| Macro | Effect |
|-------|--------|
| `setflag rm, bit` | Set bit in register/memory |
| `clrflag rm, bit` | Clear bit (masks fitted to operand size) |
| `flipflag rm, bit` | Toggle bit |
| `testflag rm, bit` | Test bit (`test` with mask) |
| `maskflag rm, bit` | Isolate bit |

**Example:**

```asm
    setflag ax, 5          ; or  ax, 0020h
    clrflag ax, 5          ; and ax, not 0020h
    testflag ax, 5         ; test ax, 0020h
    ; ZF = 0 → bit was set
```

Out-of-range bit indices on registers raise `.ERR`.

---

### 7. Bit-field helpers

Compatible with MASM-style `RECORD` / `WIDTH`.

| Macro | Effect |
|-------|--------|
| `setfield rm, lo, width, val` | Insert `val` into bits `[lo, lo+width)`. Full-width field → one `MOV`. |
| `getfield dest, src, lo, width` | Extract field with zero-extension. On 386+, `lo=0` and width 8/16 can collapse to one `movzx`. |

**Example:**

```asm
    mov     ax, 0
    setfield ax, 4, 3, 5   ; AX bits 4..6 = 5 → AX = 0050h
    getfield bx, ax, 4, 3  ; BX = 0005h
```

Range: `lo + width ≤ 32`. Below 386, fields that do not fit 16 bits are errors.

---

### 8. Redundant `mov` / `xchg` (SMART mode)

| Form | SMART | NOSMART / force |
|------|-------|-----------------|
| `mov reg, reg` (same register) | Assembles to nothing | `??mov` emits the real instruction |
| `xchg reg, reg` | Assembles to nothing | `??xchg` or plain `nop` for padding |

**Example:**

```asm
    mov  ax, ax            ; SMART: no bytes emitted
    ??mov ax, ax           ; forced 2-byte mov (or use nop for 90h)
    mov  ax, bx            ; always real mov
    mov  ax, 0             ; NOT turned into xor (flags must stay intact)
```

**Caution:** the 1-byte `xchg ax,ax` (opcode 90h) is the classic NOP for alignment. SMART removes it; pad with `??xchg ax,ax` or `nop`.

---

### 9. `lea reg16, var` → `mov reg, OFFSET var` (SMART)

When the source is a direct memory variable (no index/base), the destination is a 16-bit register and the segment is `use16`, the shorter `mov reg, OFFSET var` is emitted.

**Example:**

```asm
    lea  ax, myVar         ; → mov ax, OFFSET myVar  (3 bytes vs 4)
    lea  ax, [bx]          ; indexed: unchanged
    lea  eax, myVar        ; 32-bit dest: unchanged
    ??lea ax, myVar        ; force real lea
```

---

### 10. Extended conditional jumps (SMART)

Pre-386, short-only `Jcc` cannot reach beyond ±127. The macros:

- **Backward, in range:** keep the 2-byte short form.
- **Backward, out of range / forward / external:** emit `j<inverse> over` / `jmp target` / `over:`.
- **`@F` / `@B`:** pass through unchanged.
- **386+:** pass through; the assembler picks short or near itself.

Covers all 30 mnemonics (`je`/`jz`, `jne`/`jnz`, `ja`/`jnbe`, …).

**Example (8086):**

```asm
    je   far_label         ; if far: jne short over / jmp far_label / over:
    ??je near_ok           ; force short form
```

---

### 11. Extended `jcxz` / `loop` (SMART)

These never gained a long encoding. Out-of-range targets use a trampoline that preserves flags and the `CX=0 → 0FFFFh` wrap of `loop`. In-range backward targets keep the native 2-byte form.

**Example:**

```asm
    mov  cx, 100
@@l: dec  bx
    loop @@l               ; short if in range; else trampoline
    ??loop @@l             ; force native short loop
```

`LOOPE`/`LOOPNE` stay native (a flag-safe long form is not worth the cost).

---

### Internal helpers (not for general use)

`__Pow2`, `__IMag` / `__ISgn`, `__TZ` / `__Ones` / `__Hibit`, `__Horn`, `__RegBits`, `__FieldRange`, `__GFTail`, `__LeaOddX`, `__IsLeaOddD`, `__Jcc`, `__SExt`, etc. drive the expansions above.

---

## Safety notes (both tools)

- Flag-gated rewrites use path-sensitive liveness; `ret`/`retf` kill status flags.
- `sub R,R` → `xor R,R` requires **AF dead** (`sub` forces AF=0; `xor` leaves AF undefined).
- Memory that might be MMIO is treated conservatively.
- SP is excluded from several pair-deletes (interrupt window).
- SMART.INC does **not** turn `mov reg,0` into `xor` (flags must stay intact).

---

## Practical recommendations

- For pure size on 8086-class code: `smartpp -m86 -Oz …`
- For speed on 386+ code: `smartpp -m386 -Os …` (or `-m486` / `-m686`).
- Always keep `-w` enabled while developing; review any `-Ox` warnings.
- When auditing SMARTPP output use `-v -mark`.
- In SMART.INC prefer the `??` prefix only when you deliberately need the original encoding (alignment NOPs, self-modifying code, timing loops).

---

## License / provenance

SMART.INC is based on earlier work by Javier Gutiérrez Chamorro (Guti). Both components stay dependency-free and easy to vendor.
