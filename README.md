# SMART.INC — TASM-style optimization macros for ASMC, JWasm and UASM

**SMART.INC** is a single, dependency-free include file that brings back the
code-generation conveniences that **Borland Turbo Assembler (TASM)** used to
provide out of the box, for use with **[ASMC](https://github.com/nidud/asmc)**,
**[JWasm](https://github.com/jwasm/jwasm)** and **UASM**. It is based in previous **[SMART.INC by Javier Gutiérrez Chamorro (Guti)](https://www.javiergutierrezchamorro.com/smart-inc/)**.

It targets classic x86 assembly — 8086 through 386 and up — where every cycle
counts: DOS applications and games, boot sectors, demoscene productions, ROM
code and other environments where you still write tight 16-bit code by hand.

- [Why](#why)
- [Quick start](#quick-start)
- [Include rules](#include-rules)
- [Macro reference](#macro-reference)
  - [Shifts with a constant count (8086)](#shifts-with-a-constant-count-8086)
  - [MOVZX / MOVSX (CPU < 386)](#movzx--movsx-cpu--386)
  - [PUSH / POP with several operands](#push--pop-with-several-operands)
  - [Redundant reg, reg elimination (mov, xchg)](#redundant-reg-reg-elimination-mov-xchg)
  - [LEA reg, var → MOV reg, OFFSET var (SMART)](#lea-reg-var--mov-reg-offset-var-smart)
  - [Extended conditional jumps (SMART)](#extended-conditional-jumps-smart)
  - [Extended JCXZ / LOOP (SMART)](#extended-jcxz--loop-smart)
  - [FastIMul](#fastimul-dest-src-const)
  - [FastMul](#fastmul-const)
  - [Single bits (flags)](#single-bits-flags)
  - [Bit fields](#bit-fields)
  - [__Pow2 (internal helper)](#__pow2-internal-helper)
- [Compatibility notes](#compatibility-notes)
- [Error checking](#error-checking)
- [Testing](#testing)
- [Version history](#version-history)
- [Repository layout](#repository-layout)

---

## Why

TASM's *smart* mode silently produced better code than MASM in several common
situations — shifts by a constant count on an 8086, unsigned/signed widening
moves, multiplication by constants, `PUSH AX BX CX` — and it exposed handy
directives for bit testing. MASM (and therefore ASMC) does none of that
automatically, and some of it cannot be expressed with plain instructions on
the 8086 at all.

SMART.INC closes that gap with plain MASM macro facilities (no custom tooling,
no post-processing), so the same source assembles with ASMC, JWasm and UASM
unchanged.

What it implements:

| Group | Macros | Purpose |
| --- | --- | --- |
| Shifts | `shl` `shr` `sal` `sar` `rol` `ror` `rcl` `rcr` | Constant count shifts/rotates on 8086 |
| Widening moves | `movzx` `movsx` | Emulated widening moves on CPU < 386 |
| Stack | `push` `pop` | Several operands in one statement |
| Redundant moves | `mov` | `mov reg, reg` with the same register assembles to nothing |
| Shorter addressing | `lea` | `lea reg16, var` becomes `mov reg, OFFSET var` (SMART) |
| Jump range | `je` … `jpo` (30 mnemonics) | Conditional jumps extended automatically when out of short range (SMART) |
| Multiplication | `FastIMul` `FastMul` | Multiply by a constant without `IMUL`/`MUL` |
| Single bits | `setflag` `clrflag` `flipflag` `testflag` `maskflag` | Set / clear / invert / test / mask one bit |
| Bit fields | `setfield` `getfield` | Insert / extract a bit field |
| Helper | `__Pow2` | `2^n` as a macro function |

## Quick start

```asm
    .8086                  ; CPU directive FIRST
    .MODEL tiny
    include SMART.INC      ; then the include
    .CODE

start:
    shl  ax, 4             ; four 1-bit shifts on 8086
    mov  ax, ax            ; eliminated: assembles to nothing
    movzx bx, al           ; mov bl,al / xor bh,bh
    FastIMul cx, bx, 45    ; cx = bx * 45, no IMUL
    FastMul  1000          ; DX:AX = AX * 1000
    setflag ax, 3          ; or  ax, 8
    setfield ax, 4, 3, 7   ; insert 7 into bits 4..6
    getfield bx, ax, 4, 3  ; bx = bits 4..6 of ax
    ret
END start
```

## Include rules

1. **Include the file after the processor directive** (`.8086`, `.186`,
   `.286`, `.386`...). `@Cpu` is evaluated at the include point and decides
   which macro groups get defined.
2. **Include it before the first instruction it replaces.** The include
   enables `OPTION RENAMEKEYWORD` for the keywords it overrides.
3. Multiple inclusion is safe: the file is guarded by `__SMART_INC__`,
   which also carries the **version** as `major*100 + minor` (360 = v3.6).
   Source can test it before using a newer feature:

   ```asm
       IF __SMART_INC__ GE 360
           lea ax, var             ; v3.4: becomes mov ax, OFFSET var
       ELSE
           mov ax, OFFSET var
       ENDIF
   ```

| CPU directive | Shift macros | MOVZX/MOVSX macros | Everything else (incl. `mov`) |
| --- | --- | --- | --- |
| `.8086` (default) | defined | defined | defined |
| `.186` / `.286` | not defined (native immediate shifts) | defined | defined |
| `.386` and up | not defined | not defined (native MOVZX/MOVSX) | defined |

Everything is defined for all CPU levels unless the table above says
otherwise: `push`/`pop`, `mov`, `FastIMul`, `FastMul`, the flag macros and the
field macros work with 8-, 16- and 32-bit operands (`.386` needed only for the
32-bit ones).

---

## Macro reference

Notation: **rm** = register or memory operand; "assembly-time constant" means
the value must be fully known when the file is assembled. Unless stated
otherwise, every macro destroys the flags.

### Shifts with a constant count (8086)

```asm
shl dest[, count]
shr dest[, count]
sal dest[, count]
sar dest[, count]
rol dest[, count]
ror dest[, count]
rcl dest[, count]
rcr dest[, count]
```

| Parameter | Description |
| --- | --- |
| `dest` | Register **or memory** operand, 8 or 16 bit (32 bit with `.386`) |
| `count` | Optional. Omitted or `1` → one shift; `CL` → `SHx dest, cl`; any assembly-time constant ≥ 0 |

| Input | Expansion (8086) |
| --- | --- |
| `shl ax, 4` | four copies of `shl ax, 1` |
| `shl ax` | `shl ax, 1` |
| `shl ax, 1` | `shl ax, 1` (pass-through) |
| `shl ax, cl` | `shl ax, cl` (pass-through) |
| `shl dx, 0` | nothing |
| `shl [bx], 3` | three copies of `shl word ptr [bx], 1` |

Notes:

- The 8086 only accepts `SHx reg, 1` and `SHx reg, cl`; the count `count`
  form is what TASM's smart mode generated and what the 186+ hardware takes
  as an immediate. Negative counts raise an assembly-time error.
- The real instructions remain available internally as `??shl`, `??shr`, ...
  if you ever need to force them.
- Defined **only** with `.8086` (with `.186`+ the assembler already accepts
  immediate counts natively).

### MOVZX / MOVSX (CPU < 386)

```asm
movzx reg16, src8
movsx reg16, src8
```

| Parameter | Description |
| --- | --- |
| `reg16` | Destination: `AX`, `BX`, `CX` or `DX` only |
| `src8` | 8-bit register (`AL`/`BL`/`CL`/`DL`/`AH`/`BH`/`CH`/`DH`) or 8-bit memory |

| Macro | Expansion | Clobbers |
| --- | --- | --- |
| `movzx ax, bl` | `mov al, bl` + `xor ah, ah` | flags |
| `movzx bx, bh` | `mov bl, bh` + `xor bh, bh` | flags (high-half sources work) |
| `movsx ax, al` | `cbw` (the redundant `mov al, al` is removed by the v3.0 `mov` macro) | flags |
| `movsx bx, bl` | `mov al, bl` + `cbw` + `mov bx, ax` | **AX**, flags |

Notes:

- The 8086/186/286 have no widening moves; the 386 introduced `MOVZX`/`MOVSX`.
  These macros emulate them, and are defined **only** for `.8086`/`.186`/`.286`.
- `movzx` loads first and clears the high half afterwards, so `movzx ax, ah`
  is still correct (a naive expansion would zero the value before reading it).
- `movsx` extends through `CBW`, which always uses `AL`/`AX`; extending into
  `BX`/`CX`/`DX` therefore clobbers `AX` — unavoidable on an 8086.

### PUSH / POP with several operands

```asm
push op1[, op2[, ...]]
pop  op1[, op2[, ...]]
```

| Parameter | Description |
| --- | --- |
| `op1..opN` | Any valid `PUSH`/`POP` operand: registers (including segment registers), memory, with `.386` also immediates |

```asm
    push ax, bx, cx    ; = push ax / push bx / push cx
    pop  cx, bx, ax    ; = pop  cx / pop  bx / pop  ax
```

Notes:

- TASM 4 separated the operands with spaces (`PUSH AX BX CX`); in MASM-family
  syntax the macro argument separator is the comma, hence the commas here.
- With a single operand the expansion is exactly the plain instruction.
- An empty operand list raises an assembly-time error.
- `PUSHA`/`PUSHF`/`POPA`/`POPF` are not affected.

### Redundant reg, reg elimination (mov, xchg)

New in **v3.0** (`mov`), **v3.5** (`xchg`). Both are taken over with
`OPTION RENAMEKEYWORD` at **every CPU level**. When both operands are the
same register, the expansion is empty; every other `MOV`/`XCHG` passes
through byte-identical.

| Input | Expansion |
| --- | --- |
| `mov ax, ax` | nothing (removed) |
| `mov AX, aX` | nothing (detection is case-insensitive) |
| `mov ax, bx` | `mov ax, bx` (pass-through) |
| `mov ax, 0` | `mov ax, 0` (pass-through, **not** `xor ax, ax`) |
| `mov [bx], ax` | `mov [bx], ax` (pass-through) |
| `xchg ax, ax` | nothing (removed, v3.5) |
| `??mov ax, ax` | `mov ax, ax` (forced original instruction) |
| `??xchg ax, ax` | `xchg ax, ax` (forced original instruction) |

Notes:

- `mov reg, reg` and `xchg reg, reg` change no register, no memory and no
  flags, so removing them cannot change the behavior of the program. They
  are usually left over after edits or generated by other macros.
- **`mov reg, 0` is deliberately NOT converted to `xor reg, reg`**: `MOV`
  leaves the flags untouched and `XOR` destroys them, so that
  "optimization" can silently break flag-dependent code. SMART.INC only
  removes instructions that provably do nothing. For the same reason
  `or reg, reg` / `and reg, reg` (flag-setting idioms) and `xchg reg, reg`
  used as the 1-byte NOP (opcode 90h) are the only other single-instruction
  cases: **careful with padding** — SMART removes `xchg ax, ax` too, so pad
  with `??xchg ax, ax` or with `nop` (not taken over) when the byte count
  matters.
- The elimination requires both operands to be registers. Identical text
  that is not a register pair (e.g. the invalid `mov [bx], [bx]`) still
  reaches the assembler and keeps raising its normal error, so no invalid
  code is silently hidden.

#### SMART / NOSMART

New in **v3.3**. Like TASM's automatic optimizations, the `mov reg, reg`
elimination belongs to **SMART mode**, which is the default:

```asm
    include smart.inc
    NOSMART                 ; every MOV passes through untouched
    mov ax, ax              ; assembles to the 2-byte mov ax, ax
    SMART                   ; optimizations back on
    mov ax, ax              ; assembles to nothing again
```

- `SMART`/`NOSMART` are plain macros defined by the include; the state is
  one assembly-time flag, so you can toggle them anywhere in the source.
- `NOSMART` currently affects only the `mov reg, reg` elimination: the rest
  of the library (shifts, `push`/`pop`, `FastIMul`, `FastMul`, bit and field
  macros) consists of explicit macro calls the user wrote on purpose, not
  silent rewrites of instructions the assembler would also accept.
- `??mov ax, ax` forces the original instruction in both modes.
- If a `mov ax, ax` is kept on purpose — a 2-byte timing delay, or a patch
  hole for self-modifying code — force it with `??mov ax, ax`.
- The `mov` rename has no effect on any expression operator (`MOV` does not
  share a token with one), so constant expressions keep working exactly as
  before.

```asm
    mov  ax, bx        ; emitted as-is
    mov  ax, ax        ; removed: redundant
    mov  ax, 0         ; emitted as-is (flags untouched)
    ??mov ax, ax       ; forced: 2-byte "nop" for timing / patching
```

### LEA reg, var → MOV reg, OFFSET var (SMART)

New in **v3.4**. TASM's SMART mode replaces `LEA` with the shorter `MOV`
when the source is a plain variable: `lea ax, var` costs 4 bytes on the
8086, `mov ax, OFFSET var` costs 3, and both load the same address without
touching the flags. `lea` is taken over (`OPTION RENAMEKEYWORD`, escape
`??lea`) and the substitution happens only when it is really shorter:

| Input | Expansion |
| --- | --- |
| `lea ax, var` | `mov ax, OFFSET var` (3 bytes vs 4) |
| `lea ax, var+2` | `mov ax, OFFSET var+2` |
| `lea eax, var` | `lea eax, var` (same size, kept) |
| `lea ax, [bx]` | `lea ax, [bx]` (indexed, kept) |
| `lea ax, var[si]` | `lea ax, var[si]` (indexed, kept) |
| `lea ax, [bp+4]` | `lea ax, [bp+4]` (no constant address, kept) |
| `??lea ax, var` | `lea ax, var` (forced original instruction) |

Detection: the source must be a memory expression with direct addressing
(`OPATTR` bits 1 and 3 set, bit 6 clear) and the destination a 16-bit
register. `NOSMART` disables the substitution. The internal `LEA` forms of
`FastIMul` and `FastMul` are indexed and pass through byte-identical.

### Extended conditional jumps (SMART)

New in **v3.4**. On the 8086/186/286 a conditional jump only reaches
−128..127 bytes and the assembler just errors when the target is farther.
All 30 conditional jump mnemonics are taken over (`je` … `jpo`, aliases
included; escape `??jxx` forces the short form) and the range is handled
automatically, like TASM's SMART mode:

| Target | Expansion |
| --- | --- |
| backward, distance ≤ 126 | short `jcc target` (2 bytes) |
| backward, distance > 126 | `j<inv>` over `jmp target` (5 bytes) |
| forward (any distance) | `j<inv>` over `jmp target` (5 bytes) |
| `@F` / `@B` | short, native semantics preserved |
| `NOSMART` | short always (native behavior) |

Notes:

- A **forward** target cannot be measured at expansion time (`OPATTR`
  returns 0 for forward references), so it always takes the extended form:
  no conditional jump can ever die with "jump destination too far", at the
  price of 3 extra bytes on every forward jump that would have fit. Write
  backward branches or use `??jxx` where those bytes matter.
- The trampoline label is a macro `LOCAL`, invisible to the user's symbols
  and safe to mix with named labels.
- The plain `jmp` needs no macro: the assembler already picks its short or
  near encoding from the distance.
- The extended form reaches the full ±32K of the near `JMP`; beyond that
  (possible for a backward jump in a 64K segment) the assembler's normal
  error remains — use an intermediate label.

### Extended JCXZ / LOOP (SMART)

New in **v3.6**. `jcxz` and `loop` are the only two jumps with neither an
inverse nor a long encoding: their 8-bit displacement is all they will ever
have, `OPTION LJMP` cannot lengthen them, and a destination more than 127
bytes away is a hard `error A2075: jump destination too far` that nothing in
the assembler can fix. Both are taken over (`??jcxz` / `??loop` force the
original instruction) with the same backward measurement as the conditional
jumps, plus a trampoline that is transparent on every axis that matters:

| Target | Expansion |
| --- | --- |
| backward, distance ≤ 126 | short `jcxz`/`loop target` (2 bytes) |
| backward, distance > 126 | `jxx` over `jmp target` trampoline (7 bytes) |
| forward (any distance) | trampoline (7 bytes) |
| `@F` / `@B` | short, native semantics preserved |
| `NOSMART` | short always (native behavior) |

The trampoline keeps the **real** `LOOP` as the decrementing instruction, so
the flags stay untouched (a plain `dec cx / jnz` emulation would destroy
them) and the `CX = 0` wrap (`CX → 0FFFFh`, jump taken) is preserved exactly;
`JCXZ` touches no flags either. `loope`/`loopne`/`loopz`/`loopnz` are not
intercepted: they test `ZF`, and a flag-safe bridge would cost more than the
instruction is worth.

### FastIMul dest, src, const

```asm
FastIMul dest, src, const
```

| Parameter | Description |
| --- | --- |
| `dest` | Register (or memory with a declared size) that receives the product; same size as `src` |
| `src` | Register or memory of the same size; **destroyed** in the general case, **preserved** in the shortcuts |
| `const` | Signed constant, −32768..65535 (values 32768..65535 are taken as their 16-bit two's complement), known at assembly time |

Computes `dest = src * const` with shifts and adds only — on an 8086 the real
`IMUL r16` costs 118–133 cycles, while this expansion is typically a handful
of `SHL`/`ADD`. On a 386+ build with register operands, small factors use one
or two `LEA` and dense constants use one native three-operand `IMUL` instead
(see the strategy table). `dest` and `src` must be different operands.

```asm
    FastIMul ax, bx, 45      ; ax = bx * 45
    FastIMul cx, dx, -7      ; cx = dx * -7
    FastIMul eax, ebx, 1000  ; DWORD version with .386
```

Strategies chosen automatically from the bit pattern of the constant:

| Constant | Strategy | `src` preserved? |
| --- | --- | --- |
| `0` | `mov dest, 0` | yes |
| `±2^j` | shift `dest` | yes |
| `(2^k − 1) · 2^j`, `k ≥ 4` | Mersenne shortcut: `dest = ((src << k) − src) << j` | yes |
| `3`, `5`, `9` — 386+, `dest` and `src` 32-bit registers | one `lea dest, [src+src*2/4/8]` (v3.2; 1–2 cycles) | yes |
| `6`, `10`, `12`, `18`, `20`, `24` — 386+, `dest` and `src` 32-bit registers | `LEA` + `ADD`/`SHL` (v3.2; two instructions) | yes |
| anything else, 386+, `dest` register, `|const| > 8` | one native `imul dest, src, const` (v3.1; 9–22 cycles r16, 9–38 r32) | yes |
| anything else | general add-shift chain on `src` | **no** (it is shifted in place) |

A negative constant ends the chain expansion with `NEG dest`.

Notes (v3.2):

- On a `.386` build with a register destination, constants with a 16-bit
  magnitude greater than 8 use the native three-operand `IMUL` instead of
  chains of up to 30 instructions. Magnitudes ≤ 8, memory destinations and
  every CPU below the 386 keep the shift/add chain.
- The `LEA` factors need `dest` **and** `src` to be 32-bit registers: the
  SIB byte does not exist in 16-bit addressing, so `WORD` destinations keep
  the chain. `BYTE` destinations also keep the chain — the three-operand
  `IMUL` has no byte encoding (guard added in v3.2; a byte `FastIMul` would
  otherwise have failed to assemble since v3.1).
- Constants in 32768..65535 are passed to `IMUL` as their negative two's
  complement equivalent, so the documented contract also holds for `DWORD`
  destinations (a positive `65535` immediate would mean `+65535`, not `-1`).
- The chain itself is one shared `__Horn` helper since v3.2 (the old file
  had two 15-block branches); the emitted code is byte-identical.

### FastMul const

```asm
FastMul const
```

| Parameter | Description |
| --- | --- |
| `const` | Unsigned constant, 0..65535, known at assembly time |

Computes the 32-bit product **`DX:AX = AX * const`**, i.e. the same result
as `MUL r16` with the constant loaded in a register, but usually much faster
on an 8086/186. Clobbers `BX` (and `CX` when a real `MUL` is emitted) and the
flags; it does not reproduce the `CF`/`OF` values of `MUL`, only the result.

```asm
    FastMul 1000             ; DX:AX = AX * 1000
```

Strategies chosen automatically:

| Constant | Strategy |
| --- | --- |
| `0` | `xor ax, ax` + `xor dx, dx` |
| `2^k` | 32-bit shift of `AX` into `DX` |
| `(2^k − 1) · 2^j`, `k ≥ 4` (and cheap enough) | 32-bit Mersenne shortcut with `SUB`/`SBB` |
| dense pattern, up to ~117 estimated cycles (v3.1) | MSB-to-LSB Horner chain on the `DX:AX` accumulator |
| dense pattern, worse than hardware | real `MUL` (`mov cx, const` + `mul cx`) |

On a `.386` build, power-of-two factors use `movzx eax, ax` / `shl eax, k` /
`shld edx, eax, 16`. Factors `3`, `5`, `9` take a single `LEA`
(`lea eax, [eax+eax*2/4/8]`, 1–2 cycles vs 13–42 for `IMUL r32, imm`) and
`6`, `10`, `12`, `18`, `20`, `24` take `LEA` + `ADD`/`SHL` (v3.1). Every
other factor is a single native `imul eax, eax, const` followed by the same
`shld`, so the `DX:AX` contract holds there too and `BX`/`CL` are not touched.

### Single bits (flags)

```asm
setflag  rm, bit
clrflag  rm, bit
flipflag rm, bit
testflag rm, bit
maskflag rm, bit
```

| Parameter | Description |
| --- | --- |
| `rm` | 8-, 16- or 32-bit register or memory operand |
| `bit` | Bit position, 0..31, assembly-time constant (0 = least significant) |

| Macro | Expansion | Effect | Result flags |
| --- | --- | --- | --- |
| `setflag ax, 3` | `or  ax, 8` | bit = 1 | flags destroyed |
| `clrflag ax, 3` | `and ax, NOT 8` | bit = 0 | flags destroyed |
| `flipflag ax, 3` | `xor ax, 8` | bit inverted | flags destroyed |
| `testflag ax, 3` | `test ax, 8` | none | `ZF` = 1 if bit was 0 |
| `maskflag ax, 3` | `and ax, 8` | keep only the bit | `ZF` = 1 if bit is 0 |

Notes:

- If the bit does not exist in the operand size (e.g. bit 9 of `AL`) the
  assembler itself rejects the generated instruction instead of silently
  producing wrong code.
- For `BYTE`/`WORD` operands the assembler chooses the `imm8` encoding
  whenever the mask fits in a signed byte.
- `testflag`/`maskflag` are meant to be followed by `jz`/`jnz` on the
  resulting `ZF`.

```asm
    setflag  flags, 5        ; raise bit 5
    testflag flags, 5        ; is bit 5 set?
    jnz      bit_was_set
```

### Bit fields

```asm
setfield rm, lo, width, val
getfield dest, src, lo, width
```

| Parameter | Description |
| --- | --- |
| `rm` | 8-, 16- or 32-bit register or memory operand holding the field |
| `dest` / `src` | Operand that receives / provides the field value; the two must not both be memory; if `dest` equals `src`, the copy is skipped |
| `lo` | Start bit of the field, 0..31 (0 = LSB) |
| `width` | Field width in bits, 1..31 |
| `val` | Value to insert; truncated to `width` bits |

Constraints: `lo ≥ 0`, `1 ≤ width ≤ 31`, `lo + width ≤ 32`; all three must be
assembly-time constants.

| Macro | Expansion | Effect |
| --- | --- | --- |
| `setfield ax, 4, 3, 7` | `and ax, NOT (7*16)` + `or ax, 7*16` | inserts `7` into bits 4..6, rest preserved |
| `getfield bx, ax, 4, 3` | `mov bx, ax` + `shr bx, 4` + `and bx, 7` | `bx` = bits 4..6 of `ax`, zero extended |

Both are fully compatible with the native `RECORD` directive of MASM 6+ /
ASMC, which gives named fields:

```asm
DOOR RECORD CLOSED:1, MODE:2, SPEED:5     ; SPEED = bits 3..7
    setfield ax, 3, WIDTH SPEED, 17       ; insert 17 into SPEED
    getfield bx, ax, 3, WIDTH SPEED       ; read SPEED back
```

`getfield` with a shared operand (`getfield ax, ax, 4, 3`) skips the copy and
just shifts and masks in place.

### __Pow2 (internal helper)

```asm
n = __Pow2(i)
or   ax, __Pow2(4)
IF   v EQ __Pow2(5) - 1
```

| Parameter | Description |
| --- | --- |
| `i` | Constant, 0..31 |

A macro *function* that returns `2^i`. It exists because enabling
`OPTION RENAMEKEYWORD:<shl>` on 8086 also disables the assembler's **SHL
expression operator** (both share the same token), so SMART.INC cannot use
`1 shl bit` in its own mask arithmetic. Your code has the same restriction:

> On 8086, with SMART.INC included, the `SHL`/`SHR` operators are not usable
> in constant expressions. Use `__Pow2(n)`, multiplications or the native
> instruction `??shl` instead.

With `.186` and above the shift macros are not defined, `RENAMEKEYWORD` is
never enabled, and the normal `SHL`/`SHR` operators keep working.

---

## Compatibility notes

- **Assemblers**: [ASMC](https://github.com/nidud/asmc), JWasm and UASM.
  Only standard MASM macro facilities are used: `MACRO`/`ENDM`,
  `IF`/`ELSEIFIDNI`/`IFB`, `FOR`/`REPEAT`/`WHILE`, `:VARARG`, `OPATTR`,
  `EXITM %`, `TEXTEQU`-free string handling and `OPTION RENAMEKEYWORD`.
  `OPTION RENAMEKEYWORD` is an ASMC/JWasm/UASM extension: Microsoft MASM
  does not implement it (its `OPTION NOKEYWORD` deletes the keyword instead
  of renaming it), so **ml.exe cannot assemble this file**.
- **No segment, model or calling-convention assumptions**: SMART.INC defines
  macros only; it does not open segments, reserve data or alter `OPTION`
  settings beyond the keyword renames listed above.
- **Include guard**: a second `include SMART.INC` is a no-op
  (`IFNDEF __SMART_INC__`).
- **Keyword renames**: on the CPU levels where a macro overrides an
  instruction mnemonic, the original instruction stays available under its
  `??`-prefixed name (`??shl`, `??shr`, `??movzx`, `??push`, `??mov`, ...).
  The `??` prefix (instead of `@@`) is required by an ASMC quirk:
  identifiers starting with `@` or `_` are never looked up in the keyword
  table, so a `@@`-prefixed replacement name cannot reach the renamed
  instruction there (JWasm/UASM accept any identifier, which hides the
  difference).
- The 8086-only groups are gated on `@Cpu`: include the file **after** the
  CPU directive or the wrong group may be selected. The `mov` rename (v3.0)
  applies at every CPU level.

## Error checking

Every macro validates its arguments at assembly time and reports a clear
`forced error` instead of emitting wrong code:

| Situation | Error |
| --- | --- |
| Negative shift count | `shift: count cannot be negative` |
| `mov` with no operands | `mov: missing operands` |
| `FastIMul` with `dest` = `src` | `FastIMul: dest and src must be different operands` |
| `FastIMul`/`FastMul` constant out of range | `const out of range` / `factor out of range` |
| `movzx`/`movsx` into SI/DI/... | `destination not supported, use AX/BX/CX/DX` |
| Bit index below 0 or above 31 | `bit index must be between 0 and 31` |
| Field with `lo + width > 32` or `width = 0` | `invalid range of lo/width` |
| `getfield` with both operands in memory | `dest and src cannot both be memory` |
| `push`/`pop` with no operands | `missing operands` |

Out-of-range *values* that the macro cannot see (e.g. bit 9 of `AL`) are
still caught by the assembler itself.

## Testing

The file ships with a 104-case automated battery (`scripts/verify_smart.py`
plus the `tests/` sources):

1. `t8086.asm` and `t386.asm` are assembled to raw binaries.
2. The binaries are disassembled (Capstone) and executed instruction by
   instruction on a register/flag/stack simulator; after every `NOP` marker
   the full expected register/flag/stack state is compared (shift chains,
   widenings, multi-push/pop, every `FastIMul`/`FastMul` strategy including
   edge constants such as `0`, `±1`, `−32768`, `65535`, `0x5555`, `0xFFFF`,
   all bit/field operations with word, byte and dword operands).
3. `t8086b.asm` re-checks the memory-operand variants and the double-include
   guard by disassembly.
4. Ten `err*.asm` files confirm that every invalid invocation fails with the
   expected error message.

All 104 checks pass (assembled with JWasm, the same macro engine that ASMC
inherits; cross-checked against the ASMC 2.40 sources and test suite).

**v3.0 note:** before releasing, extend the battery with `mov` cases: an
eliminated `mov ax, ax` (zero bytes emitted), a forced `??mov ax, ax`
(2 bytes), pass-through of the remaining forms (`mov ax, bx`, `mov ax, 0`,
memory operands, segment registers) and an `err` file for `mov` with no
operands. Every pre-v3.0 expansion must stay byte-identical.

**v3.1 note:** the battery's `FastMul` 8086 expectations for the 6,304
factors in the 111..117 cost band change path (real `MUL` → Horner chain);
the reference products are recomputed by the simulator, so re-running the
full battery is enough. Add `FastIMul` 386+ cases with `|const| > 8` (native
`IMUL` path, including `const` = `65535` and `-32768` on both `r16` and
`r32` destinations) and `FastMul` 386+ cases for the nine `LEA` factors.

**v3.2 note:** the `FastIMul` refactor is verified byte-identical (old vs
new chain sequences compared for all 98,304 constants: 0 differences), so
no 8086 expectation changes. Add `FastIMul` 386+ cases for the nine `LEA`
factors with 32-bit register sources, and one `BYTE`-destination case
(`FastIMul al, bl, 45`) to pin the restored chain path.

**v3.3 note:** run the `mov` battery twice, under `SMART` (default) and
under `NOSMART`: SMART output must stay byte-identical to v3.2, and
NOSMART must pass every MOV through, including `mov ax, ax`.

**v3.4 note:** the ASMC build fixes itself (the `TYPE` operator is gone;
`__RegBits` is textual and needs no battery change). Add: `lea` cases
(`lea ax, var` → 3-byte `mov`, indexed and 32-bit pass-throughs,
`??lea` escape) and jump cases on both modes — a backward `je` at
distance 126 (short), 127 (extended), a forward `je` (extended), `@F`/
`@B` targets (short) and `NOSMART` pass-throughs. The extended jumps
must be verified on the 8086 simulator: `j<inv>` skip displacement (+3)
and the near `JMP` displacement are the bytes that can go wrong.

**v3.5 note:** the 14 alias jump macros (`jz`, `jc`, `jpe`...) now have
their own renames — add one battery case per alias (both modes) so no
alias can again fall through to the native instruction. Add `xchg ax, ax`
(SMART: 0 bytes, NOSMART/`??xchg`: 1 byte) and an out-of-segment include
test (include SMART.INC before any segment opens; nothing may be emitted
at include time).

**v3.6 note:** add `jcxz`/`loop` cases on both modes — a backward target
at distance 126 (short), 127 (trampoline), a forward target (trampoline),
`@F`/`@B` (short), `NOSMART`/`??jcxz`/`??loop` pass-throughs — plus the
trampoline semantics: flags identical to the native instructions and the
`CX = 0` wrap still taken. On the 8086 simulator, check the trampoline's
+2 short hop and the near `JMP` displacement.

## Version history

### v3.6 (current)

- **The last "jump destination too far" hole is closed: `jcxz` and `loop`
  are intercepted now** (`??jcxz` / `??loop` escapes). They are the only
  two jumps with neither an inverse nor a long encoding: `OPTION LJMP`
  lengthens the conditional jumps automatically, but a `jcxz` or `loop`
  whose destination lands more than 127 bytes away dies with
  `error A2075: jump destination too far` and nothing in the assembler can
  save it (reported by 4VIEW.ASM on the 386 build: A2075 by 2 bytes — one
  forward conditional jump extended by the v3.4 macros grew the code
  between a short-only jump and its target by exactly one 2-to-5-byte
  extension). The macro keeps the 2-byte form for backward targets
  measured in range (the same `$ - target <= 126` rule as the conditional
  jumps) and otherwise emits the trampoline `jxx near-label / jmp over /
  near-label: jmp target`: `jcxz` touches no flags, and the `loop`
  trampoline keeps the real `LOOP` as the decrementing instruction, so the
  flags and the `CX = 0` wrap are preserved exactly. `NOSMART` passes both
  through in the native form. `loope`/`loopne`/`loopz`/`loopnz` stay
  native: they test `ZF`, and a flag-safe bridge would cost more than the
  instruction is worth.

### v3.5

- **Bug fix: the 14 alias jump macros broke ASMC.** `jz`, `jnz`, `jc`,
  `jnc`, `jna`, `jnae`, `jnb`, `jnbe`, `jng`, `jnge`, `jnl`, `jnle`, `jpe`
  and `jpo` were defined without freeing their keyword first, so ASMC
  parsed `jz MACRO target` as the **`jz` instruction**: `error A2034: must
  be in segment block` at the definition line, the macro body then executed
  as main-line code (its `__Jcc` expansion emitted instructions outside any
  segment) and the orphaned `ENDM` aborted with `fatal error A1008:
  unmatched macro nesting` (reported by 4VIEW.ASM, which includes
  SMART.INC outside a segment). Every alias now has its own
  `option renamekeyword` line — the same rule every other taken-over
  mnemonic has followed since v2.0 — and the `??jz`-style escapes exist as
  a side effect.
- **Version constant.** The inclusion guard now carries the version:
  `__SMART_INC__ = 350` means v3.5 (`major*100 + minor`). Test it with
  `IF __SMART_INC__ GE 350` before using a newer feature.
- **`xchg reg, reg` joins the redundant-instruction elimination**
  (`??xchg` escape). Under SMART, `xchg ax, ax` assembles to nothing —
  it changes no register, no memory and no flags. Careful: the 1-byte
  `xchg ax, ax` (opcode 90h) is the classic single-byte NOP used for
  alignment padding; `??xchg ax, ax` forces the byte back, and NOSMART
  passes everything through.

### v3.4

- **Bug fix: `FastIMul` failed to assemble on ASMC.** The v3.2
  register-size checks used the `TYPE` operator, which **ASMC disables by
  default** (it wants `TYPEOF` or the `-Zne` switch, and neither is
  portable to JWasm/UASM; the `OPATTR` word carries no size bits either).
  4VIEW.ASM died with `error A2006: undefined symbol : TYPE`. The checks
  are now textual: a new internal `__RegBits` function matches the operand
  name against the 24 register names with `IFIDNI` and returns 1, 2, 4 or
  0. The emitted code is unchanged on every assembler; on ASMC it
  assembles again.
- **New SMART optimization: `lea reg16, var` → `mov reg, OFFSET var`.**
  `lea` is taken over (`??lea` escape) and the substitution fires only for
  a direct memory source and a 16-bit register destination, where `MOV` is
  strictly shorter (3 vs 4 bytes); indexed sources, stack variables and
  32-bit destinations pass through byte-identical.
- **New SMART optimization: extended conditional jumps.** All 30
  conditional mnemonics are taken over (`??jxx` escape). Backward targets
  are measured and extended (`j<inv>` over `jmp target`) only when the
  distance exceeds the short range; forward references and external
  targets always take the extended form, so no conditional jump can die
  with "jump destination too far". `@F`/`@B` targets pass through with
  native semantics; the trampoline label is a macro `LOCAL`.
- **Considered and NOT implemented:** minimum-size instruction encodings
  (ASMC/JWasm/UASM already pick the sign-extended imm8 forms and short
  `JMP`s natively) and cross-instruction stack optimizations (a macro
  expansion cannot see its neighboring instructions; the multi-operand
  `push`/`pop` macros remain the tool for that).

### v3.3

- **New directives: `SMART` / `NOSMART`**, the TASM-style optimization
  switch. The default is SMART, as in TASM. `NOSMART` disables the only
  automatic transformation of the file (the `mov reg, reg` elimination of
  the `mov` macro): every MOV then passes through byte-identical until the
  next `SMART`. The rest of the library is not affected, because its macros
  are explicit calls the user wrote on purpose, not silent rewrites of
  instructions the assembler would also accept. Implemented as one global
  assembly-time flag (`??smart`) read by the `mov` expansion, which
  contains no `WHILE` and defines no variables of its own, so it stays
  outside the ASMC v2.1 re-read bug pattern.

### v3.2

- **`FastIMul` 386+: `LEA` shortcuts for register operands.** With `dest`
  and `src` both 32-bit registers, factors `3`, `5`, `9` are one `LEA`
  (`lea dest, [src+src*2/4/8]`, 1–2 cycles) and `6`, `10`, `12`, `18`,
  `20`, `24` are `LEA` + `ADD`/`SHL`, mirroring `FastMul`'s v3.1 tree
  (1–2 instructions vs 3–7 for the chain or `IMUL`). `WORD` destinations
  keep the chain: the SIB byte does not exist in 16-bit addressing.
- **`FastIMul` byte fix.** The three-operand `IMUL` has no byte encoding,
  so a `BYTE` `FastIMul` — which the chain always supported — would have
  failed to assemble since v3.1. The `IMUL` path now requires a non-`BYTE`
  destination (`TYPE dest NE 1`) and bytes stay on the chain.
- **`FastIMul` chain deduplicated.** The two 15-block branches (negative
  and positive constants) differed only in the magnitude expression, and
  the `__IMag` helper already unifies it: one `__Horn` helper now holds
  the single Horner step, `FastIMul` calls it 15 times, and the negative
  case appends `NEG`. The expansion stays parameter-only (the ASMC v2.1
  doctrine) and the emitted code is byte-identical for all 98,304
  constants (verified by exhaustive comparison); ~95 source lines shorter.
- **Shared validators.** The five flag macros use one `__BitRange` check
  and `setfield`/`getfield` one `__FieldRange` check; the error texts are
  unchanged (the macro name is passed as a parameter into the `.ERR`).

### v3.1

- **`FastMul` 386+: `LEA` shortcuts.** Factors `3`, `5`, `9` are one `LEA`
  (`lea eax, [eax+eax*2/4/8]`, 1–2 cycles vs 13–42 for `IMUL r32, imm`);
  `6`, `10`, `12`, `18`, `20`, `24` are `LEA` + `ADD`/`SHL`. Every other
  factor keeps the native `IMUL`; the `DX:AX` contract is unchanged.
- **`FastIMul` 386+: native `IMUL` for dense constants.** With a register
  destination and a 16-bit magnitude greater than 8, one three-operand
  `imul dest, src, const` (9–22 cycles r16, 9–38 r32) replaces chains of up
  to 30 instructions. Magnitudes ≤ 8, memory destinations and CPUs below
  the 386 keep the shift/add chain. Constants 32768..65535 are passed as
  their negative two's complement equivalent so the `DWORD` contract holds.
- **`FastMul` MUL-fallback threshold: 110 → 117 estimated cycles.** The old
  model ignored the 5-cycle fixed overhead of the chain and priced `MUL` at
  110 when `mov cx, imm` + `MUL r16` really costs 122–137. The 6,304 factors
  in the 111..117 band switch from `MUL` to the Horner chain (verified
  exhaustively); truly dense factors (≥ 10 set bits) still take the real
  `MUL`, which remains the best 8086 option for them.
- **`FastMul`'s assembly-time variables are now `LOCAL`** (`fmF`, `fmHi`,
  `fmOnes`, `fmT`, `fmJ`, `fmM`, `fmK`, `fmP`, `fmI`): no user symbol can
  collide with them and no state leaks between expansions.
- **Analyzed and rejected: a `(2^k + 1) · 2^j` "inverse Mersenne" shortcut.**
  For every one of the 120 factors of that form, the Horner chain already
  emits exactly the same instructions in the same order (the top bit is
  implicit in the initial accumulator), so the shortcut would add macro code
  without changing one byte of output.

### v3.0

- **New macro: `mov` with `mov reg, reg` elimination.** `mov` is now taken
  over with `OPTION RENAMEKEYWORD:<mov>` at every CPU level. When both
  operands are the same register the expansion is empty; every other `MOV`
  passes through byte-identical. See
  [Redundant reg, reg elimination (mov, xchg)](#redundant-reg-reg-elimination-mov-xchg).
- **`mov reg, 0` → `xor reg, reg` was considered and rejected on purpose:**
  `XOR` destroys the flags while `MOV` leaves them untouched, so the
  substitution can silently break flag-dependent code. SMART.INC only
  removes instructions that provably do nothing.
- **Escape hatch:** `??mov ax, ax` forces the original 2-byte instruction
  (timing delays, patch holes in self-modifying code).
- **Documentation fixes:** the keyword-renamed originals are reached with
  the `??` prefix (`??shl`, `??push`, `??mov`, ...), not `@@` — ASMC never
  looks up `@`/`_`-prefixed identifiers in the keyword table — and the
  supported assemblers are ASMC/JWasm/UASM, since Microsoft MASM does not
  implement `OPTION RENAMEKEYWORD`.

### v2.43

Source simplification with zero code change: the eight 8086 shift macros
share one `__SHx` helper; assembled output byte-identical to v2.42.

### v2.42

`FastMul` 386+ paths now really deliver the `DX:AX` contract (`shld
edx, eax, 16`); the battery compares the full `DX:AX` pair for every 16-bit
multiplicand.

### v2.4

`FastMul`, 386+: every non-power-of-two factor is one native `IMUL`.

### v2.3

`FastMul` power-of-two factors: `movzx`/`shl` on 386+, two half-window
shifts on 8086 for `k ≥ 8`.

### v2.2

Documentation only; duplicated `FastIMul` doc block removed.

### v2.1

ASMC fixes: `??`-prefixed replacement names, parameter-only `FastIMul`
expansion (no assembly-time variables), `setfield` full-width and
over-wide field handling.

### v2.0

Rewrite: `movsx`, multiple `push`/`pop`, bit and field macros, Mersenne
shortcut in `FastMul`, `SHx` with `CL`/omitted/negative counts.

## Repository layout

```
SMART.INC                 the macro library (drop it next to your sources)
README.md                 this file
scripts/verify_smart.py   automated verification (assembly + simulation)
scripts/tests/            test sources: t8086.asm, t386.asm, t8086b.asm,
                          err1..10.asm + a copy of SMART.INC for the includes
```

To run the battery yourself:

```sh
JWASM=/path/to/assembler python3 scripts/verify_smart.py
```

(Requires a MASM-compatible assembler such as
[ASMC](https://github.com/nidud/asmc/releases) or JWasm, pointed to by the
`JWASM` environment variable, plus `pip install capstone`.)