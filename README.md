# SMART.INC — TASM-style optimization macros for MASM and ASMC

**SMART.INC** is a single, dependency-free include file that brings back the
code-generation conveniences that **Borland Turbo Assembler (TASM)** used to
provide out of the box, for use with **MASM 6.0+**, **[ASMC](https://github.com/nidud/asmc)**
and **[JWasm](https://github.com/jwasm/jwasm)**. It is based in previous **[SMART.INC by Javier Gutiérrez Chamorro (Guti)](https://www.javiergutierrezchamorro.com/smart-inc/)**.

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
  - [FastIMul](#fastimul-dest-src-const)
  - [FastMul](#fastmul-const)
  - [Single bits (flags)](#single-bits-flags)
  - [Bit fields](#bit-fields)
  - [__Pow2 (internal helper)](#__pow2-internal-helper)
- [Compatibility notes](#compatibility-notes)
- [Error checking](#error-checking)
- [Testing](#testing)
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
no post-processing), so the same source assembles with MASM 6.0+, ASMC and
JWasm unchanged.

What it implements:

| Group | Macros | Purpose |
| --- | --- | --- |
| Shifts | `shl` `shr` `sal` `sar` `rol` `ror` `rcl` `rcr` | Constant count shifts/rotates on 8086 |
| Widening moves | `movzx` `movsx` | Emulated widening moves on CPU < 386 |
| Stack | `push` `pop` | Several operands in one statement |
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
3. Multiple inclusion is safe: the file is guarded by `__SMART_INC__`.

| CPU directive | Shift macros | MOVZX/MOVSX macros | Everything else |
| --- | --- | --- | --- |
| `.8086` (default) | defined | defined | defined |
| `.186` / `.286` | not defined (native immediate shifts) | defined | defined |
| `.386` and up | not defined | not defined (native MOVZX/MOVSX) | defined |

Everything is defined for all CPU levels unless the table above says
otherwise: `push`/`pop`, `FastIMul`, `FastMul`, the flag macros and the field
macros work with 8-, 16- and 32-bit operands (`.386` needed only for the
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
- The real instructions remain available internally as `@@shl`, `@@shr`, ...
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
| `movsx ax, al` | `mov al, al` + `cbw` | flags |
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
of `SHL`/`ADD`. `dest` and `src` must be different operands.

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
| anything else | general add-shift chain on `src` | **no** (it is shifted in place) |

A negative constant ends the expansion with `NEG dest`.

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
| dense pattern, up to ~110 estimated cycles | MSB-to-LSB Horner chain on the `DX:AX` accumulator |
| dense pattern, worse than hardware | real `MUL` (`mov cx, const` + `mul cx`) |

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
> instruction `@@shl` instead.

With `.186` and above the shift macros are not defined, `RENAMEKEYWORD` is
never enabled, and the normal `SHL`/`SHR` operators keep working.

---

## Compatibility notes

- **Assemblers**: MASM 6.0+, [ASMC](https://github.com/nidud/asmc) and
  JWasm. Only standard MASM macro facilities are used: `MACRO`/`ENDM`,
  `IF`/`ELSEIFIDNI`/`IFB`, `FOR`/`REPEAT`/`WHILE`, `:VARARG`, `OPATTR`,
  `EXITM %`, `TEXTEQU`-free string handling and `OPTION RENAMEKEYWORD`
  (MASM 6.1+, ASMC, JWasm).
- **No segment, model or calling-convention assumptions**: SMART.INC defines
  macros only; it does not open segments, reserve data or alter `OPTION`
  settings beyond the keyword renames listed above.
- **Include guard**: a second `include SMART.INC` is a no-op
  (`IFNDEF __SMART_INC__`).
- **Keyword renames**: on the CPU levels where a macro overrides an
  instruction mnemonic, the original instruction stays available under its
  `@@`-prefixed name (`@@shl`, `@@shr`, `@@movzx`, `@@push`, ...).
- The 8086-only groups are gated on `@Cpu`: include the file **after** the
  CPU directive or the wrong group may be selected.

## Error checking

Every macro validates its arguments at assembly time and reports a clear
`forced error` instead of emitting wrong code:

| Situation | Error |
| --- | --- |
| Negative shift count | `shl: count cannot be negative` |
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
