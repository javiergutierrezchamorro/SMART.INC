# SMART.INC & SMARTPP

**Copyright (c) Javier Gutiérrez Chamorro (Guti)**

**TASM-style optimization macros** and a **conservative peephole pre-processor** for classic x86 assembly (8086 through 386+, with limited x86-64 and x87 support).

| Component | Role |
| --- | --- |
| **[SMART.INC](SMART.INC)** | Single include file: macros that rewrite instructions *inside* a macro expansion. |
| **[SMARTPP.C](SMARTPP.C)** | External one-file C tool: reads `.asm` source (following `INCLUDE`), applies provably-safe peephole rewrites *across* consecutive instructions, writes the result. |

Target assemblers: **[ASMC](https://github.com/nidud/asmc)**, **JWasm**, **UASM**. SMARTPP also accepts GNU AS / AT&T (`-att`).

---

## SMARTPP overview

```sh
gcc -O2 -o smartpp SMARTPP.C
smartpp -m386 -o out.asm in.asm
```

| Option | Meaning |
| --- | --- |
| `-m86` … `-m686` / `-m64` | Initial CPU level (default 8086). Source directives override. |
| `-att` / `-intel` | Force AT&T or Intel syntax. |
| `-I DIR` | Include search path (repeatable). |
| `-noinclude` | Do not follow `INCLUDE` at all. |
| `-Oz` | Prefer size over speed. |
| `-mark` / `-nomark` | Rewrite markers in output (default: on). |
| `-v` / `-nv` | Per-line notices on stderr (default: on). |
| `-color` / `-ncolor` | Force colored diagnostics on/off (default: **on**). |
| `-o FILE` | Output file (`-` = stdout). |

### INCLUDE (preprocessor default)

`INCLUDE` / `include` / `.include` are **expanded by default**: the directive is replaced by the full file contents (recursive, with cycle detection). Search order: directory of the including file → `-I` paths → CWD. Missing files warn and leave the directive. Expanded regions are marked with `; SMARTPP include begin/end: path`.

Use `-noinclude` only if you want the old one-file behaviour.

Progress is reported (`including...` / `included N lines`); the summary table is printed **before** writing the output file.

### v2.16

- `-v` now lists every applied optimization: all `st[]` counter sites (the v2.13/v2.14 wave P344, P351–P356, P360–P362, P365–P367, P371, P373, P377–P378, P380–P386) emit a `vlog` line.
- Const-propagation soundness fixes: any write to `esp` (add/sub/mov/xchg) breaks the tracked push/pop LIFO pairing, and a `pop` without a matching tracked push now kills the popped family instead of keeping a stale value.
- More imul factors (P380): the two-lea engine now covers m = 17, 19, 21, 25, 27, 37, 41, 45, 73, 81 (table-driven, dead scratch register). 33 and 35 are unreachable with two leas and legal SIB scales.
- Tail call across the epilogue (P383, `-Ox`): `call F / mov sp,bp / pop bp / ret` (or `call F / leave / ret`) → the restoration is kept and `ret` becomes `jmp F`, when the matching `push bp / mov bp,sp` prologue is proven and nothing is pushed between prologue and call (so F reads no stack arguments).

### v2.15

- Coverage review: rules documented but never implemented were checked against the firing set. Implemented: P17, P41, P47, P56, P63, P68, P70, P79, P80, P82, P85–P87, P89.
- P57 (`lea R,[R+R]` → `shl R,1`) is **not** implemented: covered by P365 (`lea [S+S]` → `lea [S*2]`) plus P63.
- P80 header correction: all three instructions are deleted (the writer's store is dead); the old "the writer is kept" text was unsound.
- P88 correction: the documented `rol eax,16 / xchg al,ah / rol eax,16` pattern is not a bswap; the implemented (and correct) idiom is `xchg al,ah / rol eax,16 / xchg al,ah` → `bswap eax`.

### v1.97

- INCLUDE expansion is the default again (preprocessor semantics).
- Removed `-expandinc` / “skip SMART.INC” behaviour.

### v1.96

- Extra strength rules P170–P172.

---

## Architecture

```text
read + INCLUDE expand
      ↓
scan_indefs / detect_use32 / collect_labels
      ↓
for pass in 1..MAX_PASSES:
    run_pass()
        for each live instruction line:
            bespoke C rules (control flow, multi-way patterns)
            try_table_rules()   ← declarative engine
      ↓
write optimized source + summary table
```

**Bespoke C rules** handle control flow (jump threading, bridge inversion, unreachable code) and patterns that need multi-path flag/register scans.

**Table rules** (`g_rule_tbl[]`) match 1–3 consecutive instructions by mnemonic + operand patterns + preconditions, then delete or rewrite via templates. Prefer the table for new work.

---

## How to add a new table rule

### 1. Choose a free P-number

Pick an unused number in the summary `rname[]` array (around the end of `main`) and in `g_rule_tbl`. Prefer contiguous IDs.

### 2. Describe the pattern

Each rule is one `struct rule`:

```c
{ n, rule_no,
  { /* pat[0] */ { "mnem", opclass, op0, op1, nops },
    /* pat[1] */ { ... },   /* only if n >= 2 */
    /* pat[2] */ { ... } }, /* only if n >= 3 */
  preconditions,
  { /* act[0] */ { ACT_DEL or ACT_REW or ACT_KEEP, "template" },
    /* act[1] */ { ... },
    /* act[2] */ { ... } },
  "short description" }
```

### 3. Operand patterns

| Macro | Meaning |
| --- | --- |
| `RR_('a')` | Any register; bind capture `a` (family + width) |
| `SM_('a')` | Same register as capture `a` (family **and** width) |
| `DF_('a')` | **Different** register family from capture `a` (v1.91) |
| `IM_` | Immediate or `OFFSET` expression |
| `IV_(n)` | Immediate equal to constant `n` |
| `PW2_` | Immediate that is a power of two ≥ 2 (v1.91) |
| `AN_` | Anything (or missing) |
| `RC_(RC_16)` | Register of a width class, no capture |

Register classes: `RC_ANY`, `RC_8`, `RC_16`, `RC_32`, `RC_64`.

### 4. Preconditions (`pre` bitset)

| Flag | Meaning |
| --- | --- |
| `PRE_FLAGS_DEAD_ALL` | All six status flags dead on every path |
| `PRE_FLAGS_DEAD_CF` | CF dead |
| `PRE_FLAGS_DEAD_AF` | AF dead |
| `PRE_REG_DEAD_RA` | Capture `a` register dead after the match |
| `PRE_REG_DEAD_B` | Capture `b` dead |
| `PRE_NOT_SP` | Capture `a` is not SP/ESP/RSP |
| `PRE_NO_CPU_8086` | CPU ≥ 186 |
| `PRE_CPU_386` | CPU ≥ 386 |
| `PRE_CPU_486` | CPU ≥ 486 |
| `PRE_CPU_X64` | Long mode |
| `PRE_NO_USE32` | No 32-bit segment in the unit |
| `PRE_INTEL` | Intel syntax only |
| `PRE_FPU` | x87 enabled (not `.NO87`) |
| `PRE_NEXT_IS_JCC` | Next code line is a conditional jump |
| `PRE_NEXT_JCC_NO_CF` | That jcc does not read CF |
| `PRE_NEXT_JCC_ZF_ONLY` | That jcc reads only ZF |

Combine with `|`. Use `0` when no precondition is needed.

### 5. Actions and templates

| Action | Effect |
| --- | --- |
| `ACT_DEL` | Delete the instruction (keep a leading label) |
| `ACT_KEEP` | Leave unchanged |
| `ACT_REW` | Replace body with expanded template |

**Template tokens:**

| Token | Expands to |
| --- | --- |
| `$a` | Register bound to capture `a` at its width |
| `$a8` / `$a16` / `$a32` | Same family at forced width |
| `$K` | First immediate (`imm0`) as written |
| `$K1` | Second immediate (`imm1`) |
| `$Knot` | Bitwise NOT of `imm0` (v1.91) |
| `$Kneg` | Negation of `imm0` (v1.91) |
| `$Klog2` | log₂ of `imm0` when it is a power of two (v1.91) |

### 6. Examples

**Delete a no-op:**

```c
{ 1, 146,
  { { "shl", 0, RR_('a'), IV_(0), 2 } },
  0,
  { { ACT_DEL, NULL } },
  "shl R,0 -> delete" },
```

**Rewrite with flag gate:**

```c
{ 1, 143,
  { { "add", 0, RR_('a'), SM_('a'), 2 } },
  PRE_FLAGS_DEAD_ALL,
  { { ACT_REW, "shl $a, 1" } },
  "add R,R -> shl R,1 (flags dead)" },
```

**Two-instruction fold with template transform:**

```c
{ 2, 144,
  { { "mov", 0, RR_('a'), IM_, 2 },
    { "not", 0, SM_('a'), AN_, 1 } },
  0,
  { { ACT_REW, "mov $a, $Knot" }, { ACT_DEL, NULL } },
  "mov R,imm / not R -> mov R,~imm" },
```

**Different second register (`DF_`):**

```c
{ 2, 32,  /* conceptual */
  { { "push", 0, RR_('a'), AN_, 1 },
    { "pop",  0, DF_('a'), AN_, 1 } },
  0,
  { { ACT_REW, "mov $b, $a" }, { ACT_DEL, NULL } },
  "push R / pop S -> mov S,R" },
```

(Real P32 still lives in C because capture of the *pop* destination as `$b` needs a second bind; extend with `RR_('b')` on the pop operand when migrating.)

### 7. Wire the summary name

In `main`, extend the `rname[]` string table so the end-of-run summary shows a description for your P-number.

### 8. Test

```sh
printf '    mov ax, 1\n    not ax\n    ret\n' | ./smartpp -m86 -nomark -nv -
# expect: mov ax, -2 / ret
```

Add a case to `test_smartpp.sh`.

### When to stay in C (`run_pass`)

Keep a bespoke C rule when you need:

- Multi-path control flow (jump threading, bridge inversion, unreachable runs)
- Flag/register liveness that is not a simple “all dead after this line”
- Cost models, size gates, or assembler-specific encoding choices
- Patterns longer than three instructions or with intervening labels

The table runs **after** the C rules on each line; C can still claim a pattern first.

---

## Full optimization catalogue

### Identity / redundancy

| Id | Pattern | Result | Notes |
| --- | --- | --- | --- |
| P1 | `mov R,R` / `xchg R,R` | delete | Table + C |
| P3 | `push X` / `pop X` (same) | delete both | Also pushf/popf, pusha/popa |
| P8 | `or`/`and R,R` or `or R,0` / `and R,-1` | `test R,R` or delete | Delete if flags dead |
| P14 | `xchg R,S` / `xchg R,S` | delete both | |
| P15 | `mov R,S` / `mov S,R` | delete second | |
| P18 | `add`/`sub R,0` | delete | Flags dead |
| P20/P146 | shift/rotate `R,0` | delete | |
| P21 | duplicate `cld`/`std`/`cli`/`sti`/`clc`/`stc` | delete second | |
| P22 | `inc R` / `dec R` (pair) | delete both | Flags dead; not SP |
| P23 | `not R` / `not R` | delete both | Table |
| P24 | `neg R` / `neg R` | delete both | Flags dead; not SP |
| P25 | `cmc` / `cmc` | delete both | Table |
| P28 | duplicate `cbw`/`cwde`/`cwd`/`cdq` | delete second | |
| P58 | `xor R,X` / `xor R,X` | delete both | Flags dead; X reg/imm |
| P111–P115 | `or R,0` / `and R,-1` / `xor R,0` | delete | Flags dead |
| P119–P120 | `test`/`cmp R,K` | delete | Flags dead |
| P124 | `lea R,[R]` / `[R+0]` | delete | |
| P126 | `xchg R,R` | delete | |
| P147–P148 | `or`/`and`/`test R,R` | delete | Flags dead |
| P149 | `imul R,2^k` | `shl R,k` | `$Klog2`, 186+ |
| P150 | `test R,R` / `test R,R` | delete second | |
| P151 | `cmp R,R` | delete | Flags dead |
| P152 | `push S` / `mov R,S` / `pop S` | keep mov | 3-instr |
| P153 | `mov R,S` / `mov R,S` | delete second | |
| P154 | `and R,R` | delete | Flags dead |
| P155–P156 | `shl`/`shr R,1` twice | `… R,2` | Flags dead |
| P157 | `xor R,R` / `or R,R` | delete or | Flags dead |

### Strength reduction / idioms

| Id | Pattern | Result | Notes |
| --- | --- | --- | --- |
| P9 | `mov R,0` | `xor R,R` | Flags dead; x64 uses 32-bit xor |
| P10 | `add`/`sub R,±1` | `inc`/`dec R` | CF dead |
| P11 | `cmp R,0` | `test R,R` | AF dead |
| P17 | `lea R,[R+c]` | `add`/`sub`/`inc`/`dec` | Flags dead |
| P32 | `push R` / `pop S` | `mov S,R` | |
| P35 | `mov R32,-1` | `or R32,-1` | Flags dead |
| P36 | `mov sp,bp` / `pop bp` | `leave` | 186+, 16-bit |
| P37 | `xor R,-1` | `not R` | Flags dead |
| P38 | `imul R,2^k` | `shl R,k` | 186+; flags dead |
| P50 | `imul R,2^k+1` | `lea R,[R+R*k]` | 386+; k=1,2,3 |
| P51 | `imul R,-1` | `neg R` | Flags dead |
| P59 | `and R,0` | `mov R,0` | Flags dead → chains to P9 |
| P71/P105 | `sub R,R` | `xor R,R` | AF dead; not SP |
| P141 | `not R` / `inc R` | `neg R` | Flags dead |
| P142 | `neg R` / `dec R` | `not R` | Flags dead |
| P143 | `add R,R` | `shl R,1` | Flags dead |

### Constant folding

| Id | Pattern | Result |
| --- | --- | --- |
| P16 | `add`/`sub R,c1` / `R,c2` | one op with sum (OF dead) |
| P40 | `mov R,i1` / `add|sub R,i2` | `mov R,i1±i2` |
| P52–P55 | `mov R,i` / `shl|and|or|xor R,k` | `mov R, folded` |
| P72–P75 | `mov R,i` / `shr|sar|rol|ror R,k` | `mov R, folded` |
| P144 | `mov R,i` / `not R` | `mov R,~i` (`$Knot`) |
| P145 | `mov R,i` / `neg R` | `mov R,-i` (`$Kneg`) |

### Control flow

| Id | Pattern | Result |
| --- | --- | --- |
| P5 | `jmp`/`jcc` to label that is only another `jmp` | retarget |
| P6 | jump to next code line | delete |
| P7 | `jcc L1` / `jmp L2` / `L1:` | `j⟨not cc⟩ L2` |
| P12 | duplicate consecutive jumps | delete redundant |
| P13 / P13b | code after `jmp`/`ret`/`iret`/… | delete unreachable |

### Widening / compiler idioms (386+)

| Id | Pattern | Result |
| --- | --- | --- |
| P29 | `xor T,T` / `mov L,SRC` | `movzx T,SRC` |
| P30 | same with imm 0..255 | `mov T,imm` |
| P31 | `mov al,SRC` / `cbw` (etc.) | `movsx` |
| P33 | shift pairs that zero-extend | `movzx`/`movsx` |
| P34 | `and R,0xFF` forms | `xor Rh,Rh` or `movzx` |

### x87 (when `.8087`/`.287`/`.387`)

| Id | Pattern | Result |
| --- | --- | --- |
| P129–P130 | `fld`/`fldz` + `fstp st` | delete pair |
| P131 | `fchs` / `fchs` | delete both |
| P132 | `fabs` / `fabs` | keep one |
| P134–P136 | idempotent `ffree`/`fninit`/`fwait` | keep one |
| P137 | `fxch st,st` | delete |

---

## SMART.INC (macros)

Include **after** the CPU directive and **before** the instructions it replaces.

```asm
    .8086
    .MODEL tiny
    include SMART.INC
```

Provides: constant shifts on 8086, emulated `movzx`/`movsx`, multi-operand `push`/`pop`, `FastIMul`/`FastMul`, bit/field helpers, SMART-mode `mov`/`xchg` elimination, `lea→mov OFFSET`, extended conditional jumps / `jcxz` / `loop`. Requires ASMC/JWasm/UASM (`OPTION RENAMEKEYWORD`).

---

## CPU-dependent movzx vs xor+mov

On **486** and **original Pentium**, `xor R,R` / `mov L,src` is preferred over `movzx` (2 clocks vs 3). On **386** and on **P6+/x64**, `movzx` is used instead. The old `-nz` switch was removed; this choice is automatic from the active CPU level.

## Safety notes

- Flag-gated rewrites use a path-sensitive liveness scan; `ret`/`retf` kill all six status flags (ABI does not preserve them).
- `sub R,R → xor R,R` requires **AF dead** (AF is forced 0 by `sub`, undefined after `xor`).
- Memory operands that might be MMIO are treated conservatively.
- SP is excluded from several pair-deletes (interrupt window).

---

## Build & test

```sh
gcc -O2 -Wall -o smartpp SMARTPP.C
./test_smartpp.sh          # rule-level regression
```

---

## License / provenance

SMART.INC is based on earlier work by Javier Gutiérrez Chamorro (Guti). Both components stay dependency-free and easy to vendor.