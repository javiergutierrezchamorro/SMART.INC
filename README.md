# SMART.INC & SMARTPP

**TASM-style optimization macros** and a **conservative peephole pre-processor** for classic x86 assembly (8086 through 386+, with limited x86-64 and x87 support).

| Component | Role |
| --- | --- |
| **[SMART.INC](SMART.INC)** | Single include file: macros that rewrite instructions *inside* a macro expansion (shifts on 8086, multi-operand `push`/`pop`, `FastIMul` / `FastMul`, bit/field helpers, SMART-mode jumps, etc.). |
| **[SMARTPP.C](SMARTPP.C)** | External one-file C tool: reads an `.asm` source, applies provably-safe peephole rewrites *across* consecutive instructions, writes the result. The assembler then re-computes every displacement, so removing bytes cannot corrupt jumps. |

SMART.INC can only see its own arguments. SMARTPP closes that gap. They work well together and independently.

Target assemblers: **[ASMC](https://github.com/nidud/asmc)**, **JWasm**, **UASM** (MASM-family syntax). SMARTPP also accepts GNU AS / AT&T input (`-att`).

---

## Why

TASM’s *smart* mode silently produced better code than MASM in common cases (constant shifts on 8086, multi-operand stack ops, out-of-range conditional jumps). MASM / ASMC do not. SMART.INC restores that with plain macros. SMARTPP goes further: patterns that span two or more real instructions (dead stores, jump threading, constant folding, compiler idioms from Turbo Pascal / Borland C / Watcom) cannot be expressed inside a macro at all.

Typical use cases: DOS applications and games, boot sectors, demoscene, ROM code — anywhere hand-written 16-bit (or mixed 16/32-bit) code still matters.

---

## SMART.INC (quick start)

```asm
    .8086                  ; CPU directive FIRST
    .MODEL tiny
    include SMART.INC      ; then the include
    .CODE

start:
    shl  ax, 4             ; four 1-bit shifts on 8086
    mov  ax, ax            ; eliminated under SMART
    movzx bx, al           ; mov bl,al / xor bh,bh
    FastIMul cx, bx, 45    ; cx = bx * 45, no IMUL
    FastMul  1000          ; DX:AX = AX * 1000
    setflag ax, 3          ; or  ax, 8
    setfield ax, 4, 3, 7   ; insert 7 into bits 4..6
    getfield bx, ax, 4, 3  ; bx = bits 4..6 of ax
    ret
END start
```

### Include rules

1. Include **after** the processor directive (`.8086`, `.186`, `.286`, `.386`, …). `@Cpu` is evaluated at the include point.
2. Include **before** the first instruction the file replaces (`OPTION RENAMEKEYWORD`).
3. Multiple inclusion is safe (`__SMART_INC__` carries the version as `major*100 + minor`).

| CPU directive | Shift macros | MOVZX/MOVSX | Everything else |
| --- | --- | --- | --- |
| `.8086` (default) | defined | defined | defined |
| `.186` / `.286` | not defined (native imm shifts) | defined | defined |
| `.386` and up | not defined | not defined (native) | defined |

`SMART` / `NOSMART` toggle automatic rewrites (`mov reg,reg` elimination, `lea reg16,var` → `mov OFFSET`, extended conditional jumps / `jcxz` / `loop`). Explicit macros (`FastIMul`, flag helpers, multi-`push`) are never gated by that switch.

Original instructions remain available under a `??` prefix (`??mov`, `??shl`, `??je`, …) because of an ASMC keyword-lookup quirk.

See the macro reference inside [SMART.INC](SMART.INC) and the detailed tables in the historical README sections of this repository for full expansion rules, error messages, and the verification battery notes.

**Requirement:** `OPTION RENAMEKEYWORD` (ASMC / JWasm / UASM). Microsoft MASM’s `OPTION NOKEYWORD` deletes the keyword instead of renaming it, so **ml.exe cannot assemble this file**.

---

## SMARTPP

A single standard-C source (`SMARTPP.C`). No external libraries beyond the C library.

### Build

```sh
# GCC / Clang
gcc -O2 -o smartpp SMARTPP.C

# MSVC
cl /O1 /W3 SMARTPP.C

# Open Watcom (DOS 32-bit example)
wcl386 -os -d1 SMARTPP.C
```

### Usage

```text
smartpp [options] [in [out]]
smartpp [options] -o out in
```

| Option | Meaning |
| --- | --- |
| `-m86` / `-m186` / `-m286` / `-m386` / `-m486` / `-m586` / `-m686` / `-m64` | Initial CPU level (default 8086). A `.386` / `.X64` / … directive in the source overrides from that line on. |
| `-att` / `-intel` | Force AT&T or Intel operand order (otherwise auto-detected). |
| `-nz` | Keep `xor`+`mov` and shift pairs that `movzx`/`movsx` would replace (smaller but slower on 486/Pentium). |
| `-Oz` | Prefer size over speed where both forms exist. |
| `-mark` / `-nomark` | Enable / disable trailing `; SMARTPP … (Pn)` comments on rewritten or deleted lines (default: **on**). |
| `-v` / `-nv` | Enable / disable per-line “rule fired” notices on stderr (default: **on**). End-of-run summary always prints. |
| `--ncolor` | Disable colored diagnostics (default: color on stderr only when it is a TTY). |
| `-o FILE` | Output file (default: stdout). `-` means stdin/stdout. |

Example with SMART.INC:

```sh
smartpp -m386 -o 4view.pp.asm 4view.asm
asmc -c -Fo4view.obj 4view.pp.asm
```

### What it rewrites (overview)

Rules are numbered **P1 … P140** (some numbers withdrawn). All are designed to be *provably* value- and (where needed) flag-safe. A local flag-liveness scan and a dead-register walk gate any rewrite that would change observable flags or register contents.

Groups of rules:

| Group | Examples |
| --- | --- |
| Redundant ops | `mov R,R` / `xchg R,R` deleted; `push X`/`pop X`; double `xchg`; `not`/`neg`/`cmc` pairs |
| Dead stores | `mov R,…` fully overwritten before any read of `R` |
| Jump control | Thread `jmp`/`jcc` through another `jmp`; delete jump to next line; invert `jcc` over a bridge `jmp`; unreachable code after `jmp`/`ret`/`iret`/… |
| Flag-aware strength reduction | `mov R,0` → `xor R,R`; `add R,1` → `inc R`; `cmp R,0` → `test R,R`; `or`/`and R,R` → `test R,R` |
| Constant folding | Fold consecutive `add`/`sub`; fold `mov imm` + `shl`/`and`/`or`/`xor`; `imul` by power of two → `shl` |
| Addressing | `lea` → `add`/`mov`/`inc`/`dec` when equivalent; LEA fusion; scale forms → `shl` |
| Compiler idioms (386+) | `xor T,T` / `mov L,SRC` → `movzx`; `mov al,SRC` / `cbw` → `movsx`; `push R`/`pop S` → `mov`; `leave` / `enter` patterns |
| x87 (when `.8087`/`.287`/`.387`) | Collapse `fld`/`fstp` pairs, double `fchs`, idempotent `fabs`/`ffree`/`fninit`/`fwait` |

New rules that fit the declarative pattern table (operand shapes + preconditions + rewrite templates) should be added there; older bespoke C blocks in `run_pass()` remain for patterns the table cannot express yet (jump threading, multi-line control flow, some memory forms).

### Design limits (intentional)

- One file per run: `INCLUDE`d files are not followed (run SMARTPP on each unit, or on the assembler’s preprocessed output).
- Lines longer than 8191 characters pass through untouched.
- Conditional assembly is not evaluated: a `.386` inside a disabled `IF 0` block still raises the CPU level from that line on.
- Computed / indirect jumps are opaque by construction.
- Memory operands that might be MMIO are treated conservatively (e.g. dead-store deletion does not remove loads from memory).

### Architecture of `SMARTPP.C` (one file)

```text
header comment          rule catalogue and history
includes / defines
register table          families, widths (8/16/32/64 + x87 ST)
line store              chunked arrays (DOS-friendly allocations)
parser                  Intel + AT&T, labels, comments, CPU directives
analysis                flag_sets / flags_clear, reg_dead_after
table rule engine       declarative patterns (v1.85+)
run_pass()              bespoke multi-instruction rules + table fallback
main / usage            CLI, multi-pass fixed point, summary table
```

Passes run until a fixed point or `MAX_PASSES` (chained rewrites such as `xor R,R` / `dec R` → `mov R,-1` → `or R,-1` converge without extra machinery).

---

## Compatibility notes

- **SMART.INC** needs ASMC, JWasm or UASM (`OPTION RENAMEKEYWORD`). Not MASM, not TASM.
- **SMARTPP** is plain C89/C99-ish; builds with GCC, Clang, MSVC, Open Watcom. Output is ordinary assembler text for the same toolchains (plus GAS when `-att` / auto-detected).
- SMART.INC does not open segments or change `OPTION` beyond the keyword renames it documents.
- SMARTPP does not evaluate macros; it sees source text. Expanding macros first (or running after a preprocessor) yields more opportunities.

---

## Repository layout

```text
SMART.INC       macro library (drop next to your sources)
SMARTPP.C       peephole pre-processor (single translation unit)
README.md       this file
```

---

## License / provenance

SMART.INC is based on earlier work by Javier Gutiérrez Chamorro (Guti). Both components target the same classic-x86 niche and are intended to stay dependency-free and easy to vendor into a project.
