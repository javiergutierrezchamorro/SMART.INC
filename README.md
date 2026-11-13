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
| `-m86` … `-m686` / `-m64` | Initial CPU level (default 8086). Source directives (`.386`, `.286`, …) may raise or lower it for the rest of the unit. |
| `-att` / `-intel` | Force AT&T or Intel syntax. |
| `-I DIR` | Include search path (repeatable). |
| `-noinclude` | Do not follow `INCLUDE` at all. |
| `-Os` / `-Oz` | Prefer speed (default) or size. |
| `-Ox` | Aggressive folds that are not 100% safe. |
| `-mark` / `-nomark` | Rewrite markers in output (default: on). |
| `-v` / `-nv` | Per-line rule notices on stderr (default: off). |
| `-w` / `-nw` | Show **all** warnings (CPU directives, `-Ox` non-100%-safe rules, …). Default: **on**. |
| `-color` / `-ncolor` | Force colored diagnostics on/off (default: **on**). |
| `-o FILE` | Output file (`-` = stdout). |

### INCLUDE (preprocessor default)

`INCLUDE` / `include` / `.include` are **expanded by default**: the directive is replaced by the full file contents (recursive, with cycle detection). Search order: directory of the including file → `-I` paths → CWD. Missing files warn and leave the directive. Expanded regions are marked with `; SMARTPP include begin/end: path`.

Use `-noinclude` only if you want the old one-file behaviour.

Progress is reported (`including...` / `included N lines`); the summary table is printed **before** writing the output file.

### v2.52

- **Correctness:** fixed colliding precondition bits — `PRE_FPU` and `PRE_STACK_MEM_0/1` previously shared values with `PRE_NOT_OZ` / `PRE_OZ`, so FPU rules were incorrectly suppressed under `-Oz` and stack-mem rules interacted with the size switch. Re-assigned to free high bits.
- **`-v` completeness:** `replace_line_marked` / `delete_keep_label_marked` now emit the per-line notice themselves. Rules that only used those helpers (e.g. P496/P497 `add R,2 → inc/inc` on 8086) were silently missing from `-v` output; they now appear.
- **Performance:** rule-index buckets raised to 512 and chain array to 4096 entries. `STSZ` raised to 900.
- **Table audit:** the first v2.52 draft added ~42 rules; a full pass removed the majority as either **unsound** (`shl1/shr1` is not a cancel pair — the high bit is lost) or **exact duplicates** of existing table/C rules (P28, P136, P137, P205, P227/228, P422, P443, P470–477, P487, P506, P537–539, etc.). Kept only the genuinely new safe ones:
  - P744–P746: flag-dominance completion (`std/cld`, `cli/sti`)
  - P748: `lahf / lahf`
  - P749: `wait / wait`
  - P775: `xor R,0 / xor R,K → mov R,K` (flags dead)
- **Research batch (FPC / LLVM / Watcom / classic DOS ASM):**
  - **P800** `mov al,i1 / mov ah,i2 → mov ax, combined` (and bx/cx/dx) — Open Watcom PR #96 style
  - **P801** `mov edx,eax / sar edx,31 → cdq` (386+, flags dead) — FPC #36551
  - **P802–P804** `and|or|xor R,K / test R,R → del test` (exact flag equivalence)
  - **P805–P808** `add|sub|inc|dec / test R,R → del test` (flags dead)
  - **P810–P811** `mov R,S / test R,R|cmp R,0 → test S,S` (R dead)
  - **P812–P813** `mov R,S / inc|dec R → lea R,[S±1]` (flags dead) — LLVM mov+dec→lea style; P47 already covers mov+add/sub imm
  - **P820/P822–P824** `xor0|or R,R|and R,R|test R,R / cmp R,0 → del cmp` (AF dead)
  - **P830–P832** demoscene size-coding (`-Oz`): `xor eax,eax / xor edx,edx → cdq`, 16-bit `cwd` form, and `mov eax,0 / xor edx,edx → xor/cdq` (Agner Fog / 256b intro idiom)
  - Verified non-redundant with P40/P47/P48/P53–P55/P141 (const-fold and not/inc→neg already present)
  - AZHenley/superoptimizer is a toy ISA (LOAD/SWAP/XOR/INC only) — no transferable x86 patterns; focused on real demoscene/Agner/FPC/LLVM sources instead
  - **P840–P841** `and|or R,S / and|or R,S → del second` (value identity; Hsieh/Watcom/MSC redundant pairs)
  - **P843–P844** `add R,S / sub R,S` and reverse → delete both (flags dead; inverse pair)
  - Audited Paul Hsieh Assembly Lab, Watcom PR#96, Turbo/Borland Pascal, MSC/VC++: core idioms (xor0, cmp0→test, mov-1→or, enter/leave, movzx/sx, imul strength, constant branch after zeroing) already present as P9/P11/P35/P42/P29–P31/P380/P751
  - **P36 implemented** (documented since v1.70, never coded): `mov sp,bp / pop bp` and 32-bit `mov esp,ebp / pop ebp` → `leave`. Gate **80186+** (`g_curcpu >= 2`). ENTER/LEAVE are 186 instructions, not 286-only.
  - P42 enter already correctly gated `g_curcpu >= 2` (186+)
  - **P850** `test cx,cx|cmp cx,0 / jz → jcxz` (-Oz, 8086+)
  - **P851** `test ecx,ecx|cmp ecx,0 / jz → jecxz` (-Oz, 386+)
  - P427 remains `dec cx / jnz → loop` (NOT jz — that would be inverted)
  - **P852** `bt R,K / jc|jnc → test R,(1<<K) / jnz|jz` (386+, Agner Fog / Pentium tutorials)
  - Tutorial audit (Abrash, Agner Fog, GameDev Pentium, DDJ 80x86): xor0, test vs cmp0, lea *3/5/9, imul strength, setcc+xor, bts→or, loop/jecxz, abs via cdq/xor/sub, and/or R,R→test already covered. Remaining gaps are scheduling/pairing and global opts, not local peepholes.
  - **P853** `xor|sub r64,r64 → xor r32,r32` on x64 (Intel Optimization Manual, AMD SOG, Agner: 32-bit form zero-extends, shorter, Silvermont dep-breaking)
  - Vendor docs (Intel ORM, AMD Family 10h/15h/Zen SOG, Cyrix, NEC V20): most integer peepholes already present. NEC/Cyrix extras (bit-field, 8080 emu) are non-portable. AMD SSE merge tips are SIMD-scope.
  - **P854** `bts R,K1 / bts R,K2 → or R,mask` and `btr` pair → `and` (386+; Leventhal *Intel 80386 Programming Guide*, archive.org: "OR AL,00001100B replaces two BTS")
  - Archive.org audit: Leventhal 386 (LEA, LOOP, OR vs BTS), Intel 386 PRM 1986, Cyrix 5x86/6x86 briefs (OOO/pairing), AMD Athlon/K6 SOG. Integer local rules largely saturated.
- No re-introduction of the v2.44 bulk identity tails.

### v2.50

- Removed temporary progress prints (rule index / pass starting / progress %).
- `g_scratch` / `g_build` allocated with **malloc** (not BSS) to keep the EXE smaller.
- Local peephole buffers back on the stack (with Watcom `_STACKSIZE`).

### v2.49

- **Watcom stack:** define `_STACKSIZE` (512 KiB flat / 64 KiB 16-bit); large `run_pass` buffers marked `static` where safe; rule-chain walk has a guard against infinite loops.

### v2.48

- **Watcom C89:** declarations moved to the top of the `run_pass` loop body (no mid-block decls).

### v2.47

- **Critical Watcom fix:** `next_code()` no longer allocates a ~1.6KB `struct pinfo` on the stack (caused silent death at the start of pass 1 on small stacks).
- **Progress:** `pass N progress X/Y` every few hundred lines so long runs show activity.

### v2.46

- **Watcom / stack fix:** rule index is compact linked chains (~5 KB) instead of a large 2D array; `load_entire_stream` uses a static 8K buffer (not stack).
- **Progress:** prints before rule index, before each pass, and after — so a hang is diagnosable.
- Summary markers from v2.44 kept.

### v2.45

- **Performance:** mnemonic hash index for table rules — each instruction only tests rules for its opcode (not the full table).
- **Cleanup:** removed the v2.44 bulk ~1000 redundant identity rules (`bulkN:…`); kept the curated high-value set.

### v2.44

- **Summary visibility:** `SUMMARY BEGIN/END` on stderr; `-v` default **ON**; fflush hardened.
- **+1000 table rules (P800+):** systematic identity tails after ALU / shifts / unary / mov / xor-zero.

### v2.43

- Implemented the eight deferred C optimizations:
  - **P750** one-hop copy-prop `mov R,S` / `mov T,R` → `mov T,S`
  - **P751** `xor/sub R,R` + `jz`→`jmp` / `jnz`→delete
  - **P5** multi-hop jump threading (up to 3 pure `jmp`s)
  - **P753** empty frame `push bp` / `mov bp,sp` / `pop bp`
  - **P754** `mov`/`shl 1`/`add S` → `lea` ×3 (386+)
  - **P755** `cmp R,R` + `je`/`jne`/`sete`/`setne`
  - **P756** x87 `fld`/`fstp` same stack slot; `fchs`/`fabs` pairs
  - **P757** `and R32,0FFh/FFFFh` → `movzx` (386+, flags dead)

### v2.42

- Table cleanup: withdrew pure **P1 duplicates** (`mov R,R` / `xchg R,R` extra table copies P498/P567/P568).
- Benchmark notes (hand-written DOS ASM: FreeDOS `entry.asm`, MS-DOS `EXEC`/`TCODE`/`MSINIT`):
  - With labels kept: **~1–3%** lines removed / few dozen rewrites per 300–500 lines (typical for already-tuned asm).
  - Dominant hits: **P8** (or/and→test), **P9** (mov0→xor), **P5** (jump thread), **P449** (shl folds), **P11** (cmp0→test).
  - Without labels, **P13** falsely deletes large unreachable regions — not representative.
- **Still out of scope / high value to add later:** global copy-prop, stack-frame removal, jump threading multi-hop, constant branch folding, x87 peep, broader LEA scales, `setcc`/`cmov` sequences on 386+.

### v2.41

- **Second bulk table rules (~100, P644–P743):** more identity tails after ALU/shifts/lea/inc/dec/not/neg; `push R/pop R` and double `xchg`; flag-setter pairs; zeroing folds.

### v2.40

- **+100 table rules (P541–P643):** high-frequency null sequences — `op R,0`/`and R,-1` deletes when flags dead; `mov`/`xor0` followed by identity ops; shift-by-0; duplicate flag setters; cancel `add 1`/`dec`; etc.
- **P444 withdrawn (unsound):** `adc`/`sbb R,0` cannot be deleted merely because flags are dead *after* — CF is an input operand.

### v2.39

- **C P531:** stack constant forwarding `mov [bp±n],imm` / `mov R,[bp±n]` → `mov R,imm`.
- **C P532:** `lea R,[S+d]` / `add|sub R,imm` → folded `lea` (flags dead).
- **C P533:** `push R` / `mov R,X` / `pop S` → `mov S,R` + `mov R,X` (or delete all if S==R).
- **C P534:** `mov R,0` / `add R,S` / `mov T,R` → `mov T,S` (R dead, flags dead).
- Table **P535–P540:** more null sequences and cancel pairs.

### v2.38

- More table rules **P513–P530**: `xor0`+`or`/`add`/`sub` → `mov`; dead `cmp`/`test` after `mov R,S`; cancel `add`/`sub` same K; `rcl`/`rcr 0`; duplicate zeroing; `cmc`+`clc`/`stc`; consecutive `mov R,*` dead store; etc.

### v2.37

- **CPU gating audit:** added `PRE_CPU_386` where missing for 386-only opcodes in the table:
  - P424/P425 (`movzx`/`movsx` identity delete)
  - P28 duplicates of `cwde`/`cdq`/`cwtl`/`cltd`
- Already correct: `imul` forms use `PRE_NO_CPU_8086` (186+); `bswap` uses `PRE_CPU_486`; `bt`/`setcc`/`lea [R+R]`/`P323`/`P480`/`P512` use 386+ where required; `×2` prefers `shl` on 8086 (P450), not `add`.

### v2.36

- **Oscillation fix:** withdrawn **P485/P486** (`shl`/`sal R,1` → `add R,R`). They fought **P450** (`add R,R` → `shl R,1`) every pass.
- **Canonical ×2 form:** prefer **`shl R,1`** (8086: 2 clocks vs `add R,R` at 3; same size). On **386+** with flags dead and **`-Os`**, **P323** may use `lea R,[R+R]`.
- **P428** (`lea [R+R]` → `add R,R`) only under **`-Oz`** (size).
- New **`PRE_OZ`**: rule fires only when optimizing for size.

### v2.35

- **P511 stack store forwarding:** `mov [bp±n], R` / `mov S, [bp±n]` (same slot, Intel) → `mov S,R` or delete reload if same reg. Only pure `bp`/`ebp`/`rbp`±disp.
- **P47 expanded:** `mov R,S` / `sub R,imm` → `lea R,[S-imm]`; `mov R,S` / `add R,S` → `lea R,[S+S]`.
- **P512:** `setcc R8` / `movzx Rwide, R8` → delete `movzx` when `Rwide` is dead after (keeps it when live, e.g. return in EAX).

### v2.34

- More table rules **P498–P510**: `xchg R,R` delete; duplicate `test`/`cmp`/`bt`; `or`/`and R,R` before `test`; `rol`/`ror 0` delete; `cwd`/`cdq` duplicate; `clc`/`cmc` → `stc`; `mov 0`+`add`/`or` → `mov`; `mov`+`xor` same → `xor R,R`; `and R,R`+`or 0`.

### v2.33

- **Flag non-equivalence documented:** `inc`/`dec` preserve **CF**; `add`/`sub` write CF. Two successive `inc`s can also produce intermediate **OF/AF** different from a single `add R,2`. Therefore both directions require **all six flags dead**.
- **P496 / P497 (8086/286 reverse):** `add R,2` → `inc`/`inc`, `sub R,2` → `dec`/`dec` when flags dead, not SP, width ≥ 16. Size (3→2 bytes) and speed win on pre-386. Forward P480/P481 remain 386+ / `-Os` only.

### v2.32

- **P480 / P481 gated:** `inc`/`inc` → `add R,2` and `dec`/`dec` → `sub R,2` only when **CPU ≥ 386** and **not `-Oz`** (`PRE_CPU_386 | PRE_NOT_OZ`).
  - **Size (`-Oz`):** two `inc`/`dec` = 2 bytes vs `add`/`sub imm8` = 3 bytes → keep the pair.
  - **Speed on 8086/286:** `inc`/`dec` is cheaper; folding would be slower.
  - **Speed on 386+ with `-Os` (default):** one `add`/`sub` is preferred.
- **P482 / P483** (`add 1`/`add 1` → `add 2`, same for `sub`) stay unrestricted: pure size win (two imm ops → one). Under `-Oz`, P10 may still turn each `add 1` into `inc` first (smaller), which is correct.
- New `PRE_NOT_OZ` precondition bit for table rules that enlarge encodings.
- **P491–P495:** cancel `add 2`/`sub 2`; `test`/`or 0`; `not`/`add 1` → `neg`; dead `add`/`sub 0` after `mov`; `xor0`/`sub R,R`.

### v2.31

- **Migrations from C:** P35 (`mov R32,-1` → `or`), P60 (`or R16,-1` → `mov`), P141 (`not`/`inc` → `neg`), P142 (`neg`/`dec` → `not`), P71 (`sub R,R` → `xor`, AF dead), P48 (`xor0`/`test R,R` → delete test).
- **New table rules P480–P490:** `inc`/`inc` → `add 2`; `dec`/`dec` → `sub 2`; `add 1`/`add 1` → `add 2`; dead `mov` before `xor R,R`; `sal`/`shl 1` → `add R,R`; duplicate `and`/`or R,K`; `mov 1`/`dec` and `mov -1`/`inc` → `xor R,R`; `pushf`/`popf` (and `pushfd`/`popfd`).
- Classic strength-reduction and null-sequence patterns (FPC / GCC / textbook peepholes), all gated on flag liveness and SP safety where needed.

### v2.30

- **`-w` / `-nw`:** global warning switch (default on), not only CPU directives. Covers:
  - CPU level changes from source directives
  - **`-Ox` rules** that are not 100% safe (table `PRE_AGGRESSIVE` and C P370/P383), e.g.  
    `smartpp: warning: line N: -Ox rule P240 applied (…) [not 100% safe]`
- **`wlog` / `wlog_line`:** dedicated warning channel (yellow), independent of `-v`.
- **Table migrations:** P14 (double xchg), P15 (`mov R,S`/`mov S,R`), P32 (`push R`/`pop S` → `mov` with equal-width different regs).
- **New P473–P479:** `and`/`or R,R` pairs; `add0`/`sub0` pairs; `xor`/`xor` cancel; `test`/`or R,R`; `mov -1`/`not` → `mov 0`; `mov 0`/`not` → `mov -1`.

### v2.29 (correctness audit)

- **Withdrawn (unsound):** P441 (`test` before `setcc` deleted — setcc needs those flags); P454/P455 (`mov R,imm` deleted before `cmp`/`test` left reading undefined R).
- **Fixed:** P459 (`rol`/`ror` pair) now requires **equal** counts via `p459_same_imm_check` (v2.28 matched any two immediates independently).
- **Table migrations:** P9 (`mov R,0` → `xor`), P11 (`cmp R,0` → `test R,R`, AF dead).
- **New table rules P461–P472:** duplicate `and`/`or R,R`; `xor0`+`and`; duplicate `add`/`sub R,0`; `push R`/`pop R`; `stc`/`clc` dominance; `mov`+`and`/`or`/`xor 0` with same data; duplicate `test`/`cmp R,K` (same imm); `not`↔`xor R,-1` cancel pairs.
- Redundant with C is intentional: C runs first; table is fallback/documentation and catches cases C misses after earlier rewrites.

### v2.28

- **Table migrations:** P18 (`add`/`sub R,0`), P20 (shift/rotate `R,0`), P23 (`not`/`not`), P25 (`cmc`/`cmc`), P37 (`xor R,-1` → `not`), P147/P148/P151 (`or`/`and`/`test`/`cmp R,R` with flags dead) now live in `g_rule_tbl[]` as well as (or instead of relying solely on) the older C paths.
- **New table rules P444–P460:** `adc`/`sbb R,0` delete; `xor0`/`or R,R`; `mov 0` + dead `and`/`or`/`xor`; shift-1 fusion (`shl`/`shr`/`sal`/`sar` 1+1 → 2); `add R,R` → `shl R,1`; `neg`/`neg` and `inc`/`dec` pairs; dead-reg `mov` before `cmp`/`test`; `and R,0` → `xor R,R`; `or R,0` / `and R,-1` delete; `rol`/`ror` cancel pairs; duplicate `mov R,S`.
- `STSZ` raised to 480.

### v2.27

- **CPU level policy restored:** `-m86` (and the other `-m*` switches) only set the *initial* level. A later `.386` / `.286` / `.8086` / … directive in the source freely raises or lowers `g_curcpu` for the remainder of the unit (and a subsequent directive can lower it again). The v2.26 hard ceiling (`g_cpu_max`) that clamped directives to the command-line level is removed.
- **`-w` / `-nw` (default on):** when a source CPU directive changes the active level, emit  
  `smartpp: warning: line N: .386 directive found. CPU level raised from 8086 to 386`  
  (or “set” when the level is lowered). `-nw` silences these diagnostics.
- Table-engine extensions already in place continue to power the newer rules: single-flag dead preconditions (`PRE_FLAGS_DEAD_SF` / `ZF` / `OF` / `PF`), generalized `PRE_REG_DEAD_CAP` / `DEAD_CAP_('c')`, `OP_IMM_RANGE` / `IMR_(lo,hi)`, arithmetic templates `${K + K1}`, and same-family / complement-lo operand kinds (`SFAM_`, `CLO_`) used by P431, P432, and the P433–P439 constant-fold family.

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

Include **after** the processor directive and **before** any instruction the file rewrites. Protected against multiple inclusion.

```asm
    .8086
    .MODEL tiny
    include SMART.INC
```

**Requirements:** ASMC, JWasm or UASM with `OPTION RENAMEKEYWORD`. MASM is not supported (`NOKEYWORD` deletes the mnemonic instead of renaming it). TASM is not supported. Default CPU is 8086; with `.186` or higher the shift macros and `movzx`/`movsx` emulations are not defined because native instructions already exist.

**SMART / NOSMART:** `SMART` (default) enables automatic `mov reg,reg` / `xchg reg,reg` elimination, `lea reg16,var` → `mov OFFSET`, and extended conditional / `jcxz` / `loop` jumps. `NOSMART` turns those off; every other helper remains available as an explicit macro call.

Unless stated otherwise, macros may destroy the flags. Counts and constants must be assembly-time constant expressions. Force the original instruction with the `??` prefix (`??mov`, `??shl`, `??je`, …).

### 1. Constant shifts and rotates (8086)

On the 8086, shifts only accept count 1 or `CL`. The macros expand a constant count into repeated 1-bit instructions (or use the native form from `.186` up).

| Macro | Behaviour |
| --- | --- |
| `shl` / `shr` / `sal` / `sar` | Logical/arithmetic shift; constant count unrolled on 8086 |
| `rol` / `ror` | Rotate without carry |
| `rcl` / `rcr` | Rotate through carry |

Internal helper: `__SHx` builds the repeated stream. Expression operators that shared the `SHL`/`SHR` tokens are compensated via `__Pow2(n)`.

### 2. `movzx` / `movsx` emulation (pre-386)

| Macro | Behaviour |
| --- | --- |
| `movzx reg, src` | Zero-extend; below 386 expands to xor-high + mov (or equivalent). On 386+ the native instruction is used. |
| `movsx reg, src` | Sign-extend; below 386 uses `cbw` / `cwd`-style sequences where applicable. |

### 3. Multi-operand `push` / `pop`

TASM 4 style, comma-separated:

```asm
    push ax, bx, cx
    pop  cx, bx, ax
```

Empty operand lists are rejected (`.ERRB`).

### 4. `FastIMul dest, src, const`

Signed multiply by a **constant** using only shifts, adds, LEAs and (when profitable) native `imul`.

| CPU / shape | Strategy |
| --- | --- |
| Power of two | `mov` (if needed) + `shl` + optional `neg`; **in-place** when `dest = src` (including memory on 186+) |
| 386+ 32-bit regs, odd factors 3…21, 25, 27, 37, 41, 45, 73, 81 | One or two LEAs (`__LeaOddX` / `__IsLeaOddD`); some factors allow `dest = src` |
| Remaining constants | Horner chain of shifts/adds, or a single three-operand `imul` when shorter/faster (186+) |
| Byte destinations / no in-place form | Clear assembly error instead of silent wrong code |

`dest` and `src` may be the same register for constants whose expansion never re-reads the source after the first write. ESP as destination is guarded (illegal SIB forms).

### 5. `FastMul const`

Computes **unsigned** `DX:AX = AX * const` (like `mul r16`).

| Path | Notes |
| --- | --- |
| Power of two | Short `shl`/`rcl` sequence (8086) or faster 186+ form |
| Mersenne factors (`2^k - 1`) | Shift-and-add shortcut when the cost model wins vs `mul` |
| 386+ | `movzx` + LEA tree on EAX (EDX scratch) or one native `imul` |
| Otherwise | Horner chain or `mul` according to CPU cycle model |

### 6. Single-bit helpers

| Macro | Effect |
| --- | --- |
| `setflag rm, bit` | Set bit `bit` in register/memory |
| `clrflag rm, bit` | Clear bit (register masks fitted to operand size so top-bit forms encode) |
| `flipflag rm, bit` | Toggle bit |
| `testflag rm, bit` | Test bit (typically `test` with mask) |
| `maskflag rm, bit` | Isolate bit |

Out-of-range bit indices on registers raise `.ERR`.

### 7. Bit-field helpers

Compatible with MASM-style `RECORD` / `WIDTH`.

| Macro | Effect |
| --- | --- |
| `setfield rm, lo, width, val` | Insert `val` into bits `[lo, lo+width)`. Full-width field → one `MOV`. Register overflow → error. Fitted AND masks on registers. |
| `getfield dest, src, lo, width` | Extract field with zero-extension. Same operand skips the seed `MOV`. Mixed sizes use `movzx` when legal. On 386+, `lo=0` and width 8/16 can collapse to a single `movzx`. |

Range rule: `lo + width ≤ 32` (`lo = 0`, `width = 32` allowed). Below 386, fields that do not fit 16 bits are errors.

### 8. Redundant `mov` / `xchg` (SMART)

| Form | SMART | NOSMART / force |
| --- | --- | --- |
| `mov reg, reg` (same register) | Assembles to nothing | `??mov` emits the real instruction |
| `xchg reg, reg` | Assembles to nothing (note: this removes the classic 1-byte `90h` NOP) | `??xchg` or plain `nop` for padding |

Other `mov`/`xchg` forms pass through unchanged. `mov reg, 0` is **not** turned into `xor` (flags must stay intact).

### 9. `lea reg16, var` → `mov reg, OFFSET var` (SMART)

When the source is a direct memory variable (no index/base), the destination is a 16-bit register, and the segment is use16, the shorter `mov reg, OFFSET var` is emitted. Indexed forms and use32 pass through. `??lea` forces the original.

### 10. Extended conditional jumps (SMART)

Pre-386, short-only Jcc cannot reach beyond ±127. The macros:

- **Backward, in range:** keep the 2-byte short form.
- **Backward, out of range / forward / external:** emit `j<inverse> over` / `jmp target` / `over:`.
- **`@F` / `@B`:** pass through unchanged.
- **386+:** pass through; the assembler picks short or near itself.

Covers all 30 mnemonics (`je`/`jz`, `jne`/`jnz`, `ja`/`jnbe`, …).

### 11. Extended `jcxz` / `loop` (SMART)

These never gained a long encoding. Out-of-range targets use a trampoline that preserves flags and the `CX = 0` → `0FFFFh` wrap of `loop`. In-range backward targets keep the native 2-byte form. `??jcxz` / `??loop` force the original. `LOOPE`/`LOOPNE` stay native.

### Internal helpers (not for general use)

`__Pow2`, `__IMag` / `__ISgn`, `__TZ` / `__Ones` / `__Hibit`, `__Horn`, `__RegBits`, `__FieldRange`, `__GFTail`, `__LeaOddX`, `__IsLeaOddD`, `__Jcc`, `__SExt`, etc. drive the expansions above.

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