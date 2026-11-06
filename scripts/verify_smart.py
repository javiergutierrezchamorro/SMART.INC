#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_smart.py -- automated verifier for SMART.INC

1. Assembles t8086.asm and t386.asm with a MASM-compatible assembler
   (JWasm by default; ASMC works too) pointed to by the JWASM env var.
2. Disassembles with capstone.
3. Simulates the code (8086/386, registers only) and checks the
   expected register/flag/stack state at each NOP (one block per NOP).
4. Runs the errN.asm battery (every file must FAIL with the expected
   error message).

Usage:
    JWASM=/path/to/assembler python3 scripts/verify_smart.py
"""
import subprocess, sys, os, struct
import capstone

HERE   = os.path.dirname(os.path.abspath(__file__))
TESTS  = os.path.join(HERE, "tests")
BUILD  = os.path.join(HERE, "build")
JWASM  = os.environ.get("JWASM", "jwasm")

os.makedirs(BUILD, exist_ok=True)

def run(cmd, cwd=BUILD):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)

# ------------------------------------------------------------- simulator
R16 = ["ax","cx","dx","bx","sp","bp","si","di"]
R32 = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"]
R8  = ["al","cl","dl","bl","ah","ch","dh","bh"]

class Sim:
    def __init__(self, mode):
        self.mode = mode                       # 16 | 32
        self.regs = {}
        for r in R32: self.regs[r] = 0
        self.cf = 0
        self.zf = 1
        self.stack = []
    # -- 8/16/32-bit views of a register
    def _base(self, r):
        # al->ax or eax, ah->ax or eax, bl->bx or ebx ... by mode
        pre = "e" if self.mode == 32 else ""
        return pre + r[0] + "x"
    def get(self, r):
        if r in R8:
            v = self.regs[self._base(r)]
            return (v & 0xFF) if r[1] in "lc" else ((v >> 8) & 0xFF)
        if r in R16 and self.mode == 32:
            return self.regs["e" + r[0] + "x"] & 0xFFFF
        return self.regs[r]
    def set(self, r, val):
        if r in R8:
            b = self._base(r)
            v = self.regs[b]
            if r[1] in "lc":
                v = (v & 0xFFFFFF00) | (val & 0xFF)
            else:
                v = (v & 0xFFFF00FF) | ((val & 0xFF) << 8)
            self.regs[b] = v & self.mask(b)
        elif r in R16 and self.mode == 32:
            b = "e" + r[0] + "x"
            self.regs[b] = (self.regs[b] & 0xFFFF0000) | (val & 0xFFFF)
        else:
            self.regs[r] = val & (0xFFFF if r in R16 else 0xFFFFFFFF)
    def mask(self, r):
        if r in R8:  return 0xFF
        if r in R16: return 0xFFFF
        return 0xFFFFFFFF
    def width(self, r):
        if r in R8:  return 8
        if r in R16: return 16
        return 32

    def step(self, ins):
        m  = ins.mnemonic
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        g = self.get; s = self.set
        if m == "nop": return "nop"
        if m in ("ret","int"): return "halt"
        if m == "mov":
            d, f = ops
            s(d, self.val(f))
        elif m == "movzx":
            d, f = ops
            s(d, self.val(f) & (0xFF if f in R8 else 0xFFFF))
        elif m == "movsx":
            d, f = ops
            v = self.val(f)
            bits = 8 if f in R8 else (16 if f in R16 else 32)
            if v & (1 << (bits-1)): v -= (1 << bits)
            s(d, v & self.mask(d))
        elif m in ("shl","sal","shr","sar","rol","ror","rcl","rcr"):
            d, cnt = ops
            n = g("cl") if cnt == "cl" else int(cnt, 0)
            w = self.width(d); mk = self.mask(d)
            v = g(d)
            for _ in range(n):
                if m in ("shl","sal"):
                    self.cf = (v >> (w-1)) & 1
                    v = (v << 1) & mk
                elif m == "shr":
                    self.cf = v & 1
                    v >>= 1
                elif m == "sar":
                    sv = v - (1 << w) if v & (1 << (w-1)) else v
                    self.cf = v & 1
                    sv >>= 1
                    v = sv & mk
                elif m == "rol":
                    v = ((v << 1) | (v >> (w-1))) & mk
                elif m == "ror":
                    v = ((v >> 1) | ((v & 1) << (w-1))) & mk
                elif m == "rcl":
                    nc = (v >> (w-1)) & 1
                    v = ((v << 1) | self.cf) & mk
                    self.cf = nc
                elif m == "rcr":
                    nc = v & 1
                    v = ((v >> 1) | (self.cf << (w-1))) & mk
                    self.cf = nc
            s(d, v)
        elif m in ("add","adc","sub","sbb","and","or","xor","test"):
            d, f = ops
            a = g(d); b = self.val(f)
            mk = self.mask(d); w = self.width(d)
            raw = 0
            if m == "add": raw = a + b;   ncf = 1 if raw > mk else 0
            elif m == "adc": raw = a + b + self.cf; ncf = 1 if raw > mk else 0
            elif m == "sub": raw = a - b; ncf = 1 if raw < 0 else 0
            elif m == "sbb": raw = a - b - self.cf; ncf = 1 if raw < 0 else 0
            elif m == "and": raw = a & b
            elif m == "or":  raw = a | b
            elif m == "xor": raw = a ^ b
            else:            raw = a & b          # test: does not write
            res = raw & mk
            self.zf = 1 if res == 0 else 0
            if m in ("add","adc","sub","sbb"):
                self.cf = ncf
            if m != "test": s(d, res)
        elif m == "neg":
            d = ops[0]; mk = self.mask(d)
            v = (-g(d)) & mk
            self.cf = 1 if v != 0 else 0
            self.zf = 1 if v == 0 else 0
            s(d, v)
        elif m == "not":
            d = ops[0]; s(d, (~g(d)) & self.mask(d))
        elif m == "cbw" or (m == "cwde" and self.mode == 16):  # AL->AX
            al = g("al")
            s("ax", al - 256 if al & 0x80 else al)
        elif m == "cwd":     # AX->DX:AX
            s("dx", 0xFFFF if g("ax") & 0x8000 else 0)
        elif m == "cwde":    # AX->EAX
            ax = g("ax")
            s("eax", ax - 0x10000 if ax & 0x8000 else ax)
        elif m == "cdq":
            s("edx", 0xFFFFFFFF if g("eax") & 0x80000000 else 0)
        elif m == "mul":
            d = ops[0]
            prod = g("ax") * g(d)
            s("ax", prod & 0xFFFF)
            s("dx", (prod >> 16) & 0xFFFF)
        elif m == "imul":
            d = ops[0]
            a = g(d); b = g("ax")
            if a & 0x8000: a -= 0x10000
            if b & 0x8000: b -= 0x10000
            prod = (a * b) & 0xFFFFFFFF
            s("ax", prod & 0xFFFF); s("dx", (prod >> 16) & 0xFFFF)
        elif m == "push":
            self.stack.append(g(ops[0]))
        elif m == "pop":
            s(ops[0], self.stack.pop())
        elif m == "clc": self.cf = 0
        elif m == "stc": self.cf = 1
        elif m == "cmc": self.cf ^= 1
        elif m == "xchg":
            a, b = ops; va, vb = g(a), g(b); s(a, vb); s(b, va)
        else:
            raise RuntimeError("instruction not supported by the sim: %s %s" % (m, ins.op_str))
        return "ok"
    def val(self, tok):
        tok = tok.strip()
        if tok in R8 or tok in R16 or tok in R32:
            return self.get(tok)
        return int(tok, 0)

# ------------------------------------------------------------- 8086 bank
def u16(v): return v & 0xFFFF
def sar16(v, n):
    s = v - 0x10000 if v & 0x8000 else v
    return s >> n & 0xFFFF
def rol16(v, n): return ((v << n) | (v >> (16 - n))) & 0xFFFF
def ror16(v, n): return ((v >> n) | (v << (16 - n))) & 0xFFFF
def rol8(v, n):  return ((v << n) | (v >> (8 - n))) & 0xFF
def rcl16(v, n, cf):
    for _ in range(n):
        nc = (v >> 15) & 1
        v = ((v << 1) | cf) & 0xFFFF
        cf = nc
    return v, cf
def rcr16(v, n, cf):
    for _ in range(n):
        nc = v & 1
        v = ((v >> 1) | (cf << 15)) & 0xFFFF
        cf = nc
    return v, cf

def build_checks_8086():
    """list parallel to the NOPs of t8086.asm"""
    C = []
    add = C.append
    # A
    add(("A1 shl ax,4",       {"ax": u16(0xF00D << 4)}))
    add(("A2 shr ax,2",       {"ax": 0xF00D >> 2}))
    add(("A3 sar bx,3",       {"bx": sar16(0xF00D, 3)}))
    add(("A4 sal cx,2",       {"cx": u16(0x1234 << 2)}))
    add(("A5 rol dx,5",       {"dx": rol16(0x1234, 5)}))
    add(("A6 ror si,7",       {"si": ror16(0xABCD, 7)}))
    add(("A7 rcl di,4 cf=0",  {"di": rcl16(0x8001, 4, 0)[0]}))
    add(("A8 rcr bp,9 cf=1",  {"bp": rcr16(0x8765, 9, 1)[0]}))
    add(("A9 shl ax,cl",      {"ax": u16(0xABCD << 3)}))
    add(("A10 shl bx",        {"bx": u16(0x55AA << 1)}))
    add(("A11 shl cx,1",      {"cx": u16(0x7777 << 1)}))
    add(("A12 shl dx,0",      {"dx": 0x1234}))
    add(("A13 rol al,2",      {"ax": rol8(0xC3, 2)}))
    # B
    add(("B1 movzx ax,bl",    {"ax": 0x0080}))
    add(("B2 movzx bx,bh",    {"bx": 0x00FF}))
    add(("B3 movzx cx,cl",    {"cx": 0x007F}))
    add(("B4 movsx ax,al",    {"ax": 0xFF85}))
    add(("B5 movsx bx,bl",    {"bx": 0x005A}))
    add(("B6 movsx cx,cl",    {"cx": 0xFFE0}))
    # C
    add(("C1 push/pop x3",    {"dx": 0x3333, "si": 0x2222, "di": 0x1111, "stack": []}))
    add(("C2 push ax,bx",     {"stack": [0x1111, 0x2222]}))
    add(("C3 pop cx,dx",      {"cx": 0x2222, "dx": 0x1111, "stack": []}))
    # D
    add(("D1 bits word",      {"ax": 0x0001}))
    add(("D2 testflag ax,0",  {"zf": 0}))
    add(("D3 testflag ax,1",  {"zf": 1}))
    add(("D4 maskflag ax,0",  {"ax": 0x0001}))
    add(("D5 bits byte",      {"bl": 0x73}))
    add(("D6 maskflag bl,4",  {"bl": 0x10}))
    # E
    e1 = 0xFFFF & ~0x70
    e2 = (e1 & ~0x70) | (7 << 4)
    e8 = (0x1234 & ~(0xFFF << 2) & 0xFFFF) | ((0xBCD & 0xFFF) << 2)
    add(("E1 setfield/0",     {"ax": e1}))
    add(("E2 setfield/7",     {"ax": e2}))
    add(("E3 getfield dx",    {"dx": (e2 >> 8) & 0xF}))
    add(("E4 getfield in place", {"ax": e2 & 7}))
    add(("E5 getfield cx,bx", {"cx": (0xABCD >> 4) & 0xFF}))
    e6 = ((0xBC & ~0xF) | 3)
    add(("E6 setfield cx",    {"cx": e6}))
    add(("E7 getfield si,cx", {"si": (e6 >> 4) & 0xFF}))
    add(("E8 setfield w12",   {"ax": e8}))
    add(("E8 getfield w12",   {"bx": (e8 >> 2) & 0xFFF}))
    # F: FastIMul
    def fimul(seed, cte):
        # constant in 32768..65535 = 16-bit two's complement
        if cte > 0x7FFF: cte -= 0x10000
        return u16(seed * cte)
    fim_cases = [(0x1234,0),(0x1234,1),(0x1234,-1),(0x1234,2),(0x1234,-2),
                 (0x1234,3),(0x1234,7),(0x8000,7),(0x1234,8),(0x1234,15),
                 (0x1234,16),(0x1234,17),(0x1234,-15),(0x1234,45),
                 (0x1234,48),(0x1234,112),(0x1234,255),(0x1234,256),
                 (0x1234,1000),(0x1234,4097),(0x1234,12288),(0x1234,10000),
                 (0x1234,32767),(0x8000,-32768),(0x1234,65535),(0xFFFF,-32768)]
    fim_dest  = ["ax","ax","ax","ax","ax","ax","ax","cx","ax","ax","ax",
                 "ax","ax","ax","ax","ax","ax","ax","ax","ax","ax","ax",
                 "ax","dx","ax","si"]
    for (seed, cte), d in zip(fim_cases, fim_dest):
        add(("F FastIMul %d*%d" % (seed, cte if cte <= 0x7FFF else cte-0x10000),
             {d: fimul(seed, cte)}))
    # G: FastMul
    fmul_cases = [0,1,2,3,10,15,16,17,100,255,256,1000,2,4097,0x8000,
                  0x5555,0xFFFF,0xFFF0,0xBFFF,0xEEEF,0x8000]
    fmul_seeds = [0x1234]*13 + [0x8000] + [0x1234]*5 + [0xFFFF, 0x1234,
                  0x1234, 0xFFFF, 0x8000]
    # (the exact order comes from the source file; recomputed below)
    fmul = []
    seq = [(0x1234,0),(0x1234,1),(0x1234,2),(0x1234,3),(0x1234,10),
           (0x1234,15),(0x1234,16),(0x1234,17),(0x1234,100),(0x1234,255),
           (0x1234,256),(0x1234,1000),(0x8000,2),(0x1234,4097),
           (0x1234,0x8000),(0x1234,0x5555),(0xFFFF,0xFFFF),(0x1234,0xFFF0),
           (0x1234,0xBFFF),(0xFFFF,0xEEEF),(0x8000,0x8000)]
    for seed, f in seq:
        prod = (seed * f) & 0xFFFFFFFF
        add(("G FastMul 0x%X*0x%X" % (seed, f),
             {"ax": prod & 0xFFFF, "dx": prod >> 16}))
    return C

# ------------------------------------------------------------- 386 bank
def sar32(v, n):
    sv = v - 0x100000000 if v & 0x80000000 else v
    return sv >> n & 0xFFFFFFFF

def build_checks_386():
    C = []
    add = C.append
    M = 0xFFFFFFFF
    add(("386-1 shl eax,4",   {"eax": (0xF00DABCD << 4) & M}))
    add(("386-2 sar ecx,4",   {"ecx": sar32(0xF0000000, 4)}))
    add(("386-3 movzx/movsx", {"eax": 0, "ebx": 0}))
    e4a = (0x00123456 * 1000) & M
    add(("386-4 FastIMul 32", {"eax": e4a}))
    e4b = (0xFFFFFFF0 - 0x100000000) * -3 & M
    add(("386-4b FastIMul -3",{"ecx": (0xFFFFFFF0 * -3) & M}))
    add(("386-5 bits dword",  {"eax": (1 << 20) & ~0x10 & (1 << 31) & M ^ (1 << 31)}))
    # recomputed in a readable way below
    C.pop(); 
    v = 0
    v |= (1 << 20); v &= (~0x10) & M; v ^= (1 << 31)
    add(("386-5 bits dword",  {"eax": v & M}))
    v5 = ((1 << 20) & ~0x10 & M) ^ (1 << 31)   # state after 386-5
    e6 = (v5 & ~(0xFFF << 8) & M) | ((0xABC & 0xFFF) << 8)
    add(("386-6 setfield 32", {"eax": e6}))
    add(("386-6 getfield 32", {"edx": (e6 >> 8) & 0xFFF}))
    prod = (0x1234 * 0xFFF0) & 0xFFFFFFFF
    add(("386-7 FastMul",     {"ax": prod & 0xFFFF, "dx": prod >> 16}))
    add(("386-8 push/pop 32", {"stack": [], "eax": 0x11111111,
                               "ebx": 0x22222222, "ecx": 0x33333333}))
    return C

# ------------------------------------------------------------- utils
def disasm(path, mode):
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_32 if mode == 32 else capstone.CS_MODE_16)
    code = open(path, "rb").read()
    return list(md.disasm(code, 0))

def check_block(name, exp, sim):
    ok = True
    for k, v in exp.items():
        if k == "stack":
            if sim.stack != v:
                print("   FAIL %s: stack = %s, expected %s" % (name, sim.stack, v))
                ok = False
            continue
        if k == "zf":
            got = sim.zf
        else:
            got = sim.get(k) if k not in R8 else sim.get(k)
        if got != v:
            print("   FAIL %s: %s = 0x%X, expected 0x%X" % (name, k, got, v))
            ok = False
    if ok:
        print("   ok   %s" % name)
    return ok

def verify(test, mode, checks, stop_at_ret=True):
    binf = os.path.join(BUILD, test + ".bin")
    asm  = os.path.join(TESTS, test + ".asm")
    r = run([JWASM, "-q", "-bin", "-Fo=" + test + ".bin", asm],
            cwd=BUILD)
    if r.returncode != 0:
        print("ASSEMBLY FAILED:\n%s%s" % (r.stdout, r.stderr))
        return False
    ins = disasm(binf, mode)
    sim = Sim(mode)
    ok = True
    n = 0
    for i in ins:
        try:
            st = sim.step(i)
        except RuntimeError as e:
            print("   SIM ERROR: %s" % e)
            return False
        if st == "halt":
            break
        if st == "nop":
            if n < len(checks):
                if not check_block(checks[n][0], checks[n][1], sim):
                    ok = False
            else:
                print("   warning: NOP without check (block %d)" % n)
            n += 1
    if n < len(checks):
        print("   FAIL: only %d NOP blocks, there were %d checks" % (n, len(checks)))
        ok = False
    return ok

def error_battery():
    cases = [
        ("err1",  "must be different"),
        ("err2",  "out of range"),
        ("err3",  "cannot be negative"),
        ("err4",  "not supported"),
        ("err5",  None),            # assembler error (immediate too large)
        ("err6",  "invalid range"),
        ("err7",  "cannot both be memory"),
        ("err8",  "out of range"),
        ("err9",  "missing operands"),
        ("err10", "invalid range"),
    ]
    ok = True
    for name, msg in cases:
        r = run([JWASM, "-q", "-bin", "-Fo=" + name + ".bin", name + ".asm"],
                cwd=TESTS)
        out = (r.stdout + r.stderr)
        if r.returncode == 0:
            print("   FAIL %s: assembled WITHOUT error (expected failure)" % name)
            ok = False
            continue
        if msg and msg not in out:
            print("   FAIL %s: unexpected error: %s" % (name, out.strip().splitlines()[:1]))
            ok = False
            continue
        line = [l for l in out.strip().splitlines() if "Error" in l or "error" in l]
        print("   ok   %s -> %s" % (name, line[0] if line else "(error)"))
    return ok

if __name__ == "__main__":
    print("== t8086.asm ==")
    ok1 = verify("t8086", 16, build_checks_8086())
    print("== t386.asm ==")
    ok2 = verify("t386", 32, build_checks_386())
    print("== error battery ==")
    ok3 = error_battery()
    print()
    print("RESULT: %s" % ("ALL OK" if (ok1 and ok2 and ok3) else "FAILURES FOUND"))
    sys.exit(0 if (ok1 and ok2 and ok3) else 1)
