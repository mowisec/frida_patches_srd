"""ARM64 instruction patterns as (match, mask) pairs.

The idea is checkra1n's KPF patchfinder (PongoOS checkra1n/kpf/main.c): describe
a patch site by the SHAPE of the instructions around it and mask out every field
that is free to change between builds -- register numbers the compiler picked,
branch displacements, page offsets. What is left is the part that carries the
meaning, and it survives a recompile.

A pattern is a list of (match, mask) pairs, matched against consecutive
instructions. `ANY` matches anything and is the way to skip over an instruction
whose encoding is not stable but whose presence is.

The vocabulary is split three ways, and this module re-exports all of it so a
finder can say `import srdpatch.arm64 as A` and reach everything:

    fields.py     the (match, mask) primitives and the logical-immediate encoder
    patterns.py   the instruction patterns themselves -- what a finder MATCHES
    decode.py     reading a field back out of a matched instruction
    emit.py       building the words that get WRITTEN
"""
from .fields import ANY, logical_imm, raw
from .patterns import *          # noqa: F401,F403  the whole matching vocabulary
from .decode import (decode_adrp, decode_branch_target,
                     decode_cond_branch_target, decode_ldst_off,
                     decode_tb_target, rd, rn, sextract)
from .emit import NOP, RET, encode_b, encode_movz
