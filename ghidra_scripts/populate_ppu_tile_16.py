# -*- coding: utf-8 -*-
# Add a comment to each selected array-of-16-bytes with the array's bytes.
#

#@menupath Tools.Visualize Sprites
#@category Retro Tinkertoys

from __future__ import unicode_literals

import re
import sys

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import Array, TypeDef, ByteDataType, CharDataType
from ghidra.program.model.listing import CodeUnit


def base_dt(dt):
    """Unwrap typedefs to the underlying type."""
    try:
        while isinstance(dt, TypeDef):
            nxt = dt.getBaseDataType()
            if not nxt or nxt == dt:
                break
            dt = nxt
    except:
        pass

    return dt


def build_row(
    low,   # type: int
    high,  # type: int
    size,  # type: int
):  # type: (...) -> str
    # NES bit order: bit7 is leftmost pixel
    line = []

    for bit in range(size - 1, -1, -1):
        p = ((high >> bit) & 1) << 1 | ((low >> bit) & 1)
        line.append(['.', '░', '▒', '█'][p])

    return ''.join(line)


class Comment16ByteArrays(GhidraScript):
    def run(self):
        program = state.getCurrentProgram()
        listing = program.getListing()

        sel = currentSelection

        if sel is None or sel.isEmpty():
            addr = state.getCurrentAddress()
            sel = AddressSet(addr, addr)

        dit = listing.getDefinedData(sel, True)
        total = 0
        changed = 0

        size = 16

        while dit.hasNext():
            d = dit.next()
            total += 1

            print(d)

            addr = d.getAddress()
            bs = d.getBytes()

            if bs is None:
                bytes_list = [None] * size
            else:
                bytes_list = [(b & 0xff) for b in bs[:size]]

            # Build the comment text (change this to “anything” you like)
            lines = []

            if size == 8:
                bytes_list = bytes_list * 2

            for t in range(0, len(bytes_list), 16):
                tile = bytes_list[t:t+16]
                lows = tile[0:8]
                highs = tile[8:16]

                for r in range(8):
                    lines.append(build_row(lows[r], highs[r], 8))

                if t + 16 < len(bytes_list):
                    lines.append('')

            comment_text = '\n'.join(lines)

            # Prepend to any existing comment rather than overwrite (optional)
            existing = listing.getComment(CodeUnit.PRE_COMMENT, addr)

            if existing:
                if existing.strip() != comment_text.strip():
                    new_comment = existing.rstrip() + "\n" + comment_text
                else:
                    new_comment = existing
            else:
                new_comment = comment_text

            #print(new_comment)
            listing.setComment(addr, CodeUnit.PRE_COMMENT, new_comment)
            changed += 1


# Run
Comment16ByteArrays().run()
