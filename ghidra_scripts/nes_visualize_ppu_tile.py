# Add a comment visualizing NES PPU tile data.
#
# This will take the selection representing one or more arrays of
# PPU tile data and create visualizations for each as a comment above
# the tile data.
#
# Each array may represent 1 or more tiles. If it's more than one,
# they'll be combined into a vertical row of tiles.
#
# Copyright (C) 2025 Christian Hammond.
#
# Licensed under the MIT license.


#@author Christian Hammond (ChipX86)
#@menupath Tools.NES - Visualize PPU Tiles
#@category Retro Tinkertoys


from __future__ import unicode_literals

import math

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    Array,
    DataType,
    TypeDef,
    ByteDataType,
    CharDataType,
)
from ghidra.program.model.listing import CodeUnit


class VisualizeNESPPUTiles(GhidraScript):
    """Visualize NES PPU tile data.

    This will take the selection representing one or more arrays of
    PPU tile data and create visualizations for each as a comment above
    the tile data.

    Each array may represent 1 or more tiles. If it's more than one,
    they'll be combined into a vertical row of tiles.
    """

    TILES = [
        '.',
        '░',
        '▒',
        '█',
    ]

    def run(self):  # type: (...) -> None
        """Run the PPU tile visualization.

        This will take the selection representing one or more arrays of
        PPU tile data and create visualizations for each as a comment above
        the tile data.

        Each array may represent 1 or more tiles. If it's more than one,
        they'll be combined into a vertical row of tiles.
        """
        program = state.getCurrentProgram()
        listing = program.getListing()

        # Get the selection for the start of the tile data.
        sel = currentSelection

        if sel is None or sel.isEmpty():
            addr = state.getCurrentAddress()
            sel = AddressSet(addr, addr)

        # The number of bytes for a PPU tile.
        size = 16
        half_size = size // 2

        # Loop through all the data in the selection.
        data_iterator = listing.getDefinedData(sel, True)

        while data_iterator.hasNext():
            data_type = data_iterator.next()

            addr = data_type.getAddress()
            data_bytes = data_type.getBytes()

            if data_bytes is None:
                # This is empty. Skip it.
                continue

            num_bytes = len(data_bytes)

            if num_bytes < size:
                print('Expected an array of at least %s bytes at %s, '
                      'but got a total of %s. Skipping'
                      % (size, addr, num_bytes))
                continue
            elif num_bytes % size != 0:
                new_num_bytes = math.floor(num_bytes / size)

                print('Expected an array of a multiple of %s bytes at %s, '
                      'but got a total of %s, which is not a multiple. '
                      'Trimming off %s excess bytes.'
                      % (size, addr, num_bytes, num_bytes - new_num_bytes))
                num_bytes = new_num_bytes

            # Normalize all values in the list to 1 byte values.
            bytes_list = [
                (b & 0xff)
                for b in data_bytes[:num_bytes]
            ]

            lines = []  # type: list[str]

            # Loop through each tile in the range.
            for tile_start in range(0, num_bytes, size):
                tile = bytes_list[tile_start:tile_start + size]
                lows = tile[:half_size]
                highs = tile[half_size:size]

                lines += [
                    self._build_row(lows[i], highs[i], half_size)
                    for i in range(half_size)
                ]

            comment_text = '\n'.join(lines)

            # If there are any existing comments, we'll want to prepend to
            # it instead of overwriting it.
            existing = listing.getComment(CodeUnit.PRE_COMMENT, addr)

            if existing:
                # Make sure the existing comment isn't already the same
                # visualization we generated.
                if existing.strip() != comment_text.strip():
                    new_comment = '%s\n%s' % (existing.rstrip(), comment_text)
                else:
                    new_comment = existing
            else:
                new_comment = comment_text

            # Set the resulting comment.
            listing.setComment(addr, CodeUnit.PRE_COMMENT, new_comment)

    def _build_row(
        self,
        low,   # type: int
        high,  # type: int
        size,  # type: int
    ):  # type: (...) -> str
        """Build a row of visualized tiles for a byte.

        Args:
            low (int):
                The low byte.

            high (int):
                The high byte.

            size (int):
                The size, or width, of the tile
        """
        # NES bit order: bit7 is leftmost pixel
        TILES = self.TILES
        line = []  # type: list[str]

        for bit in range(size - 1, -1, -1):
            p = ((high >> bit) & 1) << 1 | ((low >> bit) & 1)
            line.append(TILES[p])

        return ''.join(line)


# Run
VisualizeNESPPUTiles().run()
