# Retro Tinkertoys: Retro Disassembly Tools

This is a set of scripts I've developed initially to aid in my
[Faxanadu for NES disassembly work](https://github.com/chipx86/faxanadu).

At the moment, this consists of the following Python 2.7 scripts for
[Ghidra](https://github.com/nationalsecurityagency/ghidra):


## Ghidra Data Scripts

* `data_add_ref_with_offset.py`: Add a reference to each value in a selection
  with a given bank and offset.

* `data_update_types.py`: Update the types of data values without losing
  comments or references.


## Ghidra NES Scripts

* `nes_export.py`: Export annotated assembly files and a hyperlinked HTML
  disassembly for NES 6502 code.

* `nes_visualize_ppu_tile.py`: Select a 16 byte NES PPU tile data and generate
  a visualization in a comment.


# Installation

To install the Ghidra scripts:

1. Click **Window** -> **Script Manager**.
2. Click **Manage Script Directories** in the toolbar (3rd from the right).
3. Click the Add (green Plus) toolbar button.
4. Choose the ``ghidra/scripts/`` directory in this repository.
5. In Script Manager, enable the scripts in **Script Manager** ->
   **Retro Tinkertoys**.


# Licensing

This codebase is Copyright © 2005, Christian Hammond, and licensed under the
MIT license.

If you use these tools, I'd love to hear from you, and I'd appreciate a link
from anything you make public :)


# Documentation

## `data_add_ref_with_offset.py`:

**Menu Item:** Tools → Data - Add Reference with Offset

This takes a selection consisting of one or more data values, each used as an
offset into another address. It will prompt for that base address, adding each
offset into it and turning that into a reference.

This can help with annotating documentation and generating a useful
disassembly.


## `data_update_types.py`:

**Menu Item:** Tools → Data - Update Types

This helps with updating the types of data values without losing comments or
references.

Normally, when updating data types in Ghidra, any existing comments or
references will be lost. This change carefully saves this state, updates the
data types, and then restores them.


## `nes_export.py`

**Menu Item:** Tools → NES - Export Disassembly

This takes the disassembled banks for an NES ROM and turns it into:

1. An assembly source file compatible with
   [asm6f](https://github.com/freem/asm6f).

2. Browsable, annotated, hyperlinked, pretty-printed HTML source that can be
   used to view the NES source with all comments and references included.

3. A Mesen labels file, for direct import into the
   [Mesen](https://www.mesen.ca/) emulator.


## `nes_visualize_ppu_tile.py`

**Menu Item:** Tools → NES - Visualize PPU Tiles

This takes a selection containing one or more arrays of one or more PPU tiles
(each 16 bytes), turning them into ASCII visualizations. Those are inserted as
a comment above the tile data.

This helps with documenting the tiles found within the ROM.
