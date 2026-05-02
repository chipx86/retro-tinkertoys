# Retro Tinkertoys: Retro Disassembly Tools

This is a set of scripts I've developed initially to aid in my
[Faxanadu for NES disassembly work](https://github.com/chipx86/faxanadu).

At the moment, this consists of the following Python 2.7 scripts for
[Ghidra](https://github.com/nationalsecurityagency/ghidra):

* `export_nes.py`: Export annotated assembly files and a hyperlinked HTML
  disassembly for NES 6502 code.

* `populate_ppu_tile_16.py`: Select a 16 byte NES PPU tile data and generate a
* visualization in a comment.


## Installation

To install the Ghidra scripts:

1. Click **Window** -> **Script Manager**.
2. Click **Manage Script Directories** in the toolbar (3rd from the right).
3. Click the Add (green Plus) toolbar button.
4. Choose the ``ghidra_scripts`` directory in this repository.
4. In Script Manager, enable the scripts in **Script Manager** ->
   **Retro Tinkertoys**.

See below for how to use each script:


## `export_nes.py`

**Menu Item:** Tools -> Export NES

This takes the disassembled banks for an NES ROM and turns it into:

1. An assembly source file compatible with
   [asm6f](https://github.com/freem/asm6f).

2. Browsable, annotated, hyperlinked, pretty-printed HTML source that can be
   used to view the NES source with all comments and references included.

3. A Mesen labels file, for direct import into the
   [Mesen](https://www.mesen.ca/) emulator.


## `populate_ppu_tile_16.py`

**Menu Item:** Tools -> Visualize Sprites

This takes a 16-byte selection representing a 16-byte PPU tile and turns it
into an ASCII visualization attached to a comment. This helps with documenting
the tiles found within the ROM.


## Activation

Copy these scripts to your `$HOME/ghidra_scripts` (macOS/Linux) and activate the plugins. They'll then be available in the **Tools** menu.
