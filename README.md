# Retro Tinkertoys: Retro Disassembly Tools

This is a set of scripts I've developed initially to aid in my
[Faxanadu for NES disassembly work](https://github.com/chipx86/faxanadu).

This codebase is Copyright © 2005, Christian Hammond, and licensed under the
MIT license.

If you use these tools, I'd love to hear from you, and I'd appreciate a link
from anything you make public :)


# Overview

At the moment, this consists of the following Python 2.7 scripts for
[Ghidra](https://github.com/nationalsecurityagency/ghidra):


**Ghidra Data Scripts:**

* `data_add_ref_with_offset.py`: Add a reference to each value in a selection
  with a given bank and offset.

* `data_update_types.py`: Update the types of data values without losing
  comments or references.


**Ghidra NES Scripts:**

* `nes_export.py`: Export annotated assembly files and a hyperlinked HTML
  disassembly for NES 6502 code.

* `nes_visualize_ppu_tile.py`: Select a 16 byte NES PPU tile data and generate
  a visualization in a comment.


# Ghidra Support

## Installation

If you're working with these tools, you'll want to install both the Ghidra
scripts and custom data types.

To install the Ghidra scripts:

1. Click **Window** -> **Script Manager**.
2. Click **Manage Script Directories** in the toolbar (3rd from the right).
3. Click the Add (green Plus) toolbar button.
4. Choose the `ghidra/scripts/` directory in this repository.
5. In Script Manager, enable the scripts in **Script Manager** ->
   **Retro Tinkertoys**.

To install the custom Ghidra data types:

1. Under **Data Type Manager**, click the Down Arrow and choose **Open File
   Archive**.
2. Choose the `ghidra/data_types/Retro Tinkertoys.gdt` file in this
   repository.


## Scripts Reference

### `data_add_ref_with_offset.py`:

**Menu Item:** Tools → Data - Add Reference with Offset

This takes a selection consisting of one or more data values, each used as an
offset into another address. It will prompt for that base address, adding each
offset into it and turning that into a reference.

This can help with annotating documentation and generating a useful
disassembly.


### `data_update_types.py`:

**Menu Item:** Tools → Data - Update Types

This helps with updating the types of data values without losing comments or
references.

Normally, when updating data types in Ghidra, any existing comments or
references will be lost. This change carefully saves this state, updates the
data types, and then restores them.


### `nes_export.py`

**Menu Item:** Tools → NES - Export Disassembly

This takes the disassembled banks for an NES ROM and turns it files in the
following directories:

* `asm/`: Assembly source files compatible with
   [ca65](https://cc65.github.io/doc/ca65.html).

* `html/`: Browsable, annotated, hyperlinked, pretty-printed HTML source
  disassemblies that can be used to view the NES source with all comments and
  references included.

* `mesen/`: A Mesen labels file, for direct import into the
  [Mesen](https://www.mesen.ca/) emulator.

This is built to work with the provided custom Ghidra data types
(`ghidra/data_types/Retro Tinkertoys.gdt`).


### `nes_visualize_ppu_tile.py`

**Menu Item:** Tools → NES - Visualize PPU Tiles

This takes a selection containing one or more arrays of one or more PPU tiles
(each 16 bytes), turning them into ASCII visualizations. Those are inserted as
a comment above the tile data.

This helps with documenting the tiles found within the ROM.


## Data Types Reference

The bundled data types (`ghidra/data_types/Retro Tinkertoys.gdt`) can be
used when disassembling a game to help structure data for different platforms
and to define relative references to data.

The relative references are used by the exporter to correctly generate
assembly files that can utilize relative references instead of absolute
references, helping make code relocatable.

The following are available:


### NES Data Types

#### `NESPPUTile8`

Defines a 8-byte PPU tile data.


#### `NESPPUTile16`

Defines 16-byte PPU tile data.

This can be used with the `nes_visualize_ppu_tile.py` script to create a
visualization.


### References Data Types

#### `bank_offset_16`

Defines a 16-bit address relative to the start of a bank.


#### `pointer_l`

Defines the lower byte of a pointer address.

This is useful for sets of mapping tables where one tracks the high byte of an
address and one tracks the low byte.


#### `pointer_u`

Defines the upper byte of a pointer address.

This is useful for sets of mapping tables where one tracks the high byte of an
address and one tracks the low byte.


#### `pointer-1`

Defines an address that immediately precedes the address referenced by the
pointer.

That is, if the data value is `0x8011`, and there's a label at that address,
the generated files will reference `LABEL-1`, effectively `0x8010`.


#### `pointer_l-1`

Defines the lower byte of an address that immediately precedes the address
referenced by the pointer.


#### `pointer_u-1`

Defines the upper byte of an address that immediately precedes the address
referenced by the pointer.
