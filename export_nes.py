# Ghidra script to export NES 6502 code to files.
#
# This takes an NES codebase in Ghidra and exports it to a series of HTML
# and text files. Files include:
#
# * HTML and text for each bank.
# * An HTML References page (a table of contents of functions/labels).
# * An enum/constants definitions file.
# * A Mesen Labels file.
#
# Any disassembled code is augmented to include useful default comments for
# functions, and end-of-line comments for most data types and arrays.
#
# The HTML output links references together, making it easy to navigate the
# codebase.
#
# Assembly code is outputted for the ca65 compiler by default, but support is
# also available for the asm6f compiler.
#
# Copyright (C) 2025 Christian Hammond.
#
# Licensed under the MIT license.


#@menupath Tools.Export NES
#@category Exporters


from __future__ import unicode_literals

TYPE_CHECKING = False

if 0:
    import typing
    from typing import Any, Callable, Mapping, TYPE_CHECKING

import os
import re
import textwrap
import string
from contextlib import contextmanager
from functools import partial

try:
    from functools import partialmethod
except ImportError:
    if TYPE_CHECKING:
        assert False
    else:
        class partialmethod(object):
            def __init__(self, func, *args, **kwargs):
                self.func = func
                self.args = args
                self.kwargs = kwargs

            def __get__(self, obj, cls):
                if obj is None:
                    return self

                return partial(self.func, obj, *self.args, **self.kwargs)

from ghidra.program.model.address import (
    Address,
    AddressOutOfBoundsException,
    GenericAddress,
)
from ghidra.program.model.data import (
    Array,
    DataType,
    ByteDataType,
    CharDataType,
    DataType,
    Enum,
    Pointer,
    Structure,
    TypeDef,
    Union,
)
from ghidra.program.model.listing import (
    CodeUnit,
    Data,
    Function,
    Instruction,
    Program,
)
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import (
    OffsetReference,
    RefType,
    Reference,
    Symbol,
    SymbolType,
)


###########################################################################
# Pattern matching
###########################################################################

#: A regex matching invalid characters in label names.
INVALID_LABEL_NAME_RE = re.compile(r'[^A-Za-z0-9_@]')


#: A regex matching assembly instructions using indirect addressing.
INDIRECT_MATCH = re.compile(
    r'(?P<prefix>\()'
    r'?\$?(?P<addr>0x[A-Fa-f0-9]+)'
    r'(?P<suffix>\),Y|,X\))$',
    re.IGNORECASE,
)


#: A regex matching assembly instructions using absolute addressing.
ABSOLUTE_MATCH = re.compile(
    r'\$?'
    r'(?P<addr>0x[A-Fa-f0-9]+)'
    r'(?P<suffix>,(?:X|Y))?$',
    re.IGNORECASE,
)


#: A regex matching placeholders for unresolved symbols in comments.
SYMBOL_PLACEHOLDER_RE = re.compile(
    r'{@sym(?:bol) (?P<addr>.+?)}'
)


#: A regex matching resolvable symbols, comprised of a block and an address.
SYMBOL_RE = re.compile(
    r'(?:(?P<block>[^:]+)::)(?P<addr>[A-Fa-f0-9]+)'
)


#: A regex matching addresses.
#:
#: This may be 1 or 2 bytes in length.
ADDR_RE = re.compile(r'[A-Fa-f0-9]{2,4}')


###########################################################################
# Data types
###########################################################################

#: A set of Ghidra reference data types.
#:
#: Each of these may trigger logic for looking up a symbol to include
#: in place of the value.
REF_DATA_TYPES = {
    'bank_offset_8',
    'bank_offset_16',
    'pointer-1',
    'pointer',
    'pointer_l',
    'pointer_l-1',
    'pointer_u',
    'pointer_u-1',
}


#: A mapping of Ghidra reference data types to hard-coded offsets.
REF_DATA_TYPE_DELTAS = {
    'pointer-1': -1,
    'pointer_l-1': -1,
    'pointer_u-1': -1,
}


#: A mapping of Ghidra reference data types to hard-coded prefixes.
#:
#: This is used to define Ghidra data types that indicate the upper or
#: lower byte of a target address.
REF_DATA_TYPE_PREFIXES = {
    'pointer_l': '<',
    'pointer_l-1': '<',
    'pointer_u': '>',
    'pointer_u-1': '>',
}


#: A mapping of word-sized Ghidra data types to operand values to output.
#:
#: If a value is ``None``, the default word type will be used for the
#: assembler target.
WORD_DATA_TYPES = {
    'bank_offset_16': 'bank_offset_16',
    'pointer': 'pointer',
    'pointer-1': 'pointer',
    'short': None,
    'ushort': None,
}


###########################################################################
# Opcodes and addressing modes
###########################################################################

#: A set of 6502 opcodes that perform in accumulator addressing mode.
ACCUMULATOR_OPCODES = {
    0x0A,  # ASL
    0x4A,  # LSR
    0x2A,  # ROL
    0x6A,  # ROR
}


#: A set of 6502 opcodes that perform in absolute addressing mode.
ABSOLUTE_ADDR_OPCODES = {
    0x6D,  # ADC
    0x7D,  # ADC,X
    0x79,  # ADC,Y
    0x2D,  # AND
    0x3D,  # AND,X
    0x39,  # AND,Y
    0x0E,  # ASL
    0x1E,  # ASL,X
    0x2C,  # BIT
    0xCD,  # CMP
    0xDD,  # CMP,X
    0xD9,  # CMP,Y
    0xEC,  # CPX
    0xCC,  # CPY
    0xCE,  # DEC
    0xDE,  # DEC,X
    0x4D,  # EOR
    0x5D,  # EOR,X
    0x59,  # EOR,Y
    0xEE,  # INC
    0xFE,  # INC,X
    0xAD,  # LDA
    0xBD,  # LDA,X
    0xB9,  # LDA,Y
    0xAE,  # LDX
    0xBE,  # LDX,X
    0xAC,  # LDY
    0xBC,  # LDY,X
    0x4E,  # LSR
    0x5E,  # LSR,X
    0x0D,  # ORA
    0x1D,  # ORA,X
    0x19,  # ORA,Y
    0x2E,  # ROL
    0x3E,  # ROL,X
    0x6E,  # ROR
    0x7E,  # ROR,X
    0xED,  # SBC
    0xFD,  # SBC,X
    0xF9,  # SBC,Y
    0x8D,  # STA
    0x9D,  # STA,X
    0x99,  # STA,Y
    0x8E,  # STX
    0x8C,  # STY

    # Ignoring these unless there's a good reason to add them. They feel
    # just a bit messy in the disassembly.
    # 0x4C,  # JMP
    # 0x20,  # JSR
}


###########################################################################
# Common utility functions
###########################################################################

def get_addr_for_eol_comment(
    addr,  # type: Address
):  # type: (...) -> str
    """Return the representation of an address for an EOL comment.

    Args:
        addr (ghidra.program.model.address.Address):
            The address to represent.

    Returns:
        str:
        The address representation for the comment.
    """
    return '[$%s]' % addr.toString(False)


def get_data_type_str(
    data_type,  # type: DataType
):  # type: (...) -> str
    base_data_type = data_type

    while isinstance(base_data_type, TypeDef):
        base = base_data_type.getBaseDataType()

        if base is not None or base == base_data_type:
            break

        base_data_type = base

    if isinstance(base_data_type, Enum):
        return base_data_type.getName()
    elif isinstance(base_data_type, CharDataType):
        return 'char'
    elif isinstance(base_data_type, ByteDataType):
        return 'byte'
    else:
        return data_type.getName()


###########################################################################
# Assembly output support
###########################################################################

class OutputMode:
    """Types of assembly output.

    This covers the assembly languages that can be generated by this script.
    """

    #: Output for the asm6f compiler.
    ASM6f = 'asm6f'

    #: Output for the CA65 compiler (default).
    CA65 = 'ca65'


class BaseAssemblyTarget:
    """Base class for an assembly output target.

    This supplies functions and constants for generating assembly source
    code based on the disassembly.
    """

    #: Operator used to define a value as a character.
    CHAR_OP = ''  # type: str

    #: Operator used to define a value as a byte.
    BYTE_OP = ''  # type: str

    #: Operator used to define a value as an enum value.
    ENUM_OP = ''  # type: str

    #: Operator used to define a value as a word.
    WORD_OP = ''  # type: str

    #: Operator used to define a value as an equate/constant.
    EQU_OP = ''  # type: str

    #: Operator used to define a value as an undefined series of bytes.
    UNDEF_BYTES_OP = ''  # type: str

    #: Maximum number of bytes to include per line.
    MAX_BYTES_PER_LINE = 0  # type: int

    #: Separator used between bytes in a sequence.
    BYTES_SEP = ''  # type: str

    #: Operator used to define a value as a compact sequence of bytes.
    COMPACT_BYTES_OP = ''  # type: str

    #: Separator used between bytes in a compact sequence.
    COMPACT_BYTES_SEP = ''  # type: str

    def get_bank_start_lines(
        self,
        block_name,  # type: str
        start_addr,  # type: str
    ):  # type: (...) -> list[str]
        """Return a sequence of code lines to include at the start of a bank.

        Args:
            block_name (str):
                The name of the block.

            start_addr (str):
                The formatted starting address for the block.

        Returns:
            list of str:
            The list of code lines to write.
        """
        raise NotImplementedError

    def format_data_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        raise NotImplementedError

    def format_data_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word data value.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        raise NotImplementedError

    def format_op_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte operand value following an instruction.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        raise NotImplementedError

    def format_op_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word operand value following an instruction.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        raise NotImplementedError

    def format_compact_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value within a compact sequence of bytes.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        raise NotImplementedError


class ASM6FTarget(BaseAssemblyTarget):
    """Assembly output target for asm6f.

    This provides the functionality needed to generate assembly code that
    can be compiled using asm6f (https://github.com/freem/asm6f).
    """

    CHAR_OP = 'db'
    ENUM_OP = 'db'
    WORD_OP = 'dw'
    EQU_OP = 'EQU'
    UNDEF_BYTES_OP = 'db'
    MAX_BYTES_PER_LINE = 16
    BYTES_SEP = ','

    COMPACT_BYTES_OP = 'hex'
    COMPACT_BYTES_SEP = ' '

    ABSOLUTE_ADDR_FMT = 'a:%s'

    def get_bank_start_lines(
        self,
        block_name,  # type: str
        start_addr,  # type: str
    ):  # type: (...) -> list[str]
        """Return a sequence of code lines to include at the start of a bank.

        This will set the base address for the bank.

        Args:
            block_name (str):
                The name of the block.

            start_addr (str):
                The formatted starting address for the block.

        Returns:
            list of str:
            The list of code lines to write.
        """
        return [
            'BASE $%s' % start_addr,
        ]

    def format_data_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '${:02x}'.format(value & 0xFF)

    def format_data_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word data value.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        return '${:04x}'.format(value & 0xFFFF)

    def format_op_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte operand value following an instruction.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '#${:02x}'.format(value & 0xFF)

    def format_op_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word operand value following an instruction.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        return '#${:04x}'.format(value & 0xFFFF)

    def format_compact_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value within a compact sequence of bytes.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '{:02x}'.format(value & 0xFF)


class CA65Target(BaseAssemblyTarget):
    """Assembly output target for ca65.

    This provides the functionality needed to generate assembly code that
    can be compiled using ca65 (https://cc65.github.io/doc/ca65.html).

    This is the default mode for this plugin, as it can help write code that
    can be cross-compiled for other architecture.
    """

    CHAR_OP = '.byte'
    ENUM_OP = '.byte'
    WORD_OP = '.word'
    EQU_OP = '='
    UNDEF_BYTES_OP = '.byte'
    MAX_BYTES_PER_LINE = 8
    BYTES_SEP = ','

    COMPACT_BYTES_OP = '.byte'
    COMPACT_BYTES_SEP = ','

    ABSOLUTE_ADDR_FMT = 'a:%s'

    def get_bank_start_lines(
        self,
        block_name,  # type: str
        start_addr,  # type: str
    ):  # type: (...) -> list[str]
        """Return a sequence of code lines to include at the start of a bank.

        This will include the block name as the segment name and mark the
        block as relocatable.

        Args:
            block_name (str):
                The name of the block.

            start_addr (str):
                The formatted starting address for the block.

        Returns:
            list of str:
            The list of code lines to write.
        """
        return [
            '.segment "%s"' % block_name,
            '.reloc',
        ]

    def format_data_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '${:02x}'.format(value & 0xFF)

    def format_data_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word data value.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        return '${:04x}'.format(value & 0xFFFF)

    def format_op_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte operand value following an instruction.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '#${:02x}'.format(value & 0xFF)

    def format_op_word(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a word operand value following an instruction.

        Args:
            value (int):
                The value of the word.

        Returns:
            str:
            The formatted word value.
        """
        return '#${:04x}'.format(value & 0xFFFF)

    def format_compact_byte(
        self,
        value,  # type: int
    ):  # type: (...) -> str
        """Format a byte data value within a compact sequence of bytes.

        Args:
            value (int):
                The value of the byte.

        Returns:
            str:
            The formatted byte value.
        """
        return '${:02x}'.format(value & 0xFF)


###########################################################################
# Assembly output writing
###########################################################################

class BytesWriter:
    """Writer wrapper for outputting sequences of bytes.

    This helps to output statements to a writer that defines bytes, handling
    wrapping, commenting, and data types for the assembly target.
    """

    #: A set of all displayable characters.
    DISPLAYABLE_CHARS = set(
        string.ascii_letters +
        string.digits +
        string.punctuation +
        ' '
    )

    def __init__(
        self,
        writer,  # type: BaseFileWriter
    ):  # type: (...) -> None
        """Initialize the writer.

        Args:
            writer (BaseFileWriter):
                The writer to output to.
        """
        self.writer = writer

        self.buffer = []           # type: list[int | None]
        self.start_addr = None     # type: Address | None
        self.cur_data_type = None  # type: DataType | None
        self.labeled = False       # type: bool
        self.cur_size = 0          # type: int

    def append(
        self,
        value,                    # type: int
        default_start_addr=None,  # type: Address | None
        size=1,                   # type: int
        eol_comment=None,         # type: str | None
        data_type=None,           # type: DataType | None
        labeled=False,            # type: bool
    ):  # type: (...) -> None
        """Append a value to the sequence of bytes.

        This takes care to output the value either on the current line or
        on a new line, depending on the state of the sequence and the
        arguments passed.

        An end-of-line comment, change in data type or size, or change in
        labeling will cause this to start a new sequence.

        Args:
            value (int):
                The value to append.

            default_start_addr (ghidra.program.model.address.Address,
                                optional):
                The default starting address for the bytes, if this is the
                first call to ``append()``.

            size (int, optional):
                The size of the value to write in bytes.

                This can be 1 or 2.

            eol_comment (str, optional):
                The optional comment to add to the end of the line.

            data_type (ghidra.program.model.data.DataType, optional):
                The value's data type.

            labeled (bool, optional):
                Whether this value has its own label preceding it.
        """
        assert value is None or isinstance(value, int), (
            'value was %r, not None or int' % value
        )

        if self.start_addr is None:
            # This is the first call to append(). Set the start address for
            # the sequence to the provided default address.
            self.start_addr = default_start_addr

        # Check if there's state that requires this to be outputted separately
        # from other bytes. This would start a new sequence.
        if (eol_comment or
            data_type != self.cur_data_type or
            size != self.cur_size or
            (labeled and not self.labeled)):
            # Distinguish this from previous bytes.
            flushed = self.flush()

            if flushed and (not labeled or data_type != self.cur_data_type):
                self.writer.write_blank_line()

        buffer = self.buffer
        self.cur_data_type = data_type
        self.cur_size = size
        self.labeled = labeled

        # Output the value, capping to the provided size if needed.
        if value is None:
            buffer.append(None)
        elif size == 1:
            buffer.append(value & 0xFF)
        elif size == 2:
            buffer.append(value & 0xFFFF)
        else:
            assert False, (
                'Unsupported value for BytesWriter.append(): %r'
                % value
            )

        # Check if we need to flush this to the file, ending the line.
        if (eol_comment or
            (len(buffer) * size) >= asm_mode.MAX_BYTES_PER_LINE or
            isinstance(data_type, Enum)):
            # We do. Flush it.
            self.flush(eol_comment=eol_comment)

    def flush(
        self,
        eol_comment=None  # type: str | None
    ):  # type: (...) -> bool
        """Flush the buffer to the file.

        This will output the sequence of bytes to a line and then begin a
        new line.

        Args:
            eol_comment (str, optional):
                The optional comment to add to the end of the line.

        Returns:
            bool:
            ``True`` if the data was written. ``False`` if there was nothing
            to write.
        """
        buffer = self.buffer

        if not buffer:
            # There's nothing to write.
            return False

        start_addr = self.start_addr
        data_type = self.cur_data_type
        assert data_type is not None

        data_type_str = data_type.getName()
        assert data_type_str

        # Different data types will need to be written specially, based on
        # the target assembler.
        if data_type_str == 'char':
            # This is a char. Output as strings.
            groups = self._group_string(buffer)
            data_text = [
                asm_mode.CHAR_OP,
                asm_mode.BYTES_SEP.join(
                    self._format_string_group(group)
                    for group in groups
                ),
            ]
        elif isinstance(data_type, Enum):
            # This is an enum value. Output as a defined enum value.
            assert self.cur_size == 1

            data_text = [
                asm_mode.ENUM_OP,
                asm_mode.BYTES_SEP.join(
                    self._format_enum_value(b, data_type)
                    for b in buffer
                ),
            ]
        elif self.cur_size == 2:
            # This is a word (pointer, short, ushort). Output as words.
            data_text = [
                asm_mode.WORD_OP,
                asm_mode.BYTES_SEP.join(
                    asm_mode.format_data_word(word or 0)
                    for word in buffer
                ),
            ]
        elif len(buffer) < 8 or not data_type_str.startswith('undefined'):
            # These are bytes (or similar), but there's not too many. Output
            # as byte definitions.
            data_text = [
                asm_mode.CHAR_OP,
                asm_mode.BYTES_SEP.join(
                    asm_mode.format_data_byte(b or 0)
                    for b in buffer
                )
            ]
        else:
            # Output anything else as a range of raw bytes.
            data_text = [
                asm_mode.COMPACT_BYTES_OP,
                asm_mode.COMPACT_BYTES_SEP.join(
                    asm_mode.format_compact_byte(b or 0)
                    for b in buffer
                )
            ]

        # Check if a new comment should be generated for the end of the line.
        if not eol_comment and start_addr:
            eol_comment = '%s %s' % (
                get_addr_for_eol_comment(start_addr),
                data_type_str,
            )

        # Write it to the file.
        self.writer.write_code(data_text,
                               addr=start_addr,
                               eol_comment=eol_comment)

        # Reset the buffer for the next sequence of bytes.
        self.buffer = []
        self.start_addr = None

        return True

    def _group_string(
        self,
        buffer,  # type: list[int | None]
    ):  # type: (...) -> list[tuple[bool, list[int]]]
        """Return groups of data for a buffer representing a string.

        This will group together all consecutive displayable characters and
        all non-displayable characters, returning the list of groups.

        Args:
            buffer (list of int):
                The buffer to convert into string groups.

        REturns:
            list of tuple:
            A list of groups, each a 2-tuple in the form of:

            Tuple:
                0 (bool):
                    Whether the group consists of displayable characters.

                1 (list of int):
                    The list of byte values in the group.
        """
        cur_group = []             # type: list[int]
        cur_is_displayable = True  # type: bool

        result = [(cur_is_displayable, cur_group)]

        for b in buffer:
            if b is None:
                b = 0
                is_displayable = False
            else:
                is_displayable = chr(b) in self.DISPLAYABLE_CHARS

            if cur_is_displayable != is_displayable:
                cur_group = []
                cur_is_displayable = is_displayable
                result.append((is_displayable, cur_group))

            cur_group.append(b)

        return [
            group
            for group in result
            if group[1]
        ]

    def _format_string_group(
        self,
        group,  # type: tuple[bool, list[int]]
    ):  # type: (...) -> str
        """Return a string group as a formatted string.

        If the group represents displayable characters, it will be returned
        as a string. Otherwise, it will be formatted as a sequence of byte
        values.

        Args:
            group (tuple):
                The group tuple to format.

        Returns:
            str:
            The formatted string.
        """
        if group[0]:
            return '"%s"' % ''.join(
                chr(b)
                for b in group[1]
            ).replace('"', '\\"')
        else:
            return ','.join(
                asm_mode.format_data_byte(b)
                for b in group[1]
            )

    def _format_char(
        self,
        value,  # type: int | None
    ):  # type: (...) -> str
        """Return a char as a formatted string.

        Args:
            value (int):
                The char value to format.

        Returns:
            str:
            The displayable character for the value.
        """
        return chr(value or 0)

    def _format_enum_value(
        self,
        value,      # type: int | None
        data_type,  # type: Enum
    ):  # type: (...) -> str
        """Return an enum value as a formatted string.

        If this is a valid value for the enum, its name will be returned.
        Otherwise, the byte value will be returned.

        Args:
            value (int):
                The enum value to format.

            data_type (ghidra.program.model.data.Enum):
                The data type for the enum value.

        Returns:
            str:
            The formatted enum value.
        """
        if value is None:
            return '$00'

        if data_type.contains(value):
            return data_type.getName(value)

        return asm_mode.format_data_byte(value)


class BaseFileWriter(object):
    """Base class for file writers.

    This provides basic functionality for writing the components of lines
    and statements for an output format. Subclasses can override this to
    specially process and output content for its format.

    The writer must be opened before any content can be written.
    """

    #: The file extension for the file type.
    ext = None      # type: str | None

    #: The subdirectory where the file should be placed.
    dirname = None  # type: str | None

    #: The column position for comments in assembly text output.
    COMMENT_COLUMN = 45

    #: The maximum length of a line containing a comment.
    MAX_COMMENT_LINE_LEN = 77

    #: The maximum length of a line in assembly text output.
    MAX_LINE_LEN = 79

    #: A regex for templated values to parse and populate.
    TEMPLATE_RE = re.compile(
        r'{{@(?P<type>SYMBOL):(?P<value>.+?)@}}'
    )

    def __init__(
        self,
        base_path,     # str
        block_name,    # str
        program_name,  # str
    ):  # type: (...) -> None
        """Initialize the writer.

        Args:
            base_path (str):
                The base path to write to.

            block_name (str):
                The name of the block being written.

            program_name (str):
                The name of the program being disassembled.
        """
        self.base_path = base_path
        self.block_name = block_name
        self.program_name = program_name

        self.blank_line_count = 0  # type: int
        self.fp = None             # type: typing.IO | None

    @contextmanager
    def open(self):  # typing.Generator
        """Open the file for writing.

        This will display progress and begin opening the file for writing.

        Context:
            The file will be opened for writing.
        """
        assert self.ext
        assert self.dirname

        filename = '%s.%s' % (self.block_name, self.ext)
        full_path = os.path.join(self.base_path, self.dirname, filename)

        print('Writing %s...' % full_path)

        with open(full_path, 'w') as fp:
            self.fp = fp

            try:
                yield
            finally:
                self.fp = None

    def new_code_unit(self):  # type: (...) -> None
        """Prepare for a new code unit."""
        pass

    def write_line(
        self,
        line,       # type: str
        addr=None,  # type: Address | None
    ):  # type: (...) -> None
        """Write a line to the file.

        The line will be processed and then formatted before being written.

        Args:
            line (str):
                The line to write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.
        """
        fp = self.fp
        assert fp is not None

        self.blank_line_count = 0
        fp.write(self.format_line(self.process_line(line),
                                  addr=addr))

    def write_lines(
        self,
        lines,      # type: list[str]
        addr=None,  # type: Address
    ):  # type: (...) -> None
        """Write a list of line to the file.

        Each line will be processed (but not currently formatted).

        Args:
            lines (list of str):
                The list of lines to write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the first line.

                This is presently unused.
        """
        fp = self.fp
        assert fp is not None

        self.blank_line_count = 0

        for line in lines:
            fp.write(self.process_line(line).encode('utf-8'))
            fp.write('\n')

    def write_line_with_eol_comment(
        self,
        line,         # type: str
        addr,         # type: Address
        eol_comment,  # type: str | None
    ):  # type: (...) -> None
        """Write a line with an end-of-line comment.

        This must be implemented by subclasses.

        Args:
            lines (str):
                The line to write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            eol_comment (str):
                The commemnt to add to the end of the line.
        """
        raise NotImplementedError

    def write_blank_line(
        self,
        count=1,  # type: int
    ):  # type: (...) -> None
        """Write the specified number of blank lines.

        If blank lines have already been accumulated, they will be deducted
        from the provided count.

        Args:
            count (int, optional):
                The maximum number of blank lines to output since the last
                non-blank line.
        """
        fp = self.fp
        assert fp is not None

        new_blank_line_count = max(0, count - self.blank_line_count)

        if new_blank_line_count > 0:
            # We don't use write_lines() here because want to go through
            # line processing per-line, rather than treating as an atomic
            # set of lines.
            for i in range(new_blank_line_count):
                self.write_line('', addr=None)

            self.blank_line_count = new_blank_line_count

    def write_anchor(
        self,
        name,  # type: str
        addr,  # type: Address
    ):  # type: (...) -> None
        """Write an anchor to the file.

        This is not required to be implemented by the subclass.

        Args:
            name (str):
                The name of the anchor.

            addr (ghidra.program.model.address.Address, optional):
                The address of the anchor.
        """
        pass

    def write_label(
        self,
        label_name,        # type: str
        addr,              # type: Address
        is_local=False,    # type: bool
        eol_comment=None,  # type: str | None
    ):  # type: (...) -> None
        """Write a label.

        Args:
            label_name (str):
                The name of the label.

            addr (ghidra.program.model.address.Address, optional):
                The address the label points to.

            is_local (bool, optional):
                Whether this is a local label within a parent context.

            eol_comment (str, optional):
                The optional commemnt to add to the end of the line.
        """
        self.write_line_with_eol_comment(
            self.format_label(label_name, addr,
                              is_local=is_local),
            addr=addr,
            eol_comment=eol_comment,
        )

    def write_code(
        self,
        code,                    # type: list[str]
        addr,                    # type: Address
        instruction_bytes=None,  # type: list[str] | None
        eol_comment=None,        # type: str | None
    ):  # type: (...) -> None
        """Write a line of instruction code.

        The code will be formatted and processed before being written.

        Args:
            code (list of str):
                The instruction and operands to format and write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the instruction.

            instruction_bytes (list of str, optional):
                The list of bytes that make up the instruction and operands.

                This is currently unused.

            eol_comment (str, optional):
                The optional commemnt to add to the end of the line.
        """
        self.write_line_with_eol_comment(
            self.process_line(self.format_code(code)),
            addr=addr,
            eol_comment=eol_comment,
        )

    def write_equs(
        self,
        equs,       # type: list[tuple[str, str]]
    ):  # type: (...) -> None
        """Write equality/enums/constants.

        Args:
            equs (list of tuple):
                The list of values in ``(name, value)`` form.
        """
        self.write_lines(self.format_equs(equs))

    def write_comment(
        self,
        comment,                 # type: str
        addr=None,               # type: Address
        indent='',               # type: str
        leading_blank=1,         # type: int
        use_plate_syntax=False,  # type: bool
    ):  # type: (...) -> None
        """Write a comment line.

        Args:
            comment (str):
                The comment to write.

            addr (ghidra.program.model.address.Address, optional):
                The address the comment corresponds to.

            indent (str, optional):
                Any indentation to provide before the comment.

            leading_blank (int, optional):
                The leading number of blank lines before this comment.

            use_plate_syntax (bool, optional):
                Whether to output using plate syntax.
        """
        if not comment or not comment.strip():
            return

        self.write_blank_line(leading_blank)

        if use_plate_syntax:
            bullet_extra = '=' * (self.MAX_LINE_LEN - len(indent) - 3)
        else:
            bullet_extra = ''

        norm_lines = [
            ';%s' % bullet_extra,
        ]  # type: list[str]

        lines = comment.splitlines()

        # Trim away any leading or trailing blank lines.
        start = 0
        end = len(lines)

        for line in lines:
            if line.strip() != '':
                break

            start += 1

        for line in reversed(lines):
            if line.strip() != '':
                break

            end -= 1

        # Generate the comments to output.
        for line in lines[start:end]:
            stripped_line = line.lstrip()
            line_prefix = '; %s' % (' ' * (len(line) - len(stripped_line)))

            if stripped_line:
                norm_lines += textwrap.wrap(
                    stripped_line,
                    break_long_words=False,
                    break_on_hyphens=False,
                    initial_indent=line_prefix,
                    subsequent_indent=line_prefix,
                    width=self.MAX_COMMENT_LINE_LEN)
            else:
                norm_lines.append(line_prefix.rstrip())

        norm_lines.append(';%s' % bullet_extra)

        self.write_comment_lines(norm_lines,
                                 addr=addr,
                                 indent=indent,
                                 use_plate_syntax=use_plate_syntax)

    def write_comment_lines(
        self,
        lines,             # type: list[str]
        addr,              # type: Address
        indent,            # type: str
        use_plate_syntax,  # type: bool
    ):  # type: (...) -> None
        """Write one or more comment lines.

        Args:
            lines (list of str):
                The list of lines to write.

            addr (ghidra.program.model.address.Address, optional):
                The address the first comment corresponds to.

            indent (str, optional):
                Any indentation to provide before the comment.

            use_plate_syntax (bool, optional):
                Whether to output using plate syntax.
        """
        raise NotImplementedError

    def format_line(
        self,
        line,  # type: str
        addr,  # type: Address | None
    ):  # type: (...) -> str
        """Return a formatted representation of an arbitrary line.

        Args:
            line (str):
                The line to format.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

        Returns:
            str:
            The formatted line.
        """
        raise NotImplementedError

    def format_code(
        self,
        code_parts,  # type: list[str]
    ):  # type: (...) -> str
        """Return a formatted representation of a code line.

        Args:
            code_parts (list of str):
                The list of components of the code.

        Returns:
            list of str:
            The list of formatted lines.
        """
        raise NotImplementedError

    def format_equs(
        self,
        equs,  # type: list[tuple[str, str]]
    ):  # type: (...) -> list[str]
        """Format equalities/enums/constants.

        Args:
            equs (list of tuple):
                The list of values in ``(name, value)`` form.

        Returns:
            list of str:
            The list of formatted lines.
        """
        raise NotImplementedError

    def format_label(
        self,
        label_name,  # type: str
        addr,        # type: Address
        is_local,    # type: bool
    ):  # type: (...) -> str
        """Format a label.

        Args:
            label_name (str):
                The name of the label.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            is_local (bool):
                Whether this is a local label within a parent context.

        Returns:
            str:
            The formatted line.
        """
        raise NotImplementedError

    def process_line(
        self,
        line,  # type: str
    ):  # type: (...) -> str
        """Process the contents of a line.

        This defaults to processing any template strings, using
        :py:meth:`process_template_var` for any that are found.

        Args:
            line (str):
                The line to process.

        Returns:
            str:
            The resulting line.
        """
        return self.TEMPLATE_RE.sub(self.process_template_var, line)

    def process_template_var(
        self,
        m,  # type: re.Match
    ):  # type: (...) -> str
        """Process a template variable in a line.

        Args:
            m (re.Match):
                The match result found in the string.

        Returns:
            str:
            The value to populate where matched.
        """
        raise NotImplementedError


class TextFileWriter(BaseFileWriter):
    """Writer for an assembly text file.

    This provides basic functionality for writing the components of lines
    and statements for an output format.

    The writer must be opened before any content can be written.
    """

    ext = 'asm'
    dirname = 'src'

    def write_line_with_eol_comment(
        self,
        line,         # type: str
        addr,         # type: Address
        eol_comment,  # type: str | None
    ):  # type: (...) -> None
        """Write a line with an end-of-line comment.

        The line will be formatted with the comment wrapped as needed.

        Args:
            lines (str):
                The line to write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            eol_comment (str):
                The commemnt to add to the end of the line.
        """
        if eol_comment:
            padding = ' ' * max(1, self.COMMENT_COLUMN - len(line) - 1)
            line_prefix = '%s%s' % (line, padding)

            self.write_lines(
                textwrap.wrap(
                    eol_comment,
                    break_long_words=False,
                    break_on_hyphens=False,
                    initial_indent='%s; ' % line_prefix,
                    subsequent_indent='%s; ' % (' ' * len(line_prefix)),
                    width=self.MAX_COMMENT_LINE_LEN,
                ),
                addr=addr)
        else:
            self.write_line(line,
                            addr=addr)

    def write_comment_lines(
        self,
        lines,             # type: list[str]
        addr,              # type: Address
        indent,            # type: str
        use_plate_syntax,  # type: bool
    ):  # type: (...) -> None
        """Write one or more comment lines.

        Args:
            lines (list of str):
                The list of lines to write.

            addr (ghidra.program.model.address.Address, optional):
                The address the comment corresponds to.

            indent (str, optional):
                Any indentation to provide before the comment.

            use_plate_syntax (bool, optional):
                Whether to output using plate syntax.
        """
        fp = self.fp
        assert fp is not None

        self.write_lines(
            [
                '%s%s' % (indent, line)
                for line in lines
            ],
            addr=addr)

    def format_line(
        self,
        line,  # type: str
        addr,  # type: Address | None
    ):  # type: (...) -> str
        """Return a formatted representation of an arbitrary line.

        Args:
            line (str):
                The line to format.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

        Returns:
            str:
            The formatted line.
        """
        return '%s\n' % line

    def format_code(
        self,
        code_parts,  # type: list[str]
    ):  # type: (...) -> str
        """Return a formatted representation of a code line.

        Args:
            code_parts (list of str):
                The list of components of the code.

        Returns:
            list of str:
            The list of formatted lines.
        """
        return '    %s' % ' '.join(code_parts)

    def format_equs(
        self,
        equs,  # type: list[tuple[str, str]]
    ):  # type: (...) -> list[str]
        """Format equalities/enums/constants.

        Args:
            equs (list of tuple):
                The list of values in ``(name, value)`` form.

        Returns:
            list of str:
            The list of formatted lines.
        """
        max_len = max(
            50,
            max(
                len(parts[0])
                for parts in equs
            )
        )

        return [
            '%s %s %s' % (name.ljust(max_len),
                          asm_mode.EQU_OP,
                          value)
            for name, value in equs
        ]

    def format_label(
        self,
        label_name,  # type: str
        addr,        # type: Address
        is_local,    # type: bool
    ):  # type: (...) -> str
        """Format a label.

        Args:
            label_name (str):
                The name of the label.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            is_local (bool):
                Whether this is a local label within a parent context.

        Returns:
            str:
            The formatted line.
        """
        if is_local:
            return '  %s:' % label_name
        else:
            return '%s:' % label_name

    def process_template_var(
        self,
        m,  # type: re.Match
    ):  # type: (...) -> str
        """Process a template variable in a line.

        Args:
            m (re.Match):
                The match result found in the string.

        Returns:
            str:
            The value to populate where matched.
        """
        if m.group('type') == 'SYMBOL':
            return m.group('value').split('::', 1)[1]

        assert False


class HTMLString(unicode):
    """An HTML-safe string."""

    __slots__ = ()

    #: Mark this as HTML, for introspection.
    is_html = True

    def __unicode__(self):
        return self

    def __str__(self):
        return self


class HTMLFileWriter(BaseFileWriter):
    """Writer for assembly HTML files.

    This provides basic functionality for writing the components of lines
    and statements for an output format.

    References are linked together using anchors and hyperlinks, making it
    easy to navigate through the file.

    Syntax highlighting is used to help visually distinguish parts of the
    page.

    The writer must be opened before any content can be written.
    """

    ext = 'html'
    dirname = 'html'

    CSS = textwrap.dedent("""
         @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:ital,wght@0,100..700;1,100..700&display=swap');

        body {
          background: #1c212d;
          color: white;
          padding: 0.5em;
          line-height: 1.5;
        }

        body, * {
          font-family: "Roboto Mono", monospace;
          font-size: 9.5pt;
          font-style: normal;
        }

        a:link,
        a:visited {
          color: #9bdeff;
        }

        pre {
          display: grid;
          grid-template-columns: minmax(6ch, min-content)
                                 minmax(70ch, max-content)
                                 1fr;
          gap: 0 3em;
          margin: 0;
          padding: 0;
        }

        .anc {
          grid-area: addr;
          grid-column: 1;
          grid-row: 1;
        }

        .anc:link,
        .anc:visited {
          color: #666677;
          text-decoration: none;
        }

        .anc:link:hover {
          color: #9bdeff;
        }

        .equs {
          display: grid;
          grid-template-columns: minmax(50ch, max-content) min-content auto;
          gap: 0 1em;
        }

        .l {
          display: grid;
          grid-template-columns: subgrid;
          grid-column: 1 / -1;
          min-height: 1lh;
        }

        .c,
        .cp,
        .equs {
          grid-column: 2;
        }

        .cp {
          color: #6fafb5;
        }

        .c {
          margin-left: 4em;
        }

        .c, .ce {
          color: #8aa9ac;
        }

        .cd {
          grid-column: 2 / 3;
        }

        .ce {
          grid-column: -1;
          text-wrap: wrap;
          text-indent: 2ch hanging;
        }

        .lla {
          margin-left: 2em;
        }

        .la,
        .lla {
          font-weight: bold;
          grid-column: 2 / 3;
        }

        .la,
        .la:link,
        .la:visited {
          color: #e8e801;
        }

        .lla,
        .lla:link,
        .lla:visited {
          color: #caca00;
        }

        .i {
          color: #f26969;
          margin-left: 4em;
          min-width: 3em;
        }

        .idx {
          display: grid;
          grid-column: 2 / 3;
          grid-template-columns: minmax(50ch, max-content) auto;
          gap: 0 1em;
        }

        .idx-name {
          font-weight: bold;
        }

        .idx-targets {
          display: flex;
          flex-direction: row;
        }

        .o {
          color: #e3e3e3;
          margin-left: 1ch;
        }
    """)

    @contextmanager
    def open(self):  # typing.Generator
        """Open the file for writing.

        This will display progress and begin opening the file for writing.

        Context:
            The file will be opened for writing.
        """
        with super(HTMLFileWriter, self).open():
            fp = self.fp
            assert fp is not None

            title = '{block_name} - {program}'.format(
                block_name=self.block_name,
                program=self.program_name,
            )

            fp.write(
                '<!DOCTYPE html>\n'
                '\n'
                '<html>\n'
                ' <head>\n'
                '  <title>{title}</title>\n'
                '  <meta http-equiv="Content-Type"'
                ' content="text/html; charset=utf-8">\n'
                '  <style>\n'
                '{css}\n'
                '  </style>\n'
                ' </head>\n'
                ' <body>\n'
                '  <pre>\n'
                .format(css=self.CSS,
                        title=title)
            )

            yield

            fp.write(
                '</pre>\n'
                ' </body>\n'
                '</html>\n'
            )

    def new_code_unit(self):  # type: (...) -> None
        """Prepare for a new code unit."""
        fp = self.fp
        assert fp is not None

        fp.write('</pre><pre>')

    def write_anchor(
        self,
        name,  # type: str
        addr,  # type: Address
    ):  # type: (...) -> None
        """Write an anchor to the file.

        Args:
            name (str):
                The name of the anchor.

            addr (ghidra.program.model.address.Address, optional):
                The address of the anchor.
        """
        fp = self.fp
        assert fp is not None

        anchor = self._normalize_anchor(name, addr)

        fp.write('<a name="%s"></a>' % self._escape(anchor))

    def write_line_with_eol_comment(
        self,
        line,         # type: str
        addr,         # type: Address
        eol_comment,  # type: str | None
    ):  # type: (...) -> None
        """Write a line with an end-of-line comment.

        Args:
            lines (str):
                The line to write.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            eol_comment (str):
                The commemnt to add to the end of the line.
        """
        if eol_comment:
            self.write_line(
                HTMLString(
                    '{line}<span class="ce">; {comment}</span>'
                    .format(line=self._escape(line),
                            comment=self._escape(eol_comment))
                ),
                addr=addr)
        else:
            self.write_line(line,
                            addr=addr)

    def write_comment_lines(
        self,
        lines,             # type: list[str]
        addr,              # type: Address
        indent,            # type: str
        use_plate_syntax,  # type: bool
    ):  # type: (...) -> None
        """Write one or more comment lines.

        Args:
            lines (list of str):
                The list of lines to write.

            addr (ghidra.program.model.address.Address, optional):
                The address the comment corresponds to.

            indent (str, optional):
                Any indentation to provide before the comment.

            use_plate_syntax (bool, optional):
                Whether to output using plate syntax.
        """
        fp = self.fp
        assert fp is not None

        if use_plate_syntax:
            css_class = 'cp'
        else:
            css_class = 'c'

        fp.write('<div class="%s">' % css_class)
        self.write_lines(
            [
                self._escape(line)
                for line in lines
            ],
            addr=addr)
        fp.write('</div>')

    def write_equs(
        self,
        equs,       # type: list[tuple[str, str]]
    ):  # type: (...) -> None
        """Write equality/enums/constants.

        Args:
            equs (list of tuple):
                The list of values in ``(name, value)`` form.
        """
        fp = self.fp
        assert fp is not None

        fp.write('<div class="equs">')
        super(HTMLFileWriter, self).write_equs(equs)
        fp.write('</div>')

    def format_line(
        self,
        line,  # type: str
        addr,  # type: Address | None
    ):  # type: (...) -> str
        """Return a formatted representation of an arbitrary line.

        Args:
            line (str):
                The line to format.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

        Returns:
            str:
            The formatted line.
        """
        if addr is None:
            anchor = ''
        else:
            anchor = (
                '<a class="anc" name="{addr}" href="#{addr}">[{addr}]</a>'
                .format(addr=addr.toString(False))
            )

        return HTMLString(
            '<span class="l">{anchor}{line}</span>\n'
            .format(anchor=anchor,
                    line=self._escape(line))
        )

    def format_code(
        self,
        code_parts,  # type: list[str]
    ):  # type: (...) -> str
        """Return a formatted representation of a code line.

        Args:
            code_parts (list of str):
                The list of components of the code.

        Returns:
            list of str:
            The list of formatted lines.
        """
        result = '<span class="i">%s</span>' % self._escape(code_parts[0])

        if len(code_parts) > 1:
            result = (
                '%s <span class="o">%s</span>'
                % (
                    result,
                    ' '.join(
                        self._escape(part)
                        for part in code_parts[1:]
                    )
                )
            )

        return HTMLString('<span class="cd">%s</span>' % result)

    def format_equs(
        self,
        equs,  # type: list[tuple[str, str]]
    ):  # type: (...) -> list[str]
        """Format equalities/enums/constants.

        Args:
            equs (list of tuple):
                The list of values in ``(name, value)`` form.

        Returns:
            list of str:
            The list of formatted lines.
        """
        return [
            HTMLString(
                '<div class="n">%s</div> '
                '<div class="i">%s</div> '
                '<div class="v">%s</div>\n'
                % (
                    self._escape(name),
                    asm_mode.EQU_OP,
                    self._escape(value),
                )
            )
            for name, value in equs
        ]

    def format_label(
        self,
        label_name,  # type: str
        addr,        # type: Address
        is_local,    # type: bool
    ):  # type: (...) -> str
        """Format a label.

        Args:
            label_name (str):
                The name of the label.

            addr (ghidra.program.model.address.Address, optional):
                The address of the line.

            is_local (bool):
                Whether this is a local label within a parent context.

        Returns:
            str:
            The formatted line.
        """
        if is_local:
            cssclass = 'lla'
        else:
            cssclass = 'la'

        return HTMLString(
            '<a href="#{anchor}" class="{cssclass}">{label}:</a>'
            .format(anchor=self._normalize_anchor(label_name, addr),
                    cssclass=cssclass,
                    label=self._escape(label_name))
        )

    def process_line(
        self,
        line,  # type: str
    ):  # type: (...) -> str
        """Process the contents of a line.

        This defaults to processing any template strings, using
        :py:meth:`process_template_var` for any that are found.

        Args:
            line (str):
                The line to process.

        Returns:
            str:
            The resulting line.
        """
        return HTMLString(super(HTMLFileWriter, self).process_line(line))

    def process_template_var(
        self,
        m,  # type: re.Match
    ):  # type: (...) -> str
        """Process a template variable in a line.

        Args:
            m (re.Match):
                The match result found in the string.

        Returns:
            str:
            The value to populate where matched.
        """
        if m.group('type') == 'SYMBOL':
            value = m.group('value')

            block_name, ref = value.split('::', 1)

            if block_name == self.block_name:
                target = '#%s' % ref
            else:
                target = '%s.html#%s' % (block_name, ref)

            return HTMLString('<a href="%s">%s</a>' % (target, ref))

        assert False

    def _escape(
        self,
        text,  # type: str
    ):  # type: (...) -> HTMLString
        """Return the content with HTML-sensitive characters escaped.

        If the provided string is already HTML-safe, it will be returned
        as-is. Otherwise, ``<``, ``>``, and ``&`` characters will be
        escaped.

        Args:
            text (str):
                The string to escape.

        Returns:
            str:
            The resulting string.
        """
        if hasattr(text, 'is_html'):
            return text

        return HTMLString(
            text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
        )

    def _normalize_anchor(
        self,
        name,  # type: str
        addr,  # type: Address
    ):  # type: (...) -> str
        """Normalize an anchor name.

        If the anchor name is local (starts with ``@``), the resulting
        name will be in the form of: ``<address>:<label>``.

        Otherwise, the name will be returned as-is.

        Args:
            name (str):
                The label name for the anchor.

            addr (ghidra.program.model.address.Address):
                The address of the anchor.

        Returns:
            str:
            The normalized anchor name.
        """
        if name.startswith('@'):
            name = '%s:%s' % (addr.toString(False), name)

        return name


class MultiFileWriter(BaseFileWriter):
    """Writer for writing simultaneously to assembly and HTML files.

    This will pass all writing operations to both writers, efficiently
    generating both at the same time.
    """

    def __init__(
        self,
        *args,
        **kwargs
    ):  # type: (...) -> None
        """Initialize the writer.

        Args:
            *args (tuple):
                Positional arguments to pass to both writers.

            **kwargs (dict):
                Keyword arguments to pass to both writers.
        """
        super(MultiFileWriter, self).__init__(*args, **kwargs)

        self.asm_writer = TextFileWriter(*args, **kwargs)
        self.html_writer = HTMLFileWriter(*args, **kwargs)

    @contextmanager
    def open(self):  # typing.Generator
        """Open both writers for writing.

        Context:
            The files will be opened for writing.
        """
        with self.asm_writer.open():
            with self.html_writer.open():
                yield

    def _call_writers(
        self,
        func_name,  # type: str
        *args,
        **kwargs
    ):  # type: (...) -> None
        """Pass a call to both writers.

        Args:
            func_name (str):
                The function name to call.

            *args (tuple):
                Positional arguments to pass.

            **kwargs (dict):
                Keyword arguments to pass.
        """
        getattr(self.asm_writer, func_name)(*args, **kwargs)
        getattr(self.html_writer, func_name)(*args, **kwargs)

    new_code_unit = partialmethod(_call_writers, 'new_code_unit')
    write_anchor = partialmethod(_call_writers, 'write_anchor')
    write_blank_line = partialmethod(_call_writers, 'write_blank_line')
    write_code = partialmethod(_call_writers, 'write_code')
    write_comment = partialmethod(_call_writers, 'write_comment')
    write_equs = partialmethod(_call_writers, 'write_equs')
    write_label = partialmethod(_call_writers, 'write_label')
    write_line = partialmethod(_call_writers, 'write_line')
    write_line_with_eol_comment = partialmethod(_call_writers,
                                                'write_line_with_eol_comment')
    write_lines = partialmethod(_call_writers, 'write_lines')


###########################################################################
# Exporters
###########################################################################

class BlockExporter:
    """Exporter that processes a block's code and data and writes it to files.

    This will write a file representing a block (generally a bank), including
    all of its code and data. Those will be written in a clean form that
    includes provided or default comments for functions and data, and to
    include links to symbols wherever they're referenced.
    """

    def __init__(
        self,
        block,     # type: MemoryBlock
        exporter,  # type: Exporter
    ):  # type: (...) -> None
        """Initialize the exporter.

        Args:
            block (ghidra.program.model.mem.MemoryBlock):
                The block being exported.

            exporter (Exporter):
                The main program exporter.
        """
        self.block = block
        self.block_name = block.getName()
        self.exporter = exporter
        self.end_addr = block.getEnd()
        self.is_block_initialized = block.isInitialized()
        self.prev_code_unit = None

    def export(
        self,
        writer,  # type: BaseFileWriter
    ):  # type: (...) -> None
        """Export the block to a writer.

        Args:
            writer (BaseFileWriter):
                The writer to write to.
        """
        block = self.block
        exporter = self.exporter

        block_name = block.getName()
        start_addr = block.getStart()
        end_addr = self.end_addr

        norm_start_addr = exporter.normalize_address(start_addr)
        norm_end_addr = exporter.normalize_address(end_addr)

        assert norm_start_addr

        self.bytes_writer = BytesWriter(writer)

        # Write the comment at the top of the file.
        writer.write_comment(
            comment=(
                '{program}\n'
                '\n'
                '{block_name} (${start_addr} - ${end_addr})'
                .format(block_name=block_name,
                        program=exporter.program_name,
                        start_addr=norm_start_addr,
                        end_addr=norm_end_addr)
            ),
            addr=start_addr,
            leading_blank=0,
            use_plate_syntax=True,
        )
        writer.write_blank_line()

        # Write any instructions needed to set up the bank's address.
        for line in asm_mode.get_bank_start_lines(block_name=block_name,
                                                  start_addr=norm_start_addr):
            writer.write_code([line], addr=None)

        writer.write_blank_line()

        # Walk the address space of the block, exporting lines for each
        # address.
        cur_addr = start_addr

        while cur_addr is not None and cur_addr.compareTo(end_addr) <= 0:
            processed_len = self.export_addr(
                addr=cur_addr,
                writer=writer,
            )

            if processed_len <= 0:
                processed_len = 1

            if cur_addr == end_addr:
                break

            try:
                next_addr = cur_addr.addNoWrap(processed_len)

                if next_addr.compareTo(cur_addr) <= 0:
                    cur_addr = None
                else:
                    cur_addr = next_addr
            except AddressOutOfBoundsException:
                cur_addr = None
            except Exception as e:
                print(e)
                cur_addr = None

        # Flush any remaining bytes to the file.
        self.bytes_writer.flush()

    def export_addr(
        self,
        addr,          # type: Address
        writer,        # type: BaseFileWriter
    ):  # type: (...) -> int
        """Export lines for an address.

        This will export the code or data for the given address to the writer.

        Args:
            addr (ghidra.program.model.address.Address):
                The address to export.

            writer (BaseFileWriter):
                The writer to use for the export.

        Returns:
            int:
            The number of bytes processed starting at this address.
        """
        code_unit = self.exporter.listing.getCodeUnitAt(addr)

        if isinstance(code_unit, Instruction):
            # Export the instruction at this address.
            processed_len = self.export_instruction(code_unit, addr, writer)
        elif isinstance(code_unit, Data):
            # Export the sequence of data.
            processed_len = self.export_data(code_unit, addr, writer)
        else:
            # This isn't an instruction or defined data. Export it as just
            # a single byte.
            self.bytes_writer.append(self.exporter.memory.getByte(addr))
            processed_len = 1

        return processed_len

    def export_instruction(
        self,
        code_unit,  # type: CodeUnit
        addr,       # type: Address
        writer      # type: BaseFileWriter
    ):  # type: (...) -> int
        """Export a line for an instruction.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit to export.

            addr (ghidra.program.model.address.Address):
                The address to export.

            writer (BaseFileWriter):
                The writer to use for the export.

        Returns:
            int:
            The number of bytes processed starting at this address.
        """
        assert addr == code_unit.getAddress()

        exporter = self.exporter
        listing = exporter.listing

        # If there are any bytes in the buffer, flush them first.
        self.bytes_writer.flush()

        # Export any labels and comments preceding this address.
        self.export_labels_and_comments(addr, writer, is_inner=True)

        # Generate the human-readable instruction.
        instruction_bytes, code = self.generate_code(code_unit, addr, writer)
        writer.write_code(
            code=code,
            instruction_bytes=instruction_bytes,
            addr=addr,
            eol_comment=self.process_comment(
                listing.getComment(CodeUnit.EOL_COMMENT, addr)),
        )

        # Output any post-code comment.
        self.export_comment(listing.getComment(CodeUnit.POST_COMMENT, addr),
                            writer,
                            indent='    ')

        return code_unit.getLength()

    def export_data(
        self,
        code_unit,  # type: CodeUnit
        addr,       # type: Address
        writer,     # type: BaseFileWriter
    ):  # type: (...) -> int
        """Export a line for a sequence of data.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit representing the data.

            addr (ghidra.program.model.address.Address):
                The address to export.

            writer (BaseFileWriter):
                The writer to use for the export.

        Returns:
            int:
            The number of bytes processed starting at this address.
        """
        data = self.exporter.listing.getDataContaining(addr)

        return self.export_data_tree(data or code_unit, writer)

    def export_labels_and_comments(
        self,
        addr,           # type: Address
        writer,         # type: BaseFileWriter
        is_inner=False  # type: bool
    ):  # type: (...) -> dict[str, Any] | None
        """Export labels and comments for an address.

        Args:
            addr (ghidra.program.model.address.Address):
                The address to export.

            writer (BaseFileWriter):
                The writer to use for the export.

            is_inner (bool, optional):
                Whether to display this within an existing function.

        Returns:
            dict:
            Information on the labels and comments for this address.
        """
        exporter = self.exporter
        listing = exporter.listing

        # Fetch any existing comments and labels for this address.
        plate_comment = listing.getComment(CodeUnit.PLATE_COMMENT, addr)
        pre_comment = listing.getComment(CodeUnit.PRE_COMMENT, addr)
        pending_labels = exporter.get_labels_at_addr(addr)
        func = exporter.func_manager.getFunctionAt(addr)

        if plate_comment or pre_comment or pending_labels:
            # There's something to show here, so flush any pending bytes.
            self.bytes_writer.flush()

        if is_inner:
            pre_comment_indent = ' ' * 4
        else:
            pre_comment_indent = ''

        # Write blank lines preceding any content.
        if plate_comment or (func is None and pre_comment):
            writer.write_blank_line(count=2)
        elif pending_labels and not plate_comment and not pre_comment:
            writer.write_blank_line()

        if func is not None:
            # This is a function. Write the anchor and prepare a plate
            # comment if needed.
            writer.new_code_unit()
            writer.write_anchor(func.getName(), addr)

            if not plate_comment:
                plate_comment = self._get_default_func_comment(func)
        elif pending_labels:
            # This is not a function, but it has a label. Write an anchor.
            for label in pending_labels:
                label_name = exporter.sanitize_label_name(label)

                if label_name:
                    writer.write_anchor(label_name, addr)

            # Normalize the first pre-comment, if not a local label.
            if not pending_labels[0].startswith('@'):
                pre_comment = self._add_xrefs_to_comment(pre_comment or '',
                                                         addr)

        # If there's a plate comment, write it here.
        if plate_comment:
            plate_comment = self._add_xrefs_to_comment(plate_comment, addr)

        self.export_comment(plate_comment,
                            writer=writer,
                            leading_blank=0,
                            use_plate_syntax=True)

        if func is None:
            # Write a pre-comment at this location, before any labels.
            self.export_comment(pre_comment,
                                writer=writer,
                                indent=pre_comment_indent)

        # Write any labels.
        if pending_labels:
            eol_comment = get_addr_for_eol_comment(addr)

            for label in pending_labels:
                label_name = exporter.sanitize_label_name(label)

                if label_name:
                    writer.write_label(
                        label_name,
                        addr=addr,
                        is_local=label_name.startswith('@'),
                        eol_comment=eol_comment,
                    )

                    eol_comment = ''

        if func is not None:
            # Write this comment at this location, after the function label.
            self.export_comment(pre_comment,
                                writer=writer,
                                indent=pre_comment_indent,
                                leading_blank=0)

        if not plate_comment and not pre_comment and not pending_labels:
            # There was nothing to write, so just return None.
            return None

        return {
            'labels': pending_labels,
            'plate_comment': plate_comment,
            'pre_comment': pre_comment,
        }

    def export_comment(
        self,
        comment,                # type: str | None
        writer,                 # type: BaseFileWriter
        indent='',              # type: str
        leading_blank=1,        # type: int
        use_plate_syntax=False  # type: bool
    ):  # type: (...) -> None
        """Export a comment to the writer.

        Args:
            comment (str):
                The comment to write.

            writer (BaseFileWriter):
                The writer to use for the export.

            indent (str, optional):
                Any leading indentation for the comment.

            indent (str, optional):
                Any indentation to provide before the comment.

            leading_blank (int, optional):
                The leading number of blank lines before this comment.

            use_plate_syntax (bool, optional):
                Whether to output using plate syntax.
        """
        if not comment or not comment.strip():
            return

        comment = self.process_comment(comment)

        if not comment or not comment.strip():
            return

        writer.write_comment(comment=comment,
                             indent=indent,
                             leading_blank=leading_blank,
                             use_plate_syntax=use_plate_syntax)

    def generate_code(
        self,
        code_unit,  # type: CodeUnit
        addr,       # type: Address
        writer,     # type: BaseFileWriter
    ):  # type: (...) -> tuple[list[str], list[str]]
        """Generate an instruction and operands for a code unit.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit representing the instruction and operands.

            addr (ghidra.program.model.address.Address):
                The address to export.

            writer (BaseFileWriter):
                The writer to use for the export.
        """
        exporter = self.exporter

        # Generate raw bytes for the instructions.
        raw_instruction_bytes = [
            b & 0xFF
            for b in code_unit.getBytes()
        ]

        # Format those for output.
        instruction_bytes = [
            '{:02x}'.format(b)
            for b in raw_instruction_bytes
        ]

        # Convert the instruction to a mnemonic and generate state for it.
        mnemonic = code_unit.getMnemonicString().upper()

        operand_strings = []  # type: list[str]

        # Walk through all operands, processing them, normalizing their
        # display, and handling any references to symbols.
        for i in range(code_unit.getNumOperands()):
            op_str, primary_symbol, primary_offset = \
                self._get_operand_info(
                    code_unit=code_unit,
                    operand_index=i,
                    mnemonic=mnemonic,
                )

            default_op_rep = code_unit.getDefaultOperandRepresentation(i)
            norm_default_op_rep = default_op_rep.upper()

            if norm_default_op_rep.endswith(',X'):
                index_suffix = ',X'
            elif norm_default_op_rep.endswith(',Y'):
                index_suffix = ',Y'
            else:
                index_suffix = ''

            # If we found a symbol from the above, normalize it and
            # update any operands.
            if primary_symbol:
                symbol_ref = self.normalize_ref(
                    exporter.sanitize_label_name(primary_symbol[1]),
                    primary_symbol[0],
                    offset=primary_offset,
                )

                if (norm_default_op_rep.startswith('(') and
                    norm_default_op_rep.endswith(',X)')):
                    op_str = '({},X)'.format(symbol_ref)
                elif (norm_default_op_rep.startswith('(') and
                      norm_default_op_rep.endswith('),Y')):
                    op_str = '({}),Y'.format(symbol_ref)
                else:
                    op_str = '%s%s' % (symbol_ref, index_suffix)
            elif not op_str:
                op_str = self.normalize_operand_addressing(default_op_rep)

            # Make sure Zero Page mode isn't used for these instructions.
            if raw_instruction_bytes[0] in ABSOLUTE_ADDR_OPCODES:
                op_str = asm_mode.ABSOLUTE_ADDR_FMT % op_str

            operand_strings.append(op_str)

        code = [mnemonic.ljust(3)]
        code += operand_strings

        return instruction_bytes, code

    def normalize_operand_addressing(
        self,
        op_rep,       # type: str
    ):  # type: (...) -> str
        """Normalize the addressing for an operand.

        This will check the addressing mode of an operand. If it's absolute
        or indirect, it will take the address and try to convert it into a
        symbol. Any prefixes or suffixes on the operand will then be restored.

        Args:
            op_rep (str):
                The representation of the operand.

        Returns:
            str:
            The normalized operand with proper addressing.
        """
        is_abs = ABSOLUTE_MATCH.match(op_rep)
        m = is_abs or INDIRECT_MATCH.match(op_rep)

        if not m:
            # This is not using absolute or indirect addressing. Just
            # do routine template reference normalization and return.
            return self.normalize_ref(op_rep)

        # Extract state for the operand.
        prefix = m.groupdict().get('prefix', '')
        suffix = (m.group('suffix') or '').upper()
        addr = m.group('addr')

        if addr.startswith('0x'):
            # This is a hex address. Ensure we have a 4-byte value (padding
            # if necessary).
            addr = addr[2:]

            if len(addr) < 4:
                addr = addr.rjust(4, '0')

            # Find any possible reference pointing to this address. If one
            # is found, use that symbol's name.
            addr = self.get_ref_to_addr(addr)

        # Normalize the reference to a symbol template, if needed.
        addr = self.normalize_ref(addr)

        return '%s%s%s' % (prefix, addr, suffix)

    def process_comment(
        self,
        comment,  # type: str | None
    ):  # type: (...) -> str | None
        """Process a comment.

        This will convert any Ghidra symbol references in a comment to
        symbol placeholder used by this disassembler.

        Args:
            comment (str):
                The comment to process.

        Returns:
            str:
            The processed comment.
        """
        if not comment:
            return comment

        return SYMBOL_PLACEHOLDER_RE.sub(
            lambda m: (
                self.get_ref_to_addr(m.group('addr')) or
                m.group('addr')
            ),
            comment.rstrip())

    def get_defined_ref_and_offset(
        self,
        ref,  # type: Reference
    ):  # type: (...) -> tuple[Address, int | None]
        """Return an address and offset within it for a given reference.

        If the reference is an Offset Reference, the result will include the
        base address and the offset within that. Otherwise, it will include
        the address the reference points to without an offset.

        Args:
            ref (ghidra.program.model.symbol.Reference):
                The reference to process.

        Returns:
            tuple:
            A 2-tuple of:

            Tuple:
                0 (ghidra.program.model.address.Address):
                    The target address.

                1 (int):
                    The offset within the target address, or ``None`` if
                    this is not an offset address.
        """
        if isinstance(ref, OffsetReference):
            return ref.getBaseAddress(), ref.getOffset()
        else:
            return ref.getToAddress(), None

    def get_ref_str_from_addr(
        self,
        addr,  # type: Address
    ):  # type: (...) -> str | None
        """Return a normalized reference from a given address.

        If the address maps to a symbol, it will be normalized into a
        symbol placeholder.

        Args:
            addr (ghidra.program.model.address.Address):
                The address.

        Returns:
            str:
            The normalized reference to a symbol, or ``None`` if not found.
        """
        exporter = self.exporter
        symbol = None
        refs = exporter.ref_manager.getReferencesFrom(addr)

        if refs:
            assert len(refs) == 1

            symbol = exporter.symbol_table.getPrimarySymbol(
                refs[0].getToAddress(),
            )

            if symbol:
                return self.normalize_ref(
                    symbol.getName(True),
                    exporter.get_block_name_for_addr(addr),
                )

        return None

    def get_ref_to_addr(
        self,
        addr_str,  # type: str
    ):  # type: (...) -> str
        """Return a normalized reference to a given address string.

        This will take a string representing an address (in ``<addr>`` or
        ``<block>::<addr>`` form) and attempt to find a symbol at that
        address. If found, it will be normalized as a symbol placeholder.
        If not, it will be formatted as a standard representation of an
        address.

        If the string does not include a block, the current block will be
        used.

        Args:
            addr_str (str):
                The string representation of the address.

        Returns:
            str:
            The normalized symbol placeholder or string address
            representation.
        """
        addr = None             # type: Address | None
        fallback_symbol = None  # type: tuple | None
        sanitized_symbol = None
        sanitized_symbol_offset = 0

        norm_addr_str = addr_str.lower()
        norm_addrs = [(norm_addr_str, 0)]

        if '::' not in norm_addr_str:
            # The address doesn't include a block, so consider one relative
            # to the current block.
            norm_addrs.append((
                '%s::%s' % (self.block_name.lower(), norm_addr_str),
                0,
            ))

        # Go through the candidates, validate them, and ensure a consistent
        # address format for each.
        for norm_addr, offset in list(norm_addrs):
            parts = norm_addr.split(':')

            try:
                temp_addr = int(parts[-1], 16) - 1
            except ValueError:
                continue

            norm_addrs.append((
                '%s%04x' % ('::'.join(parts[:-1]), temp_addr),
                1,
            ))

        # Go through the normalized candidates and look for any symbols.
        for norm_addr, offset in norm_addrs:
            if norm_addr:
                fallback_symbol = (
                    exporter.addr_to_label.get(norm_addr, [None])[0] or
                    exporter.addr_to_symbol.get(norm_addr, [None])[0]
                )

                if not fallback_symbol and SYMBOL_RE.match(norm_addr) and addr:
                    addr = exporter.default_addr_space.getAddress(norm_addr)

                    if addr:
                        fallback_symbol = \
                            exporter.find_symbol_for_address(addr)

                if fallback_symbol:
                    # A symbol was found. Store the information on it and
                    # break out of the loop.
                    sanitized_symbol = (
                        fallback_symbol[0],
                        exporter.sanitize_label_name(fallback_symbol[1]),
                    )
                    sanitized_symbol_offset = offset
                    break

        if sanitized_symbol:
            # We found a symbol above. Normalize the reference to the
            # symbol.
            ref = self.normalize_ref(sanitized_symbol[1],
                                     sanitized_symbol[0],
                                     offset=sanitized_symbol_offset)
        else:
            # A symbol was not found. Instead, parse the address and create
            # a suitable representation.
            norm_addr = norm_addr_str

            if ADDR_RE.match(norm_addr):
                if norm_addr.startswith('00'):
                    ref = '$%s' % norm_addr[2:]
                else:
                    ref = '$%s' % norm_addr
            else:
                ref = addr_str

        return ref

    def normalize_ref(
        self,
        ref,              # type: str
        block_name=None,  # type: str | None
        offset=0,         # type: int
    ):  # type: (...) -> str
        """Normalize a string representation to an address.

        This will take a reference name and compute either a symbol placeholder
        for it or return it as-is.

        If a block name is provided or can be inferred, a symbol placeholder
        will be used, allowing it to be resolved and linked to when writing.
        If one can't be found, it will be returned roughly as-is.

        This will also take care of applying any offset to the address. As
        a bit of a hack, if the symbol ends with ``_1`` (which Ghidra will
        sometimes do), an offset of 1 will be inferred.

        Args:
            ref (str):
                The reference to normalize.

            block_name (str, optional):
                The block name, if known. If not provided, one will be
                inferred if possible.

            offset (int, optional):
                An explicit offset to apply.

        Returns:
            str:
            The normalized symbol placeholder or provided reference, with
            an offset as needed.
        """
        if ref.startswith('{{@SYMBOL:'):
            return ref

        suffix = ''

        if ref.endswith('_1'):
            # This appears to be an offset of one, based on Ghidra's naming.
            # Strip that suffix and apply the offset.
            ref = ref[:-2]
            suffix = '+1'
        else:
            suffix = self._format_dest_offset(offset)

        if block_name is None:
            # Look for a block name for this reference by trying to find a
            # symbol.
            symbol = self.exporter.find_symbol_for_address(ref)

            if symbol is not None:
                # One was found, so use its block name.
                block_name = symbol[0]

        if block_name is not None:
            # A block name was found, so we can build a symbol placeholder
            # for later processing.
            ref = (
                '{{@SYMBOL:%s::%s@}}'
                % (block_name, ref)
            )

        return '%s%s' % (ref, suffix)

    def export_data_tree(
        self,
        data,             # type: Data
        writer,           # type: BaseFileWriter
        index_path=None,  # type: list[int] | None
    ):  # type: (...) -> int
        """Export a whole data tree.

        This will export a data tree, which may be an array, structure,
        union, or range of bytes.

        Nested arrays and structures are supported.

        Values will be normalized to the right representation for the
        inferred data types.

        Args:
            data (ghidra.program.model.listing.Data):
                The data tree to export.

            writer (BaseFileWriter):
                The writer to export to.

            index_path (list of int, optional):
                The index path for nested arrays or structures.

                Each entry will represent a layer in the nesting, using
                the index of each item in the tree.

        Returns:
            int:
            The length of the data written.
        """
        if index_path is None:
            index_path = []

        data_type = data.getDataType()
        data_len = data.getLength()
        block_initialized = self.is_block_initialized

        is_array = isinstance(data_type, Array)

        if is_array or isinstance(data_type, (Structure, Union)):
            # This is an array, structure, or union. This supports nesting.
            # We'll go through each component of the tree and export each
            # child, tracking the index of each nested item in the process.
            #
            # This will ultimately result in exporting data.
            count = data.getNumComponents()

            for i in range(count):
                child = data.getComponent(i)

                if is_array:
                    new_index_path = index_path + [i]
                else:
                    new_index_path = index_path

                self.export_data_tree(data=child,
                                      writer=writer,
                                      index_path=new_index_path)
        else:
            # This is a sequence of bytes. It's the leaf of any tree (of any
            # length).
            #
            # It'll normalize values to the right data type size and encode
            # them.
            byte_addr = data.getAddress()
            data_type_str = get_data_type_str(data_type)

            if block_initialized:
                data_bytes = data.getBytes()
            else:
                data_bytes = [None] * data_len

            if data_type_str in WORD_DATA_TYPES:
                # We'll need to specially output these as shorts.
                assert data_len % 2 == 0

                data_size = 2

                if block_initialized:
                    # Normalize each pair of values into words.
                    data_values = [
                        (data_bytes[i] & 0xFF) |
                        ((data_bytes[i + 1] & 0xFF) << 8)
                        for i in range(0, data_len, 2)
                    ]
                else:
                    data_values = [None] * (data_len // 2)
            else:
                # Output anything else as bytes.
                data_values = data_bytes
                data_size = 1

            self._encode_bytes(
                data_values=data_values,
                data_type=data_type,
                data_type_str=data_type_str,
                size=data_size,
                writer=writer,
                addr=byte_addr,
                index_path=index_path,
            )

        return data_len

    def _encode_bytes(
        self,
        data_values,    # type: list[int]
        data_type,      # type: DataType
        data_type_str,  # type: str
        size,           # type: int
        writer,         # type: BaseFileWriter
        addr,           # type: Address
        index_path,     # type: list[int]
    ):  # type: (...) -> None
        """Encode and export a sequence of bytes.

        Args:
            data_values (list of int):
                The list of values to encode

            data_type (ghidra.program.model.data.DataType):
                The type of the data to encode.

            data_type_str (str):
                The string representation of the data type.

            size (int):
                The size of each value.

            writer (BaseFileWriter):
                The writer to export to.

            addr (ghidra.program.model.address.Address):
                The address of the first byte in the sequence.

            index_path (list of int):
                The path of indexes for nested arrays/structures.
        """
        assert data_values

        exporter = self.exporter
        listing = exporter.listing

        bytes_writer = self.bytes_writer
        end_addr = self.end_addr
        code_op = None  # type: str | None

        # If the data type is a reference, perform special checks to
        # resolve values as symbols.
        check_jump_tables = data_type_str in REF_DATA_TYPES

        if check_jump_tables:
            # Determine what assembly directive we want to represent
            # this data type for the reference.
            if data_type_str in WORD_DATA_TYPES:
                code_op = (
                    WORD_DATA_TYPES.get(data_type_str) or
                    asm_mode.WORD_OP
                )
            else:
                code_op = asm_mode.CHAR_OP

        if index_path and data_type_str != 'char':
            # Build comments that indicate the nesting level.
            comment_prefix = ''.join(
                '[%s]: ' % i
                for i in index_path
            )
            default_comment_suffix = ''
        else:
            comment_prefix = ''
            default_comment_suffix = data_type_str

        # Begin exporting each value.
        for value_i, value in enumerate(data_values):
            labels_comments = self.export_labels_and_comments(addr, writer)
            labeled = bool(labels_comments)

            # Build an EOL comment for this entry. We'll prioritize any
            # comment already set, or any default computed above. If neither
            # are set, a new default specific to this address may be created.
            comment_suffix = listing.getComment(CodeUnit.EOL_COMMENT, addr)

            if comment_prefix or comment_suffix:
                eol_comment = '%s%s' % (
                    comment_prefix,
                    comment_suffix or default_comment_suffix,
                )
            else:
                eol_comment = ''

            if not eol_comment:
                ref_str = self.get_ref_str_from_addr(addr)

                if ref_str:
                    eol_comment = '%s [$%s]' % (ref_str, addr)

            output_bytes = True

            # If this appears to be a jump table pointing to other references,
            # then begin processing the current entry in that table.
            if check_jump_tables:
                # Check if the entry in the table references a target.
                target_info = self._get_jump_table_dest_target(
                    entry_addr=addr,
                    entry_value=value,
                    entry_data_type_str=data_type_str,
                )

                if target_info:
                    # A target was referenced. Build a formatted name with
                    # with any necessary prefixes and suffixes for that
                    # target.
                    offset_str = self._format_dest_offset(
                        target_info['offset'])
                    dest_name = '%s%s' % (
                        self.normalize_ref(
                            exporter.sanitize_label_name(target_info['name']),
                            target_info['block_name']),
                        offset_str,
                    )

                    # See if there's a prefix needed for this data type in
                    # order to reference a lower or upper byte.
                    data_dest_name_prefix = \
                        REF_DATA_TYPE_PREFIXES.get(data_type_str, '')

                    if data_dest_name_prefix:
                        # There was a prefix. If there's an offset, wrap the
                        # combined address + offset in parens so the prefix
                        # will apply to that result.
                        if offset_str:
                            dest_name = '(%s)' % dest_name

                        # Apply the prefix.
                        dest_name = '%s%s' % (data_dest_name_prefix,
                                              dest_name)

                    # Write the entry for the table.
                    assert code_op is not None

                    writer.write_code(
                        [code_op, dest_name],
                        addr=addr,
                        eol_comment=self.process_comment(eol_comment),
                    )

                    output_bytes = False

            if output_bytes:
                bytes_writer.append(
                    value,
                    addr,
                    data_type=data_type,
                    size=size,
                    eol_comment=self.process_comment(eol_comment),
                    labeled=labeled,
                )

            if addr == end_addr:
                # We're done.
                break

            try:
                addr = addr.addNoWrap(size)
            except Exception:
                break

    def _get_operand_info(
        self,
        code_unit,      # type: CodeUnit
        operand_index,  # type: int
        mnemonic,       # type: str
    ):  # type: (...) -> tuple[str | None, Symbol | None, int]
        """Return processed information for an operand.

        This will process the operand and determine if it's a reference to
        a target address or a scalar value.

        If it's a reference to an address, a primary symbol will be returned
        for that address, if one is found.

        If it's a scalar, the operand value will be returned based on the
        target assembler.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit to process.

            operand_index (int):
                The index of the operand.

            mnemonic (str):
                The instruction mnemonic this operand follows.

        Returns:
            tuple:
            A 3-tuple of:

            Tuple:
                0 (str):
                    The operand string, if a scalar. ``None`` otherwise.

                1 (ghidra.program.model.symbol.Symbol):
                    The primary symbol, if found. ``None`` otherwise.

                2 (int):
                    The offset from the primary symbol, if found. ``None``
                    otherwise.
        """
        # Build a map of normalized target addresses to reference objects,
        # based on the operands in this code unit.
        op_refs = {
            _ref.getToAddress().toString(False).lower(): _ref
            for _ref in code_unit.getOperandReferences(operand_index)
        }

        op_str = None  # type: str | None
        default_op_rep = \
            code_unit.getDefaultOperandRepresentation(operand_index)

        primary_symbol = None  # type: Symbol | None
        primary_offset = 0     # type: int

        # Loop through all the operands and convert any addresses to
        # a suitable reference target if one is available. If one is
        # found, it may be converted to a relative address, depending
        # on the disassembly.
        for op_obj in code_unit.getOpObjects(operand_index):
            op_addr_ref = None  # type: str | None
            op_addr = None      # type: Address | None

            if isinstance(op_obj, GenericAddress):
                # This is a generic address, which is not tied to
                # a given bank. We'll use the lookup table of
                # defined references if we can.
                op_addr = op_obj
                op_addr_ref = op_refs.get(str(op_obj).lower())
            elif isinstance(op_obj, Address):
                # This is an explicit address, which should resolve
                # to a stable location.
                op_addr = op_obj
            elif isinstance(op_obj, Scalar):
                # This may be a value to include as an operand, or
                # it may be an address. Find out which it may be.
                if default_op_rep.startswith('#'):
                    # This is a static value. Format it appropriately.
                    scalar_value = op_obj.getValue()

                    if (abs(scalar_value) <= 0xFF and
                        not mnemonic.startswith('j')):
                        op_str = asm_mode.format_op_byte(scalar_value)
                    else:
                        op_str = asm_mode.format_op_word(scalar_value)

                    break
                else:
                    # Treat this as a reference to convert to a
                    # symbol.
                    op_addr_ref = op_refs.get('%04x' % op_obj.getValue())
            else:
                # This isn't an operand value we need to transform.
                continue

            # If we have an address reference, determine the target
            # address and offset.
            op_addr_offset = 0

            if op_addr_ref is not None:
                op_addr, op_addr_offset = \
                    self.get_defined_ref_and_offset(op_addr_ref)

            # If we have an address, try to convert it to a symbol.
            if op_addr is not None:
                symbol = exporter.find_symbol_for_address(op_addr)

                if symbol:
                    primary_symbol = symbol
                    primary_offset = op_addr_offset or 0
                    break

        return op_str, primary_symbol, primary_offset

    def _get_jump_table_dest_target(
        self,
        entry_addr,            # type: Address
        entry_value,           # type: int
        entry_data_type_str,   # type: str
    ):  # type: (...) -> Mapping[str, Any] | None
        """Process an entry in a table, returning any resolved reference info.

        This will look at the provided entry in the table, making various
        checks to see if there's a target symbol and destination address
        referenced by the entry. That reference may be defined in Ghidra
        explicitly or it may be defined based on the data type.

        Args:
            entry_addr (ghidra.program.model.address.Address):
                The address of the entry.

            entry_value (int):
                The entry value.

            entry_data_type_str (str):
                The data type of the entry.

        Returns:
            dict:
            A dictionary containing:

            Keys:
                addr (ghidra.program.model.address.Address):
                    The target address.

                block_name (str):
                    The target block name.

                offset (int):
                    The target offset within the address.

                name (str):
                    The target name.
        """
        exporter = self.exporter
        refs = exporter.ref_manager.getReferencesFrom(entry_addr)

        if refs:
            # Ghidra has known references from this entry's address. Locate
            # any symbol and offset for that reference, returning the result
            # if everything is found.
            ref = refs[0]
            dest_addr, dest_offset = \
                self.get_defined_ref_and_offset(ref)
            dest_symbol = exporter.find_symbol_for_address(dest_addr)

            if dest_symbol:
                dest_block_name, dest_symbol_name = dest_symbol
                dest_addr = dest_symbol

                if dest_offset is None:
                    dest_offset = self._get_offset_for_data_type(
                        entry_data_type_str)

                    return {
                        'addr': dest_addr,
                        'block_name': dest_block_name,
                        'name': dest_symbol_name,
                        'offset': dest_offset,
                    }
        else:
            # Look for any references from this address using our own
            # methods. This will look for any functions or general symbols.
            #
            # Functions can be a direct reference or off-by-one. Other
            # symbols must be direct reference.
            jump_dest = self._find_data_target_ref_from(entry_addr)

            if jump_dest is not None:
                if isinstance(jump_dest, Function):
                    # The destination is a function. Consider both this
                    # address and the address immediately before it.
                    jump_dest_addr = jump_dest.getEntryPoint()
                    deltas = [0, -1]
                else:
                    # The destination is any other label. Consider only that
                    # address.
                    jump_dest_addr = jump_dest.getAddress()
                    deltas = [0]

                jump_dest_addr_value = jump_dest_addr.getUnsignedOffset()

                for delta in deltas:
                    jump_table_offset = jump_dest_addr_value + delta

                    if jump_table_offset == entry_value:
                        return {
                            'addr': jump_dest_addr,
                            'block_name': exporter.get_block_name_for_addr(
                                jump_dest_addr),
                            'has_refs_from': True,
                            'name': jump_dest.getName(),
                            'offset': jump_table_offset,
                        }

        return None

    def _get_offset_for_data_type(
        self,
        data_type_str,  # type: str
    ):  # type: (...) -> int
        """Return a hard-coded offset for a given data type.

        This may be positive or negative, depending on the data type. For
        most, this will be 0.

        Args:
            data_type_str (str):
                The data type as a string.

        Returns:
            int:
            The offset.
        """
        return REF_DATA_TYPE_DELTAS.get(data_type_str, 0)

    def _format_dest_offset(
        self,
        dest_offset,  # type: int | None
    ):  # type: (...) -> str
        """Return a destination address offset formatted as a string.

        The formatted offset wlil be shown as a hex number if >= 16, or
        a decimal number if < 16.

        Args:
            dest_offset (int):
                The offset to format.

        Returns:
            str:
            The offset string.
        """
        if not dest_offset:
            return ''

        if dest_offset >= 0:
            sign = '+'
        else:
            sign = '-'

        abs_dest_offset = abs(dest_offset)

        if abs_dest_offset >= 16:
            # The offset is 16 or more bytes away, so format it as a
            # hex value to keep it manageable.
            offset_str = '$%X' % abs_dest_offset
        else:
            # The offset is under 16 bytes away, so format as a decimal
            # number just to simplify output.
            offset_str = str(abs_dest_offset)

        return '%s%s' % (sign, offset_str)

    def _find_data_target_ref_from(
        self,
        addr,  # type: Address
    ):  # type: (...) -> Function | Symbol | None
        """Find any symbols referenced from this address.

        This will look for all references from the provided address and,
        if found, return them. It explicitly looks for functions and then
        general symbols.

        Args:
            addr (ghidra.program.model.address.Address):
                The address to search.

        Returns:
            ghidra.program.model.listing.Function or
            ghidra.program.model.symbol.Symbol:
            The resulting function or symbol, or ``None`` if not found.
        """
        exporter = self.exporter
        func_manager = exporter.func_manager
        ref_manager = exporter.ref_manager
        symbol_table = exporter.symbol_table

        for ref in ref_manager.getReferencesFrom(addr):
            to_addr = ref.getToAddress()

            if to_addr:
                return (
                    func_manager.getFunctionAt(to_addr) or
                    next(symbol_table.getSymbols(to_addr))
                )

        return None

    def _get_default_func_comment(
        self,
        func,  # type: Function
    ):  # type: (...) -> str
        """Return a default comment for a function.

        This will generate a default plate comment that can be used for
        a function that otherwise lacks any function-level documentation.
        It will include a big TODO, along with any known parameters and
        outputs.

        Args:
            func (ghidra.program.model.listing.Function):
                The function to document.

        Returns:
            str:
            The default comment.
        """
        params = func.getParameters()
        func_return = func.getReturn()

        comment = [
            'TODO: Document %s' % func.getName(),
            '',
            'INPUTS:',
        ]

        if params:
            for param in params:
                comment.append('    %s' % param.getRegister().getName())
        else:
            comment.append('    None.')

        comment += [
            '',
            'OUTPUTS:',
        ]

        if func_return:
            register = func_return.getRegister()

            if register:
                return_name = register.getName()
            else:
                return_name = func_return.getName()

            if return_name == '<RETURN>':
                return_name = 'TODO'

            comment.append('    %s' % return_name)
        else:
            comment.append('    None.')

        return '\n'.join(comment)

    def _add_xrefs_to_comment(
        self,
        comment,  # type: str
        addr,     # type: Address
    ):  # type: (...) -> str
        """Add cross-references for an address to a comment.

        This takes the address and looks for anything that references that
        address. All references will be appended to the given comment as an
        ``XREFS`` section.

        Args:
            comment (str):
                The comment to append to.

            addr (ghidra.program.model.address.Address):
                The address to search for references to.

        Returns:
            str:
            The resulting comment.
        """
        xrefs = set()  # type: set[str]
        exporter = self.exporter
        listing = exporter.listing
        symbol_table = exporter.symbol_table
        refs_to_addr = self.exporter.ref_manager.getReferencesTo(addr)

        if refs_to_addr:
            # There are references to the address. Loop through them and
            # try to find out what each reference is and how it should be
            # represented.
            for ref in refs_to_addr:
                if not ref.isMemoryReference():
                    continue

                ref_type = ref.getReferenceType()

                if ref_type == RefType.FALL_THROUGH:
                    continue

                from_addr = ref.getFromAddress()

                # Check if there's a function managing the reference.
                func = exporter.func_manager.getFunctionContaining(from_addr)

                if func is not None:
                    # This was a function. Add a placeholder to that function
                    # to the list of cross-refs.
                    xrefs.add(self.normalize_ref(
                        func.getName(),
                        exporter.get_block_name_for_addr(from_addr)))
                    continue

                # Check if there's a data section managing the reference.
                data = listing.getDataContaining(from_addr)
                primary_symbol = None  # type: Symbol | None

                if data is not None:
                    # Walk to the top of the data.
                    parent = data.getParent()

                    while (parent is not None and
                           parent.getAddress() is not None and
                           parent.getAddress().compareTo(
                               data.getAddres()) <= 0 and
                           parent.getMaxAddress().compareTo(from_addr) >= 0):
                        data = parent
                        parent = data.getParent()

                    primary_symbol = \
                        symbol_table.getPrimarySymbol(data.getAddress())

                if primary_symbol is None:
                    # Get the nearest label.
                    primary_symbol = symbol_table.getPrimarySymbol(from_addr)

                if primary_symbol is not None:
                    # A symbol was found. Add it to the list of cross-refs.
                    xrefs.add(
                        '%s [$%s]'
                        % (self.normalize_ref(
                            primary_symbol.getName(True),
                            exporter.get_block_name_for_addr(from_addr)),
                           from_addr)
                    )

                    continue

            if xrefs:
                # Cross-refs were found above. Add them to the comment.
                comment = '%s\n\nXREFS:\n%s' % (
                    comment,
                    '\n'.join(
                        '    %s' % ref_name
                        for ref_name in sorted(xrefs)
                    )
                )

        return comment


class Exporter:
    """The main exporter for the disassembly.

    This loads up information about the program and begins exporting a
    series of files, documenting the entire ROM.
    """

    #: Top-level options name for the any stored settings for the exporter.
    EXPORTER_OPTIONS_NAME = 'Export NES'

    #: The setting name for the export path.
    EXPORT_PATH_SETTING = 'export.path'

    def __init__(
        self,
        program,  # type: Program
    ):  # type: (...) -> None
        """Initialize the exporter."""
        self.program = program
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.blocks = self.memory.getBlocks()
        self.func_manager = program.getFunctionManager()
        self.ref_manager = program.getReferenceManager()
        self.equate_table = program.getEquateTable()
        self.symbol_table = program.getSymbolTable()
        self.addr_factory = program.getAddressFactory()
        self.default_addr_space = self.addr_factory.getDefaultAddressSpace()

        program_name = program.getName()

        # Strip off junk from the program name that we don't care about.
        if program_name.endswith(' - .ProgramDB'):
            program_name = program_name[:len(' - .ProgramDB')]

        self.program_name = program_name

        self.addr_to_label = {}   # type: dict[str, list[tuple[str, str]]]
        self.addr_to_symbol = {}  # type: dict[str, list[tuple[str, str]]]
        self.name_to_symbol = {}  # type: dict[str, list[Symbol]]

        # Build a mapping of block names to indexes.
        self.block_index_map = {
            block.getName(): i
            for i, block in enumerate(
                sorted(
                    (
                        block
                        for block in self.blocks
                        if block.isInitialized()
                    ),
                    key=lambda block: (
                        block.getStart().getAddressSpace().getUnique(),
                        block.getStart().getOffset(),
                        block.getName(),
                    ),
                ),
            )
        }

    def export(self):  # type: (...) -> None
        """Export the disassembly to files.

        This will export a general references (table of contents) file,
        a Mesen labels file, definitions for enums, and then every block
        (bank) in the disassembly.
        """
        self.build_symbol_maps()

        # Figure out where we're exporting to.
        #
        # If this is the first run, the user will be prompted for a path.
        # That path will be remembered and used for future runs.
        options = self.program.getOptions(self.EXPORTER_OPTIONS_NAME)
        export_path = options.getString(self.EXPORT_PATH_SETTING, None)

        if export_path is  None or not os.path.exists(export_path):
            export_path = askDirectory(
                ('Where do you want to export to? asm/, html/, and mesen/ '
                 'directories will be created at this path.'),
                'Export here',
            )

            export_path = os.path.abspath(str(export_path))
            options.setString(self.EXPORT_PATH_SETTING, export_path)

        self.export_refs_index(export_path)
        self.export_mesen_labels(export_path)
        self.export_defs(export_path)

        for block in self.blocks:
            self.export_block(block, export_path)

    def export_defs(
        self,
        base_path,  # type: str
    ):  # type: (...) -> None
        """Export a definitions file.

        The definitions file is a table of contents for all symbols,
        functions, and other meaningful labels in the disassembly, grouped
        by prefixes (using ``__`` as a delimiter).

        Args:
            base_path (str):
                The base path to write files to.
        """
        writer = MultiFileWriter(base_path=base_path,
                                 block_name='DEFS',
                                 program_name=self.program_name)

        data_types = self.program.getDataTypeManager().getAllDataTypes()

        with writer.open():
            while data_types.hasNext():
                data_type = data_types.next()

                if isinstance(data_type, Enum):
                    writer.write_comment(data_type.getName(),
                                         use_plate_syntax=True)

                    writer.write_equs([
                        (self.normalize_var(data_type.getName(value)),
                         '${:02x}'.format(value))
                        for value in data_type.getValues()
                    ])

    def export_block(
        self,
        block,      # type: MemoryBlock
        base_path,  # type: str
    ):  # type: (...) -> None
        """Export a block (generally a bank) to a file.

        The exported block will contain all code and data needed to view
        the disassembly and compile it back into the right memory address.

        Args:
            block (ghidra.program.model.mem.MemoryBlock):
                The block to export.

            base_path (str):
                The base path to write files to.
        """
        if block.getSize() <= 0:
            return

        self.block = block

        block_exporter = BlockExporter(block=block,
                                       exporter=self)
        writer = MultiFileWriter(base_path=base_path,
                                 block_name=block_exporter.block_name,
                                 program_name=self.program_name)

        with writer.open():
            block_exporter.export(writer)

    def export_mesen_labels(
        self,
        base_path,  # type: str
    ):  # type: (...) -> None
        """Export a Mesen labels file.

        This will generate a file for Mesen that assigns names to file offset
        addresses, making it easy to keep Mesen and the disassembly in sync.

        Args:
            base_path (str):
                The base path to write files to.
        """
        mesen_path = os.path.join(base_path, 'mesen')

        if not os.path.exists(mesen_path):
            os.mkdir(mesen_path, 0o755)

        symbols = self.symbol_table.getAllSymbols(True)
        block_index_map = self.block_index_map
        memory = self.memory

        results = []  # type: list[tuple[int, str]]

        # Iterate through all label and function symbols, building a list
        # that can be sorted and written.
        while symbols.hasNext():
            symbol = symbols.next()
            addr = symbol.getAddress()

            if not addr:
                continue

            if symbol.getSymbolType() not in (SymbolType.LABEL,
                                              SymbolType.FUNCTION):
                continue

            block = memory.getBlock(addr)

            if block is None:
                continue

            bank_index = block_index_map.get(block.getName())

            if bank_index is None:
                continue

            offset_in_block = addr.subtract(block.getStart())
            block_size = block.getSize()

            if offset_in_block < 0 or offset_in_block >= block_size:
                continue

            file_offset = bank_index * block_size + offset_in_block
            results.append((
                file_offset,
                self.sanitize_label_name(symbol.getName()),
            ))

        filename = os.path.join(
            mesen_path,
            '%s.mlb' % self.program_name.split('.', 1)[0])

        # Sort the results so they're in offset order.
        results.sort()

        # Write the result to the file.
        with open(filename, 'w') as fp:
            for file_offset, name in results:
                fp.write('NesPrgRom:%04X:%s\n'
                         % (file_offset, name))

        os.chmod(filename, 0o644)

    def export_refs_index(
        self,
        base_path,  # type: str
    ):  # type: (...) -> None
        """Export a symbol references table of contents file.

        This will generate a file that includes all known references,
        linking to the target addresses for each.

        References are grouped by the first prefix in an underscore-separated
        identifier.

        Args:
            base_path (str):
                The base path to write files to.
        """
        program_name = self.program_name
        writer = HTMLFileWriter(base_path=base_path,
                                block_name='REFERENCES',
                                program_name=program_name)

        with writer.open():
            writer.write_comment(
                comment=(
                    '{program}\n'
                    '\n'
                    'References'
                ).format(program=program_name),
                leading_blank=0,
                use_plate_syntax=True,
            )
            writer.write_blank_line()

            last_prefix = None

            for name, symbols in sorted(self.name_to_symbol.items(),
                                        key=lambda pair: pair[0]):
                if name.startswith('_'):
                    continue

                prefix = name.split('_', 1)[0]

                if last_prefix != prefix:
                    writer.write_comment(
                        comment=prefix,
                        leading_blank=2,
                        use_plate_syntax=True,
                    )
                    last_prefix = prefix

                lines = []  # type: list[str]

                for symbol in symbols:
                    addr = symbol.getAddress()
                    block_name = self.get_block_name_for_addr(addr)

                    lines.append(
                        '<a href="%s.html#%s">%s</a>'
                        % (block_name, name, addr)
                    )

                writer.write_lines([
                    '<div class="idx">'
                    '<span class="idx-name">%s</span> '
                    '<span class="idx-targets">%s</span>'
                    '</div>'
                    % (name, ''.join(lines))
                ])

    def build_symbol_maps(self):  # type: (...) -> None
        """Build mapping tables for all symbols.

        This will walk all symbols and generate a set of mapping tables that
        can be used to map addresses to labels or to block and sanitized
        label names, and to map symbol names to instances.
        """
        addr_to_label_map = {}   # type: dict[str, list[tuple[str, str]]]
        addr_to_symbol_map = {}  # type: dict[str, list[tuple[str, str]]]
        name_to_symbol_map = {}  # type: dict[str, list[Symbol]]

        symbols = self.symbol_table.getSymbolIterator()

        while symbols.hasNext():
            symbol = symbols.next()
            addr = symbol.getAddress()

            if not addr:
                continue

            symbol_name = symbol.getName()
            is_user_symbol = (symbol.getSource() != 0)

            is_label = False
            is_user_label = False

            if symbol.getSymbolType() == SymbolType.LABEL:
                is_label = True
                is_user_label = (is_label and is_user_symbol)

            addr_str = addr.toString()
            addr_key = addr_str.lower()

            name_to_symbol_map.setdefault(symbol_name, []).append(symbol)

            addr_to_symbol_map.setdefault(addr_key, []).append((
                self.get_block_name_for_addr(addr),
                self.sanitize_label_name(symbol_name)
            ))

            if is_user_label or addr_str not in addr_to_label_map:
                label_name = self.sanitize_label_name(symbol_name)

                if label_name:
                    addr_to_label_map.setdefault(addr_key, []).append((
                        self.get_block_name_for_addr(addr),
                        label_name,
                    ))

        self.addr_to_label = addr_to_label_map
        self.addr_to_symbol = addr_to_symbol_map
        self.name_to_symbol = name_to_symbol_map

    def normalize_address(
        self,
        addr,           # type: Address
    ):  # type: (...) -> str | None
        """Normalize an address to a string.

        This will take an address and optional block name and turn it into
        a normalized address string representation.

        Args:
            addr (ghidra.program.model.address.Address):
                The address to normalize.

        Returns:
            str:
            The normalized string representation of the address.
        """
        if not addr or not isinstance(addr, Address):
            return None

        # Convert the Address to a string representation, stripping any
        # leading "0x" and ensuring the resulting address is a 4-character
        # address representation in lowercase.
        addr_str = str(addr).rsplit(':', 1)[-1]

        if addr_str.startswith('0x'):
            addr_str = addr_str[2:]

        try:
            int_val = int(addr_str, 16)

            return '{:04x}'.format(int_val)
        except ValueError:
            return addr_str.lower().zfill(4)

    def normalize_var(
        self,
        name,  # type: str
    ):  # type: (...) -> str
        """Return a normalized version of a variable name.

        This will replace any ``.`` characters with ``_``.

        Args:
            name (str):
                The variable name to normalize.

        Returns:
            str:
            The normalized name.
        """
        return name.replace('.', '_')

    def get_block_name_for_addr(
        self,
        addr,  # type: Address
    ):  # type: (...) -> str
        """Return the block name for an address.

        Args:
            addr (ghidra.program.model.address.Address):
                The address.

        Returns:
            str:
            The address's block name.
        """
        assert isinstance(addr, Address)

        return addr.getAddressSpace().getName()

    def find_symbol_for_address(
        self,
        addr,  # type: Address | str
    ):  # type: (...) -> tuple[str, str] | None
        """Return symbol information for a given address, if one is found.

        This support an address or a string representation of the address.

        If one is found, the result will be a tuple containing the block name
        and sanitized label for the symbol.

        If multiple symbols are found, the first will be returned.

        Args:
            addr (ghidra.program.model.address.Address or str):
                The address to use for the search.

        Returns:
            tuple:
            If a symbol is found, this will be a 2-tuple of:

            Tuple:
                0 (str):
                    The block name where the symbol resides.

                1 (str):
                    The sanitized label for the symbol.

            If one is not found, this will be ``None``.
        """
        symbols = self.find_symbols_for_address(addr)

        if symbols:
            return symbols[0]

        return None

    def find_symbols_for_address(
        self,
        addr,  # type: Address | str
    ):  # type: (...) -> list[tuple[str, str]]
        """Return all symbols for a given address.

        This support an address or a string representation of the address.

        Any that are found will be returned in a list of tuples, each
        containing the block name and sanitized label for the symbol.

        Args:
            addr (ghidra.program.model.address.Address or str):
                The address to use for the search.

        Returns:
            list of tuple:
            Each symbol that's found, as a 2-tuple of:

            Tuple:
                0 (str):
                    The block name where the symbol resides.

                1 (str):
                    The sanitized label for the symbol.
        """
        if isinstance(addr, (str, unicode)):
            if not SYMBOL_RE.match(addr):
                return []

            addr = self.default_addr_space.getAddress(addr)

        result = []  # type: list[tuple[str, str]]

        if addr is None:
            return result

        assert isinstance(addr, Address), addr

        symbols = self.symbol_table.getSymbols(addr)

        remaining_result = []

        addr_str = str(addr).lower()
        result += self.addr_to_label.get(addr_str, [])
        result += self.addr_to_symbol.get(addr_str, [])

        for symbol in symbols:
            symbol_info = (
                self.get_block_name_for_addr(symbol.getAddress()),
                self.sanitize_label_name(symbol.getName()),
            )

            if (symbol.getSource() != 0 and
                symbol.getSymbolType() == SymbolType.LABEL):
                result.append(symbol_info)
            else:
                remaining_result.append(symbol_info)

        result += remaining_result

        return result

    def sanitize_label_name(
        self,
        name,  # type: str
    ):  # type: (...) -> str
        """Return a sanitized label name.

        This will replace any invalid characters in the label with an
        underscore, and strip any ``[0]`` characters at the end of the label.

        If the label starts with an underscore or ``LAB_``, it will be
        prefixed with a ``@`` in order to define a relative label.

        Args:
            name (str):
                The label name to normalize.

        Returns:
            str:
            The normalized label name.
        """
        assert name

        label_name = INVALID_LABEL_NAME_RE.sub(
            '_',
            name.replace('[0]', ''))

        if (label_name.startswith(('_', 'LAB_')) and
            not label_name.startswith('_thunk_')):
            label_name = '@%s' % label_name

        return label_name

    def get_labels_at_addr(
        self,
        addr,  # type: Address
    ):  # type: (...) -> list[str]
        """Return all labels for a given address.

        This will look for all user-created labels or function names that
        identify the given address, returning each result as a sorted list.

        Args:
            addr (ghidra.program.model.address.Address):
                The address to use for the search.

        Returns:
            list of str:
            Each label name at the address.
        """
        symbols = self.symbol_table.getSymbols(addr)
        instruction = self.listing.getInstructionAt(addr)
        new_labels = set()

        for symbol in symbols:
            symbol_type = symbol.getSymbolType()

            found = (
                symbol_type == SymbolType.FUNCTION or
                (symbol_type == SymbolType.LABEL and
                 symbol.getSource() != 0 and
                 instruction is not None and
                 instruction.getAddress().equals(addr))
            )

            if found:
                new_labels.add(self.sanitize_label_name(symbol.getName()))

        new_labels.update(
            symbol[1]
            for symbol in self.find_symbols_for_address(addr)
        )

        return sorted(new_labels)


def main():
    """Main function for the exporter plugin.

    This will set up the configuration state and the exporter and begin
    the export process.
    """
    global asm_mode, exporter

    program = state.getCurrentProgram()

    print('=' * 60)
    print(' Exporting NES code for %s' % program.getName())
    print('=' * 60)

    asm_mode = CA65Target()

    exporter = Exporter(program)
    exporter.export()


if __name__ == '__main__':
    main()
