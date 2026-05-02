# Add a reference to each value in a selection with a given bank and offset.
#
# This will take the selection representing values that should be relative
# to some address (such as the bank, or another label). It will ask for
# an address that each should be relative to, and then add a memory
# reference in Ghidra mapping those values to the target absolute address.
#
# Copyright (C) 2025 Christian Hammond.
#
# Licensed under the MIT license.


#@author Christian Hammond (ChipX86)
#@menupath Tools.Data - Add Reference with Offset
#@category Retro Tinkertoys


from __future__ import unicode_literals

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import RefType


class AddRefWithOffset(GhidraScript):
    """Add a reference to each value in a selection, given an offset.

    This will take the selection representing values that should be relative
    to some address (such as the bank, or another label). It will ask for
    an address that each should be relative to, and then add a memory
    reference in Ghidra mapping those values to the target absolute address.
    """

    def run(self):  # type: (...) -> None
        """Run the script.

        This will prepare the selection, prompt for input, and then begin
        creating memory references.
        """
        program = state.getCurrentProgram()
        listing = program.getListing()

        # Figure out the selection.
        #
        # If there's no selection, the current address will be used.
        sel = currentSelection

        if sel is None or sel.isEmpty():
            addr = state.getCurrentAddress()
            sel = AddressSet(addr, addr)

        # Prompt for the base address to add any selected valus to.
        base_addr = askAddress('Base address',
                               'Base address to add each value to')

        # Iterate through the bytes in the selection, generating memory
        # addresses.
        dit = listing.getDefinedData(sel, True)

        while dit.hasNext():
            d = dit.next()

            # Grab the value at the address.
            value_obj = d.getValue()

            if isinstance(value_obj, Scalar):
                # This is a scalar. Grab the value it wraps.
                offset = value_obj.getValue()
            elif isinstance(value_obj, int):
                # This is a raw value. Use it as-is.
                offset = value_obj
            else:
                # This isn't something we can add to. Skip it.
                continue

            # Add the base address the user provided.
            try:
                target = base_addr.add(offset)
            except Exception:
                continue

            # And create the memory reference.
            try:
                createMemoryReference(d, target, RefType.DATA)
            except Exception as e:
                printerr('Failed to create reference at %s: %s'
                         % (d.getMinAddress(), e))


# Run the script.
AddRefWithOffset().run()
