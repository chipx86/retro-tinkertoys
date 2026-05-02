# Update the types of data values without losing comments or references.
#
# Normally, when updating data types in Ghidra, any existing comments or
# references will be lost. This change carefully saves this state, updates
# the data types, and then restores them.
#
# Copyright (C) 2025 Christian Hammond.
#
# Licensed under the MIT license.


#@author Christian Hammond (ChipX86)
#@category Retro Tinkertoys
#@menupath Tools.Data - Update Types


from __future__ import unicode_literals

from ghidra.app.script import GhidraScript

from ghidra.app.services import DataTypeManagerService
from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.program.model.address import Address
from ghidra.program.model.data import Array, ArrayDataType, DataType
from ghidra.program.model.listing import CodeUnit, Listing
from ghidra.program.model.symbol import RefType, ReferenceManager, SourceType
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.util.exception import CancelledException

if 0:
    _StoredComments = dict[int, str | None]

    _StoredRefs = list[tuple[
        Address,
        Address,
        RefType,
        SourceType,
        int,
        int,
    ]]


class UpdateDataTypes(GhidraScript):
    def run(self):  # type: (...) -> None
        """Run the script.

        This will take the selection range and ask for the data type to
        replace those values with. It will then attempt to replace them
        all, splitting or merging values as necessary.
        """
        try:
            start, end = self._get_selection_range()
            data_type = self._ask_data_type()

            if data_type is not None:
                self._update_datatypes(start, end, data_type)
        except CancelledException:
            popup('Canceled.')
        except Exception as e:
            popup('Error: %s' % e)

    def _get_selection_range(self):  # type: (...) -> tuple[Address, Address]
        """Return the selection range to update.

        If there's an existing selection, this will use that. Otherwise, the
        user will be prompted for a start and end address.

        Returns:
            tuple:
            A 2-tuple of:

            Tuple:
                0 (ghidra.program.model.address.Address):
                    The start address.

                1 (ghidra.program.model.address.Address):
                    The end address.
        """
        sel = currentSelection

        if sel is not None and not sel.isEmpty():
            # There's a selection, so use that.
            return sel.getMinAddress(), sel.getMaxAddress()

        # There was no selection. Ask the user what they want to use for
        # the addresses.
        start = self.askAddress('Start Address', 'Enter start address')
        end = self.askAddress('End Address', 'Enter end address')

        if start.compareTo(end) > 0:
            # The addresses are reversed. Swap them.
            start, end = end, start

        return start, end

    def _ask_data_type(self):  # type: (...) -> DataType
        """Ask the user for the data type to apply.

        Returns:
            ghidra.program.model.data.DataType:
            The resulting data type.

        Raises:
            ghidra.util.exception.CancelledException:
                The user cancelled the dialog.
        """
        tool = state.getTool()
        data_type_manager = currentProgram.getDataTypeManager()

        dlg = DataTypeSelectionDialog(
            tool,                           # serviceProvider
            data_type_manager,              # dtm
            -1,                             # maxSize
            AllowedDataTypes.FIXED_LENGTH,  # allowedTypes
        )
        dlg.setTitle('Choose a data type')

        tool.showDialog(dlg)

        dt = dlg.getUserChosenDataType()

        if dt is None:
            raise CancelledException('No data type was chosen.')

        return dt

    def _update_datatypes(
        self,
        start,      # type: Address
        end,        # type: Address
        data_type,  # type: DataType
    ):  # type: (...) -> None
        """Update the data type across the selection.

        This will loop through the selection, tracking all arrays and
        individual data items that need updating. Each of these will have
        any existing comments and references saved, which will be restored
        after the data types have been updated.

        If the size of the data types have changed, this will make a
        best-attempt at splitting or combining values. That is, a short
        should become two bytes, or vice-versa.

        Args:
            start (ghidra.program.model.address.Address):
                The start address.

            end (ghidra.program.model.address.Address):
                The end address.

            data_type (ghidra.program.model.data.DataType):
                The data type to apply.
        """
        program = currentProgram
        listing = program.getListing()

        data_len = data_type.getLength()

        if data_len <= 0:
            raise Exception(
                "The selected data type doesn't have a known or predictable "
                "length. You need to use a fixed-length data type."
            )

        if self._get_range_has_instructions(listing, start, end):
            raise Exception(
                'The selection contains instructions. Please make sure it '
                'only contains data values.'
            )

        placements = []  # type: list[tuple[Address, int, str]]

        # Walk through the selection range, looking for the start of any
        # arrays that fully fit within the range.
        cur_addr = start

        while cur_addr.compareTo(end) <= 0:
            # Check if there's an array starting at this address.
            array = self._get_array_at(listing, cur_addr)

            if array is not None:
                array_len = array.getLength()
                array_end = cur_addr.add(array_len - 1)

                # Only treat it as a unit if it fully fits in our selection.
                if array_end.compareTo(end) <= 0:
                    # It does, so add it for tracking.
                    placements.append((cur_addr, array_len, 'array'))

                    # Advance past the array.
                    cur_addr = cur_addr.add(array_len)

                    continue

            # This was not the start of an array, or the array did not fit
            # within the range. Treat this as a single item, and make sure it
            # fits within the range.
            item_end = cur_addr.add(data_len - 1)

            if item_end.compareTo(end) <= 0:
                # It does, so add it for tracking.
                placements.append((cur_addr, data_len, 'item'))
                cur_addr = cur_addr.add(data_len)

        # Grab all the comments and references for each of the places
        # we've tracked.
        ref_mgr = program.getReferenceManager()
        comment_map = {}  # type: dict[Address, _StoredComments | None]
        refs_map = {}  # type: dict[Address, _StoredRefs]

        for placement_addr, placement_len, placement_kind in placements:
            comment_map[placement_addr] = self._get_comments(
                listing=listing,
                addr=placement_addr,
            )
            refs_map[placement_addr] = self._get_outgoing_refs(
                ref_mgr=ref_mgr,
                addr=placement_addr,
            )

        # Prepare to track progress for the updating, since this can take a
        # little while.
        monitor.initialize(len(placements))

        # Loop through all the placements we found above.
        for i, (placement_addr,
                placement_len,
                placement_kind) in enumerate(placements):
            monitor.checkCanceled()
            monitor.setProgress(i)

            # Find the end of the placement.
            placement_end = placement_addr.add(placement_len - 1)

            # Clear out this entire range.
            clearListing(placement_addr, placement_end)

            if placement_kind == 'array':
                # This is an array. Rebuild it with the same length. This
                # may involve combining or splitting items.
                new_item_count = placement_len // data_len

                if placement_len % data_len == 0:
                    # This fits evenly. Create a new array covering the
                    # item count we need.
                    array_data_type = ArrayDataType(data_type, new_item_count,
                                                    data_len)
                    createData(placement_addr, array_data_type)
                else:
                    # The items won't fit in the placement. Only process what
                    # we can, and keep it flat data.
                    for i in range(new_item_count):
                        item_addr = placement_addr.add(i * data_len)
                        createData(item_addr, data_type)
            elif placement_kind == 'item':
                # This is an individual item.
                createData(placement_addr, data_type)
            else:
                printerr('Unexpected internal placement state type: %r'
                         % placement_kind)
                continue

            # Remove any auto-created outgoing references.
            for ref in ref_mgr.getReferencesFrom(placement_addr):
                try:
                    ref_mgr.delete(ref)
                except Exception:
                    # If we can't delete this, ignore it.
                    pass

            # And restore the references and comments.
            self._restore_outgoing_refs(
                ref_mgr=ref_mgr,
                refs=refs_map.get(placement_addr, []),
            )
            self._restore_comments(
                listing=listing,
                addr=placement_addr,
                comments=comment_map.get(placement_addr),
            )

    def _get_range_has_instructions(
        self,
        listing,  # type: Listing
        start,    # type; Address
        end       # type: Address
    ):  # type: (...) -> bool
        """Return whether a range contains any code instructions.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing to search through.

            start (ghidra.program.model.address.Address):
                The start address of the range.

            end (ghidra.program.model.address.Address):
                The end address of the range.

        Returns:
            bool:
            ``True`` if the range contains instructions. ``False`` if they
            do not.
        """
        # First check if the start of the range has an instruction.
        if listing.getInstructionAt(start) is not None:
            return True

        # Next, walk the instructions in the range and check.
        instructions_iter = listing.getInstructions(start, True)

        while instructions_iter.hasNext():
            instruction = instructions_iter.next()

            if instruction.getAddress().compareTo(end) <= 0:
                return True

        # No instructions were found.
        return False

    def _get_array_at(
        self,
        listing,  # type: Listing
        addr,     # type: Address
    ):  # type: (...) -> Array | None
        """Return the array at a given address.

        This will check if there's any data at the given address and see if
        it's an array starting at that address. If so, it will be returned.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing containing the address.

            addr (ghidra.program.model.address.Address):
                The address to check for the start of an array.

        Returns:
            ghidra.program.model.data.Array:
            The array, if found and starting at the address, or ``None`` if
            not.
        """
        data = listing.getDataAt(addr)

        if data is not None:
            data_type = data.getDataType()

            if isinstance(data_type, Array) and data.getMinAddress() == addr:
                return data

        # No array was found starting at that address.
        return None

    def _get_comments(
        self,
        listing,  # type: Listing
        addr,     # type: Address
    ):  # type: (...) -> _StoredComments | None
        """Return all comment types for a code unit at the given address.

        If the provided address is a code unit, this will return a mapping
        of all comment types to their values.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing owning the address.

            addr (ghidra.program.model.address.Address):
                The address to fetch comments for.

        Returns:
            dict:
            A mapping of comment types to values, if this is a code unit.
            Otherwise, this will be ``None``.
        """
        code_unit = listing.getCodeUnitAt(addr)

        if code_unit is None:
            # No code unit was found.
            return None

        return {
            code_unit_type: code_unit.getComment(code_unit_type)
            for code_unit_type in (
                CodeUnit.EOL_COMMENT,
                CodeUnit.PRE_COMMENT,
                CodeUnit.POST_COMMENT,
                CodeUnit.PLATE_COMMENT,
                CodeUnit.REPEATABLE_COMMENT,
            )
        }

    def _get_outgoing_refs(
        self,
        ref_mgr,  # type: ReferenceManager
        addr,     # type: Address
    ):  # type: (...) -> _StoredRefs
        """Return information on all outgoing references at an address.

        Args:
            ref_mgr (ghidra.program.model.symbol.ReferenceManager):
                The reference manager used for the program.

            addr (ghidra.program.model.address.Address):
                The address to return references for.

        Returns:
            list:
            A list of tuples of reference information, in the form of:

            Tuple:
                0 (ghidra.program.model.address.Address):
                    The address referenced from.

                1 (ghidra.program.model.address.Address):
                    The address being referenced.

                2 (ghidra.program.model.symbol.RefType):
                    The reference type.

                3 (ghidra.program.model.symbol.SourceType):
                    The source type.

                4 (int):
                    The operand index where the reference is attached.

                5 (bool):
                    Whether this is a primary reference.
        """
        return [
            (
                ref.getFromAddress(),
                ref.getToAddress(),
                ref.getReferenceType(),
                ref.getSource(),
                ref.getOperandIndex(),
                ref.isPrimary()
            )
            for ref in ref_mgr.getReferencesFrom(addr)
            if ref.getToAddress() is not None
        ]

    def _restore_comments(
        self,
        listing,   # type: Listing
        addr,      # type: Address
        comments,  # type: _StoredComments | None
    ):  # type: (...) -> None
        """Restore comments at an address.

        This will take any provided comments and apply them to the address.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing that owns the address.

            addr (ghidra.program.model.address.Address):
                The address to restore comments to.

            comments (dict):
                The comments to restore.
        """
        if not comments:
            # There's nothing to restore.
            return

        code_unit = listing.getCodeUnitAt(addr)

        if code_unit is not None:
            for code_unit_type, text in comments.items():
                if text:
                    code_unit.setComment(code_unit_type, text)

    def _restore_outgoing_refs(
        self,
        ref_mgr,  # type: ReferenceManager
        refs,     # type: _StoredRefs
    ):  # type: (...) -> None
        """Restore outgoing references to an address.

        This will take any provided outgoing references and apply them to the
        address.

        Args:
            ref_mgr (ghidra.program.model.symbol.ReferenceManager):
                The program's reference manager.

            refs (list of tuple):
                The list of saved reference information to apply.
        """
        # Attempt to restore the references as best as we can. Some of these
        # may already exist or may no longer be valid after having retyped
        # some data.
        for (from_addr,
             to_addr,
             ref_type,
             src_type,
             op_index,
             is_primary) in refs:
            try:
                ref = ref_mgr.addMemoryReference(
                    fromAddr=from_addr,
                    toAddr=to_addr,
                    type=ref_type,
                    source=src_type,
                    opIndex=op_index,
                )

                if ref is not None and is_primary:
                    ref_mgr.setPrimary(ref, True)
            except Exception:
                # Something went wrong. This may be a duplicate or invalid
                # reference. Ignore it.
                pass


UpdateDataTypes().run()
