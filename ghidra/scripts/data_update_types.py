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

    _StoredArrayComments = dict[int, _StoredComments]
    _StoredArrayCommentsList = list[_StoredArrayComments]

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
        # we've tracked. These are index-aligned with `placements`, since
        # references and array-component comments are captured across an
        # entire placement's range, not just at its starting address.
        ref_mgr = program.getReferenceManager()
        placement_own_comments = []  # type: list[_StoredComments | None]
        placement_component_comments = []  # type: _StoredArrayCommentsList
        placement_refs = []  # type: list[dict[Address, _StoredRefs]]

        for placement_addr, placement_len, placement_kind in placements:
            placement_end = placement_addr.add(placement_len - 1)

            own_comments, component_comments = self._get_placement_comments(
                listing=listing,
                addr=placement_addr,
                kind=placement_kind,
            )
            placement_own_comments.append(own_comments)
            placement_component_comments.append(component_comments)

            placement_refs.append(self._get_range_refs_map(
                ref_mgr=ref_mgr,
                start_addr=placement_addr,
                end_addr=placement_end,
            ))

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

            # Track the end of what we actually create, which may be less
            # than the full placement if the new data type doesn't evenly
            # fit (or is wider than the whole placement).
            new_end = placement_end

            # If the array placement ends up rebuilt as flat, individually
            # created items instead of a true array (the "uneven split"
            # fallback), this tracks how many were created, so comments can
            # be restored onto each item directly instead of onto array
            # components that no longer exist.
            flat_item_count = None  # type: int | None

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
                    for item_index in range(new_item_count):
                        item_addr = placement_addr.add(item_index * data_len)
                        createData(item_addr, data_type)

                    flat_item_count = new_item_count

                    if new_item_count > 0:
                        new_end = placement_addr.add(
                            new_item_count * data_len - 1)
                    else:
                        # The new type is wider than the whole placement.
                        # Nothing was created.
                        new_end = placement_addr
            elif placement_kind == 'item':
                # This is an individual item.
                createData(placement_addr, data_type)
            else:
                printerr('Unexpected internal placement state type: %r'
                         % placement_kind)
                continue

            # Remove any auto-created outgoing references across the whole
            # range we just created.
            source_addrs = self._get_ref_source_addrs(
                ref_mgr=ref_mgr,
                start_addr=placement_addr,
                end_addr=new_end,
            )

            for ref_addr in source_addrs:
                for ref in ref_mgr.getReferencesFrom(ref_addr):
                    try:
                        ref_mgr.delete(ref)
                    except Exception:
                        # If we can't delete this, ignore it.
                        pass

            # And restore the references and comments.
            for ref_addr, addr_refs in placement_refs[i].items():
                self._restore_outgoing_refs(
                    ref_mgr=ref_mgr,
                    refs=addr_refs,
                )

            self._restore_placement_comments(
                listing=listing,
                addr=placement_addr,
                kind=placement_kind,
                own_comments=placement_own_comments[i],
                component_comments=placement_component_comments[i],
                item_len=data_len,
                flat_item_count=flat_item_count,
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

    def _get_comments_for_code_unit(
        self,
        code_unit,  # type: CodeUnit | None
    ):  # type: (...) -> _StoredComments | None
        """Return all comment types for a code unit.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit to fetch comments for.

        Returns:
            dict:
            A mapping of comment types to values. If a code unit was
            not provided, this will be ``None``.
        """
        if code_unit is None:
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
        return self._get_comments_for_code_unit(listing.getCodeUnitAt(addr))

    def _get_placement_comments(
        self,
        listing,  # type: Listing
        addr,     # type: Address
        kind,     # type: str
    ):  # type: (...) -> tuple[_StoredComments | None, _StoredArrayComments]
        """Return all comments for a placement.

        This captures the placement's own top-level comments (e.g. the
        comments on an array as a whole, or on a single item).

        For arrays, this also captures each component's own comments, keyed by
        the component's index.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing owning the address.

            addr (ghidra.program.model.address.Address):
                The placement's starting address.

            kind (str):
                The kind of placement (``array`` or ``item``).

        Returns:
            tuple:
            A 2-tuple of:

            Tuple:
                0 (dict):
                    The placement's own top-level comments, or ``None``.

                1 (dict):
                    A mapping of array component index to that component's
                    comments. This will be empty for non-array placements.
        """
        own_comments = self._get_comments(listing=listing, addr=addr)
        component_comments = {}  # type: dict[int, _StoredComments]

        if kind == 'array':
            # This is an array. Go through its componetns and build up a
            # list, storing at each component's index.
            data = listing.getDataAt(addr)

            if data is not None:
                for index in range(data.getNumComponents()):
                    component = data.getComponent(index)

                    if component is None:
                        continue

                    comments = self._get_comments_for_code_unit(component)

                    if comments:
                        component_comments[index] = comments

        return own_comments, component_comments

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

    def _get_ref_source_addrs(
        self,
        ref_mgr,     # type: ReferenceManager
        start_addr,  # type: Address
        end_addr,    # type: Address
    ):  # type: (...) -> list[Address]
        """Return every address with an outgoing reference within a range.

        This walks each address in the range, checking if there are any
        outgoing references from that address. If there is one, it will be
        returned in the result.

        Args:
            ref_mgr (ghidra.program.model.symbol.ReferenceManager):
                The reference manager used for the program.

            start_addr (ghidra.program.model.address.Address):
                The start of the range (inclusive).

            end_addr (ghidra.program.model.address.Address):
                The end of the range (inclusive).

        Returns:
            list:
            The list of addresses within the range that have at least one
            outgoing reference.
        """
        addrs = []  # type: list[Address]
        addr = start_addr

        while addr.compareTo(end_addr) <= 0:
            if len(ref_mgr.getReferencesFrom(addr)) > 0:
                addrs.append(addr)

            addr = addr.add(1)

        return addrs

    def _get_range_refs_map(
        self,
        ref_mgr,     # type: ReferenceManager
        start_addr,  # type: Address
        end_addr,    # type: Address
    ):  # type: (...) -> dict[Address, _StoredRefs]
        """Return a map of addresses to their outgoing references.

        Args:
            ref_mgr (ghidra.program.model.symbol.ReferenceManager):
                The reference manager used for the program.

            start_addr (ghidra.program.model.address.Address):
                The start of the range (inclusive).

            end_addr (ghidra.program.model.address.Address):
                The end of the range (inclusive).

        Returns:
            dict:
            A mapping of each address in the range to their outgoing
            references.
        """
        return {
            addr: self._get_outgoing_refs(ref_mgr=ref_mgr,
                                          addr=addr)
            for addr in self._get_ref_source_addrs(
                ref_mgr=ref_mgr,
                start_addr=start_addr,
                end_addr=end_addr,
            )
        }

    def _restore_comments_for_code_unit(
        self,
        code_unit,  # type: CodeUnit | None
        comments,   # type: _StoredComments | None
    ):  # type: (...) -> None
        """Restore comments onto a code unit.

        Args:
            code_unit (ghidra.program.model.listing.CodeUnit):
                The code unit to restore comments onto, such as a code unit
                itself or an individual array component.

            comments (dict):
                The comments to restore.
        """
        if comments and code_unit:
            for code_unit_type, text in comments.items():
                if text:
                    code_unit.setComment(code_unit_type, text)

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
        self._restore_comments_for_code_unit(listing.getCodeUnitAt(addr),
                                             comments)

    def _restore_placement_comments(
        self,
        listing,               # type: Listing
        addr,                  # type: Address
        kind,                  # type: str
        own_comments,          # type: _StoredComments | None
        component_comments,    # type: dict[int, _StoredComments]
        item_len=None,         # type: int | None
        flat_item_count=None,  # type: int | None
    ):  # type: (...) -> None
        """Restore all comments for a placement.

        This restores the placement's own top-level comments, and, for
        arrays, all their components' comments.

        Args:
            listing (ghidra.program.model.listing.Listing):
                The listing owning the address.

            addr (ghidra.program.model.address.Address):
                The placement's starting address.

            kind (str):
                The kind of placement (``array`` or ``item``).

            own_comments (dict):
                The placement's own top-level comments to restore.

            component_comments (dict):
                A mapping of array component index to that component's
                comments to restore.

            item_len (int, optional):
                The length of each item, used to locate flat items by
                index. Required if ``flat_item_count`` is provided.

            flat_item_count (int, optional):
                The number of flat items created in place of a true array,
                if the array was rebuilt that way. ``None`` if a true array
                was created.
        """
        self._restore_comments(listing=listing, addr=addr,
                               comments=own_comments)

        if kind != 'array' or not component_comments:
            return

        if flat_item_count is not None:
            assert item_len is not None

            # Flat items were created instead of a true array. Restore each
            # captured component directly onto its own item's address.
            for index, comments in component_comments.items():
                if index >= flat_item_count:
                    # There's nowhere to put this comment.
                    continue

                item_addr = addr.add(index * item_len)
                self._restore_comments(listing=listing,
                                       addr=item_addr,
                                       comments=comments)

            return

        data = listing.getDataAt(addr)

        if data is not None:
            num_components = data.getNumComponents()

            for index, comments in component_comments.items():
                if index >= num_components:
                    # The new array is shorter than the old one, so
                    # there's nowhere to put this comment.
                    continue

                component = data.getComponent(index)

                if component is not None:
                    self._restore_comments_for_code_unit(component, comments)

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
                    from_addr,
                    to_addr,
                    ref_type,
                    src_type,
                    op_index,
                )

                if ref is not None and is_primary:
                    ref_mgr.setPrimary(ref, True)
            except Exception:
                # Something went wrong. This may be a duplicate or invalid
                # reference. Ignore it.
                pass


UpdateDataTypes().run()
