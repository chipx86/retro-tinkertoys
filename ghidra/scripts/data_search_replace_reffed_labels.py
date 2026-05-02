# Search/replace text in the references in the selection.
#
# This will take a selected range of code, ask for the text to search for
# and to replace it with, and then update the names of any referencs found
# in that selection accordingly.
#
# The text can be matched in case-sensitive or case-insensitive form.
#
# A dry-run can be performed, showing what renames would be performed,
# which can help with testing the results of the search/replace without
# risking anything beind modified.
#
# This all occurs in a transaction, so it's easy to undo.
#
# Copyright (C) 2025 Christian Hammond.
#
# Licensed under the MIT license.


#@author Christian Hammond (ChipX86)
#@menupath Tools.Data - Search/Replace Reffed Labels
#@category Retro Tinkertoys


from __future__ import unicode_literals

import re

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import InvalidInputException
from java.lang import RuntimeException


class SearchReplaceReffedLabels(GhidraScript):
    """Search/replace text in the references in the selection.

    This will take a selected range of code, ask for the text to search for
    and to replace it with, and then update the names of any referencs found
    in that selection accordingly.

    The text can be matched in case-sensitive or case-insensitive form.

    A dry-run can be performed, showing what renames would be performed,
    which can help with testing the results of the search/replace without
    risking anything beind modified.

    This all occurs in a transaction, so it's easy to undo.
    """

    def run(self):  # type: (...) -> None
        """Run the script.

        This will ask for the text to seach, replace, and the flags for the
        run. It will then walk through the selection and handle renaming any
        references.
        """
        program = currentProgram
        sel = currentSelection

        if sel is None or sel.isEmpty():
            raise RuntimeException('No selection was made.')

        search = askString(
            'Search',
            'Text to search for in referenced label names:',
        )
        replace = askString(
            'Replace',
            'Replacement text:',
        )
        case_sensitive = askYesNo(
            'Case Sensitive?',
            'Perform a case-sensitive match? Text will have to match exactly.',
        )

        dry_run = askYesNo(
            'Dry Run?',
            "Perform a dry run? This will show what would change, but won't "
            "modify any names.",
        )

        # Generate the normalized search text we'll compare against.
        if case_sensitive:
            norm_search = search
        else:
            norm_search = search.lower()

        listing = program.getListing()
        symbol_table = program.getSymbolTable()

        renamed = 0
        skipped = 0
        seen_symbols = set()  # type: set[int]

        transaction = program.startTransaction(
            'Searching/replacing referenced label names',
        )

        try:
            code_unit_iter = listing.getCodeUnits(sel, True)

            while code_unit_iter.hasNext() and not monitor.isCancelled():
                code_unit = code_unit_iter.next()

                # Retrieve all references from this code unit.
                refs = code_unit.getReferencesFrom() or []

                # Loop through any references found.
                for ref in refs:
                    if monitor.isCancelled():
                        break

                    # Check the address this reference points to.
                    to_addr = ref.getToAddress()

                    if to_addr is None:
                        # None found, so bail.
                        continue

                    # Check the primary symbol at that address.
                    symbol = symbol_table.getPrimarySymbol(to_addr)

                    if symbol is None:
                        # None found, so bail.
                        continue

                    # Check if this is a label that's easily user-controllable.
                    if symbol.isExternal():
                        continue

                    # Avoid doing the same symbol multiple times.
                    symbol_id = symbol.getID()

                    if symbol_id in seen_symbols:
                        # This has already been processed, so skip it.
                        continue

                    seen_symbols.add(symbol_id)

                    old_name = symbol.getName()

                    if old_name is None:
                        # This symbol didn't have a name, so we should skip
                        # it.
                        continue

                    # Check if it's a match for what the user provided.
                    if case_sensitive:
                        norm_old_name = old_name
                    else:
                        norm_old_name = old_name.lower()

                    if norm_search not in norm_old_name:
                        # This wasn't found in the name, so skip.
                        continue

                    # Replace the searched text with the replacement.
                    if case_sensitive:
                        # This is case-sensitive, so we can just do a simple
                        # replace.
                        new_name = old_name.replace(search, replace)
                    else:
                        # This is a case-insensitive replacement.
                        new_name = re.sub(
                            re.escape(search),
                            replace,
                            old_name,
                            flags=re.IGNORECASE,
                        )

                    if new_name == old_name:
                        # The name hasn't changed. Skip it but track it.
                        skipped += 1
                        continue

                    # Check if the new name already exists at the target
                    # address. If so, we can skip it.
                    found = False

                    for s in symbol_table.getSymbols(to_addr):
                        if s.getName() == new_name:
                            found = True
                            break

                    if found:
                        println('[%s] Skipping %r. New name %r already exists.'
                                % (to_addr, old_name, new_name))
                        skipped += 1
                        continue

                    println('[%s] Renaming %r -> %r'
                            % (to_addr, old_name, new_name))

                    if not dry_run:
                        try:
                            symbol.setName(new_name, SourceType.USER_DEFINED)
                            renamed += 1
                        except InvalidInputException as e:
                            println('[%s] Skipping %r -> %r. The name is '
                                    'invalid.'
                                    % (to_addr, old_name, new_name))
                            skipped += 1

            if dry_run:
                println('\nDry run complete.')

            println('\nDone. Renamed %s; skipped %s' % (renamed, skipped))
        finally:
            program.endTransaction(transaction, True)


# Run the script.
SearchReplaceReffedLabels().run()
