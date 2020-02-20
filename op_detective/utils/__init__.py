from bb_utils import (bb2ilbb, get_code_ref_bbs, get_last_bb_instr)

from collections import defaultdict

from binaryninja.log import log_debug  # noqa: F401


def get_symbols(bv):
    """Return all symbols in binary.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        list: list of symbols in binary.
    """
    total_symbols = list()
    for s in bv.symbols.values():
        if isinstance(s, list):
            total_symbols.extend(s)
        else:
            total_symbols.append(s)
    return total_symbols


def get_authentic_bbs(bv):
    """Return set of bbs that we are confident are authentic.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        set: int set, where each int is a bb start address.
    """
    good_bbs = list()

    total_symbols = get_symbols(bv)
    # filter symbols to those that can be referenced in code
    total_symbols = [
        s for s in total_symbols if s.type.name in
        ['ImportedFunctionSymbol', 'FunctionSymbol', 'DataSymbol']
    ]

    # code refs from strings
    for s in bv.strings:
        good_bbs.extend(get_code_ref_bbs(bv, s.start))

    # code refs from symbols
    for sym in total_symbols:
        good_bbs.extend(get_code_ref_bbs(bv, sym.address))

    # filter out duplicate bb
    return set(good_bbs)
