from .llil_helpers import *  # noqa: F401, F403
from .mlil_helpers import *  # noqa: F401, F403

from binaryninja import *


def instr_with_addr_in_bb(bb, addr):
    """

    Return list of instructions in `bb` that have the virtual address `addr`

    Args:
        bb: a BasicBlock object
        addr: virtual address

    Returns:
        list of instructions
    """
    shared_addr = list()
    log_debug('[instr_with_addr_in_bb]: bb type '+str(bb))
    for instr in bb:
        log_debug('[instr_with_addr_in_bb]: cur instr '+str(instr))
        if instr.address == addr:
            shared_addr.append(instr)
    return shared_addr
