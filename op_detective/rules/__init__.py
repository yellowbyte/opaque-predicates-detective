from __future__ import division

import toolz
import operator

from .llil_rules import *  # noqa: F403, F401
from .mlil_rules import *  # noqa: F403, F401
from binaryninja.log import log_debug  # noqa: F401

from ..utils import bb2ilbb


def prob_of_unimpl(bb, bv, isa_specific_data):
    """
    """
#    log_debug('[prob_of_unimpl]: enter '+hex(bb.start))
    if not isa_specific_data or not \
            isa_specific_data.get('common_unlifted_instructions'):
        # or else could lead to high FP rate
        return False

    ok_unlifted_instructions = isa_specific_data['common_unlifted_instructions']
    addr2ignore = list()
    cur_addr = bb.start
    for instr in bb:
#        log_debug('[prob_of_unimpl]: cur instr '+instr[0][0])
        if str(instr[0][0]) in ok_unlifted_instructions:
            addr2ignore.append(cur_addr)
        cur_addr += instr[1]

    unimpl = 0
    llil_bb = bb2ilbb(bb, 'llil', bv)

    for instr in llil_bb:
        if instr.address in addr2ignore:
            continue
        if instr.operation.value in [81, 82]:
            # 81, 82 = LLIL_UNIMPL, LLIL_UNIMPL_MEM
            unimpl += 1

#    log_debug('[prob_of_unimpl]: addr2ignore '+str(addr2ignore))
#    log_debug('[prob_of_unimpl]: va '+str(bb.instruction_count))
#    log_debug('[prob_of_unimpl]: unimpl '+str(unimpl))
    if unimpl and ((unimpl/bb.instruction_count) >= .2):
        return True
    return False


def bb_start_overlapped(bb, bv):
    """
    """
    bbs = bv.get_basic_blocks_at(bb.start)
    overlapped_bbs = list(toolz.unique(bbs, operator.attrgetter('start')))
    if len(overlapped_bbs) > 1:
        return True
    return False


def priviledged_instructions(instr, bv, isa_specific_data):
    """
    """
    if not isa_specific_data:
        return False
    if isa_specific_data and isa_specific_data.get('privileged_instructions'):
        if instr[0][0].text in isa_specific_data['privileged_instructions']:
            return True
    return False


def weird_cutoff(bb, bv):
    """
    """
#    log_debug('[weird_cuttoff]: enter '+hex(bb.start))

    mlil_bb = bb2ilbb(bb, 'mlil', bv)
    if not mlil_bb:
        return False
    if mlil_bb[-1].operation.name == 'MLIL_UNDEF':
        # disassembly is quick to self-repair
        return True

    # basic block neighbors data bytes
    # and does not end in control-transferring instruction
    if not bb.function.llil.get_instruction_start(bb.end):
        op_code = mlil_bb[-1].operation.value
        if op_code not in range(48, 59) and \
                op_code not in range(74, 76):
            return True
    return False
