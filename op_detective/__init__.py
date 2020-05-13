import os
import json

from .rules import *  # noqa: F403, F401

from .utils import *  # noqa: F403, F401

from binaryninja.enums import LowLevelILOperation
from binaryninja.log import log_debug  # noqa: F401


def get_non_generic_spec():
    """Return dictionary of non-generic specifications
       like (isa-specific, compiler-specific)

    Returns:
        dict: <look at non_generic_spec.json for layout>
    """
    # import non-generic readonly data
    path = os.path.join(os.path.dirname(__file__),
                        'non_generic_spec.json')
    with open(path, 'r') as f:
        non_generic_spec = json.load(f)

    assert non_generic_spec is not None
    return non_generic_spec


def bb_analysis(bv, bb, og_bb_start, metadata):
    """Check authenticity of `bb` based on instructions used.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.
        bb (BasicBlock): BinaryNinja.BasicBlock object.
        og_bb_start (long): address of where original basic block starts.
        isa_specific_data (dict): None or dictionary containing isa-specific
                                  info. Read in from
                                  "storage/non_generic_spec.json".

    Returns:
        bool: True if content of bb doesn't make sense. False if it's a legit.
    """
    # first bb's instruction; instr.address
    faulting_addr = og_bb_start

    # check if isa is supported. If not, do not run this analysis
    isa_specific_data = metadata.spec['isa'].get(bv.arch.name)

    # result
    alerted_rules = list()

    # rule: weird_cutoff
    if weird_cutoff(bb, bv):
        log_debug(('* weird_cutoff: ' + 'bb start( 0x{0:02X} ) ' +
                  'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                    faulting_addr))
        alerted_rules.append('weird_cutoff')

    # rule: prob_of_unimpl
    if prob_of_unimpl(bb, bv, isa_specific_data):
        log_debug(('* prob_of_unimpl: ' + 'bb start( 0x{0:02X} ) ' +
                  'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                    faulting_addr))
        alerted_rules.append('prob_of_unimpl')

    for instr in bb:

        # rule: priviledged_instructions
        if priviledged_instructions(instr, bv, isa_specific_data):
            log_debug(
                ('* priviledged_instructions: ' + 'bb start( 0x{0:02X} ) ' +
                 'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                   faulting_addr))
            alerted_rules.append('priviledged_instructions')

    return alerted_rules


def bb_mlil_analysis(bv, bb, og_bb_start, metadata):
    """Check authenticity of instructions in MLIL.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.
        bb (list): list of MLIL instructions.
        og_bb_start (long): address of where original basic block starts.
        isa_specific_data (dict): None or dictionary containing isa-specific
                                  info. Read in from
                                  "storage/non_generic_spec.json".

    Returns:
        bool: True if content of bb doesn't make sense. False if it's a legit.
    """
    bb = bb2ilbb(bb, 'mlil', bv)
    if not bb:
        return False

    # first bb's instruction; instr.address
    faulting_addr = og_bb_start

    # check if isa is supported. If not, do not run this analysis
    isa_specific_data = metadata.spec['isa'].get(bv.arch.name)

    # result
    alerted_rules = list()

#    # rule: def_no_use_dep
#    if def_no_use_dep(bb, bv, isa_specific_data):
#        log_debug(
#            ('* def_no_use_dep: ' + 'bb start( 0x{0:02X} ) ' +
#             'instr addr( 0x{1:02X} )').format(faulting_addr,
#                                               faulting_addr))
#        alerted_rules.append('def_no_use_dep')

    for instr in bb:

        if instr.operation.name == 'MLIL_STORE':

            # rule: memaccess_self
            if memaccess_self(instr.ssa_form):
                log_debug(
                    ('* memaccess_self: ' + 'bb start( 0x{0:02X} ) ' +
                     'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                       instr.address))
                alerted_rules.append('memaccess_self')

#        # rule: conditional_unused
#        if conditional_unused(instr):
#            log_debug(
#                ('* conditional_unused: ' + 'bb start( 0x{0:02X} ) ' +
#                 'instr addr( 0x{1:02X} )').format(faulting_addr,
#                                                   instr.address))
#            alerted_rules.append('conditional_unused')

    return alerted_rules


def bb_llil_analysis(bv, bb, og_bb_start, metadata):
    """Check authenticity of instructions in LLIL.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.
        bb (list): list of LLIL instructions.
        og_bb_start (long): address of where original basic block starts.

    Returns:
        bool: True if content of bb doesn't make sense. False if it's a legit.
    """
    bb = bb2ilbb(bb, 'llil', bv)
    if not bb:
        return False

    isa_specific_data = metadata.spec['isa'].get(bv.arch.name)

    # first bb's instruction; instr.address
    faulting_addr = og_bb_start

    # result
    alerted_rules = list()

    for instr in bb:

        # rule: stack_pointer_oddity
        if stack_pointer_oddity(instr, bv, isa_specific_data):
            log_debug(
                ('* stack_pointer_oddity: ' + 'bb start( 0x{0:02X} ) ' +
                 'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                   instr.address))
            alerted_rules.append('stack_pointer_oddity')

        # rule: crazy_mem_offset
        if crazy_mem_offset(instr.ssa_form, bv):
            log_debug(
                ('* crazy_mem_offset: ' + 'bb start( 0x{0:02X} ) ' +
                 'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                   instr.address))
            alerted_rules.append('crazy_mem_offset')

        # rule: type_discrepency_ptr_in_mult_div
        if type_discrepency_ptr_in_mult_div(instr):
            log_debug(
                ('* type_discrepency_ptr_in_mult_div: ' + 'bb start( 0x{0:02X} ) ' +
                 'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                   instr.address))
            alerted_rules.append('type_discrepency_ptr_in_mult_div')

        if instr.operation == LowLevelILOperation.LLIL_STORE:

            # rule: memaccess_nonexist
            if memaccess_nonexist(instr, bv):
                log_debug(
                    ('* memaccess_nonexist: ' + 'bb start( 0x{0:02X} ) ' +
                     'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                       instr.address))
                alerted_rules.append('memaccess_nonexist')

            # rule: memaccess_src_dest_discrepancy
            if memaccess_src_dest_discrepancy(instr, bv):
                log_debug(
                    ('* memaccess_src_dest_discrepancy: ' +
                     'bb start( 0x{0:02X} ) ' +
                     'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                       instr.address))
                alerted_rules.append('memaccess_src_dest_discrepancy')

        if instr.operation == LowLevelILOperation.LLIL_CALL:

            # rule: call_dest_nonexist
            if call_dest_nonexist(instr, bv):
                log_debug(
                    ('* call_dest_nonexist: ' + 'bb start( 0x{0:02X} ) ' +
                     'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                       instr.address))
                alerted_rules.append('call_dest_nonexist')

        # rule: jmp_dest_nonexist
        if instr.operation == LowLevelILOperation.LLIL_JUMP:
            if jmp_dest_nonexist(instr, bv):
                log_debug(
                    ('* jmp_dest_nonexist: ' + 'bb start( 0x{0:02X} ) ' +
                     'instr addr( 0x{1:02X} )').format(faulting_addr,
                                                       instr.address))
                alerted_rules.append('jmp_dest_nonexist')
    return alerted_rules
