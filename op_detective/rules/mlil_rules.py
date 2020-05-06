from __future__ import division

from .helpers import (is_instr_set_flag,
                     is_reg_no_longer_used,
                     instr_with_addr_in_bb)

from .llil_rules import call_dest_nonexist

from binaryninja import *
from binaryninja.log import log_debug  # noqa: F401


def is_not_final_rv(var, instr):
    if instr.function.is_ssa_var_live(var):
        return False

    # return value will not have usage, but make sure it is the final version
    # instructions returned from `get_ssa_var_uses` is only the il of the og 
    # instruction at the address it will not include PHI operation. We can use 
    # this to simulate `is_ssa_var_live`, which we cannot use since there is no 
    # way to differentiate final version of return value
    if hasattr(var, 'var'):
        if not is_reg_no_longer_used(var, instr):
            return True
    return False


def conv2s32(n):
    return ((n & 0xffffffff) ^ 0x80000000) - 0x80000000


def def_no_use_dep(bb, bv, isa_specific_data):
    """Check if register (except return value) assigned value but not used.

    Args:
        instr (MediumLevelILInstruction): mlil instruction object.
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.
        isa_specific_data (dict): None or dictionary containing isa-specific
                                  info. Read in from
                                  "storage/non_generic_spec.json"

    Returns:
        bool: True if register assigned value but not used, else False.
    """
    log_debug("enter def_no_use_dep: "+hex(bb[0].address))

    # Early Exit
    # skip analysis if basic block contains unimplemented instructions
    # unimplemented can be the source for why variable usage is not found
    if any([i for i in bb if i.operation.value in [81, 82]]):
        # 81, 82 == 'MLIL_UNIMPL', 'MLIL_UNIMPL_MEM'
        return False

    # Early Exit
    # if no outgoing edges or ret instruction/tail call,
    # ignore bb for analysis
    if bb[-1].operation.value in [50, 55, 74, 75, 56]:
        return False
    if len(bb[-1].il_basic_block.outgoing_edges) == 0:
        return False

    # Special Exception
    # (1) some native instructions can be splitted into multiple instructions
    #     in a different BinaryNinja il
    # (2) keep track of last function call in basic block to ignore later
    #     since sometimes binja does not correctly identify function parameter,
    #     leading to FP
    # (3) some instructions are incorrectly lifted. Keep basic blocks containing
    #     those instructions
    addrs_to_skip = list()
    incorrectly_lifted = isa_specific_data.get('incorrectly_lifted_instructions')
    if not incorrectly_lifted:
        incorrectly_lifted = list()
    for instr in bb:

        # Early Exit
        # check for incorrectly lifted instructions
        native_instr = bv.get_disassembly(instr.address)
        if native_instr:
            for i in incorrectly_lifted:
                if native_instr.startswith(i):
                    return False

        instr = instr.ssa_form
        # assignment to multiple variables. Some will prob not be used
        # ex: IMUL where dividend is put in edx and leftover is put in eax
        #     and sometimes leftover is never looked at
        if instr.operation.name == 'MLIL_SET_VAR_SPLIT_SSA':
            addrs_to_skip.append(instr.address)

        # skip instruction where its source contains
        # MLIL_VAR_SPLIT_SSA variable
        if hasattr(instr, 'src') and  \
                hasattr(instr.src, 'prefix_operands') and  \
                MediumLevelILOperation.MLIL_VAR_SPLIT_SSA in instr.src.prefix_operands:
            addrs_to_skip.append(instr.address)

        if hasattr(instr, 'operation') and \
                instr.operation.value in [51, 53, 122, 54, 121, 115, 52, 116]:
            if not call_dest_nonexist(instr.llil.non_ssa_form, bv):
                # authentic CALL instruction exists
                # push and pop is common before or after function call
                return False

    for instr in bb:
        # changed to ssa form
        instr = instr.ssa_form
        log_debug('[def_no_use_dep]: current instr: '+str(instr))

        if instr.address in addrs_to_skip:
            continue

        # no data written
        if not instr.vars_written:
            continue

        # ignore check for callee's return value
        if instr.operation.name == 'MLIL_CALL_SSA':
            # return value from subroutine may not always be used
            continue

        # for variable involved in PUSH/POP, check if src variable is used
        # the destination of POP instruction will naturally not be live
        if instr.operation.name == 'MLIL_SET_VAR_ALIASED' and instr.src.operation.name == 'MLIL_ADDRESS_OF' and \
                len(instr.vars_read) == 1:
            # authentic stack access because it is aliased
            continue
        if (instr.operation.name == 'MLIL_SET_VAR_SSA' or instr.operation.name == 'MLIL_SET_VAR_ALIASED') and \
                (instr.src.operation.name == 'MLIL_VAR_SSA' or instr.src.operation.name == 'MLIL_LOAD_SSA') and \
                len(instr.vars_read) == 1:
            log_debug('[def_no_use_dep]: possible PUSH/POP')
            # POP semantic
            if (not instr.function.is_ssa_var_live(instr.dest)) and len(instr.vars_read) == 1 and instr.src.operation.name == 'MLIL_LOAD_SSA':
                log_debug('[def_no_use_dep]: filter usages list')
                usages = instr.function.get_ssa_var_uses(instr.vars_read[0])
                usages_wo_phi = list()
                log_debug('[def_no_use_dep]: usages: '+str(usages))
                log_debug('[def_no_use_dep]: first usage: '+str(usages[0].operation.name))
                for u in usages:
                    if u.operation.name != 'MLIL_VAR_PHI':
                        usages_wo_phi.append(u)
                log_debug('[def_no_use_dep]: usages_wo_phi: '+str(usages_wo_phi))
                if len(set([i.address for i in usages_wo_phi])) == 1:
                    log_debug('[def_no_use_dep]: (mlil) POP not live '+hex(instr.address))
                    return True
            # PUSH semantic (catch PUSHAD, PUSHFD)
            # catching only PUSH is hard since sometimes push for function arg is not recognized
            if (not instr.function.is_ssa_var_live(instr.dest)) and \
                    len(instr.vars_read) == 1 and \
                    instr.dest.var.name.startswith('var'):
                # PUSH looks just like stack access. Catch PUSHAD/PUSHFD
                same_va_instrs = instr_with_addr_in_bb(bb, instr.address)
                same_va_instrs_push_semantics = True 
                log_debug('[def_no_use_dep]: same_va_instrs '+str(same_va_instrs))
                for i in same_va_instrs:
                    if (len(i.vars_read) != 1) or (not i.dest.name.startswith('var')):
                        same_va_instrs_push_semantics = False
                if same_va_instrs_push_semantics and len(same_va_instrs) > 1:
                    log_debug('[def_no_use_dep]: (mlil) PUSH not live '+hex(instr.address))
                    return True
            # current PUSH/POP instruction looks good. Next!
            continue

        ### CHECK VARIABLE LIVENESS ###
        # for each var that is overwritten, check if it is live
        if isa_specific_data and isa_specific_data.get('return_values'):
            rvs = isa_specific_data['return_values']
        else:
            rvs = instr.function.source_function.return_regs
        assert len(rvs) == 1
        rv = rvs[0]
        for var in instr.vars_written:
            log_debug('[def_no_use_dep]: (mlil) current var '+str(var))

            # setting var to 0 or 1 or -1 or small constant for no good reason seems to be
            # a thing. Bad compiler optimization? As a result, ignore
            # instruction that simply set rv to 9 (e.g. xor eax, eax)
            if isinstance(instr.dest, SSAVariable):
                if hasattr(instr.src, 'value') and \
                        hasattr(instr.src.value, 'value'):
                    if instr.src.value.is_constant:
                        const_value = conv2s32(instr.src.value.value)
                        log_debug('[def_no_use_dep]: current const value '+hex(const_value))   
                        if const_value >= -1 and const_value <= 100:
                            log_debug('[def_no_use_dep]: (mlil) current var skipped at setting const')
                            continue

            # stack variables heuristics
            if var.var.name.startswith('var'):
                stack_vars = instr.function.source_function.get_stack_vars_referenced_by(instr.address)
                # filter to stack offset with ebp/esp
                # ex: [<ref to var_ac>, <operand 0 ref to var_88>]
                # first is a var to pushed arg and second is a var to ebp offset
                stack_vars = [sv for sv in stack_vars if sv.source_operand is not None]
                if any([sv for sv in stack_vars if sv.var.name == var.var.name]):
                    log_debug('[def_no_use_dep]: (mlil) current var skipped at stack variables heuristics')
                    continue

            # (1) stuff written to stack pointer logically might not be used again
            # (2) binja has mis-identified function as not taking any parameter when in fact it does, leading to
            #     FP 'def_no_use_dep'  rule
            # (3) instruction is not live but used to set flag(s). If so, ignore
            log_debug('[def_no_use_dep] liveness: '+str(instr.function.is_ssa_var_live(var))+' for '+str(var)+' at '+hex(instr.address))
            if not var.var.name.startswith(rv):
                if not instr.function.is_ssa_var_live(var) and not \
                        var.var.name.startswith(
                        bv.arch.stack_pointer) and \
                        not is_instr_set_flag(instr): # and \
                    if var.var.name.startswith('arg'):
                        continue
                    elif var.var.name.startswith('var'):
                        log_debug('[def_no_use_dep]: found(1) '+str(var)+' '+hex(instr.address)+' '+hex(instr.il_basic_block[0].address))
                        return True
                    else: 
                        if is_not_final_rv(var, instr):
                            log_debug('[def_no_use_dep]: found(2) '+str(var)+' '+hex(instr.address)+' '+hex(instr.il_basic_block[0].address))
                            return True
            else:  # return value heuristic
                if not instr.function.is_ssa_var_live(var) and \
                        is_not_final_rv(var, instr) and \
                        not is_instr_set_flag(instr):
                    log_debug('[def_no_use_dep]: found(3) '+str(var)+' '+hex(instr.address)+' '+hex(instr.il_basic_block[0].address))
                    return True
    log_debug('[def_no_use_dep]: did not alert def_no_use_dep')
    return False


def memaccess_self(instr):
    """Check if register used as pointer but also stored its ptr address to itself.

    Args:
        instr (MediumLevelILInstruction): mlil instruction object.

    Returns:
        bool: True if register used as pointer but also stored its ptr address
              to itself, else False.
    """
    log_debug("enter memaccess_self: "+hex(instr.address))
    # get vars read at destination
    # get vars used in memory access
    dest_vars_read = [
        i.var.name for i in instr.dest.vars_read if hasattr(i, 'var')
    ]
    if not dest_vars_read:
        return False
    log_debug("[memaccess_self] dest_vars_read: "+str(dest_vars_read))

    # get vars read at src that is not part of memory load
    # vars in src operands that are not a part of memory load!
    src_vars_read = list()
    # (1) check if it is a mov instruction for a subregister
    if instr.src.operation.name in ['MLIL_CONST', 'MLIL_VAR_SSA', 'MLIL_VAR_SSA_FIELD']:
        if instr.src.operation.name == 'MLIL_VAR_SSA_FIELD':
            src_vars_read.append(instr.src.src)
    # (2) heuristic for all other instructions
    else:
        for operand in instr.src.operands:
            if isinstance(operand, MediumLevelILInstruction):
                if operand.operation.name == 'MLIL_LOAD_SSA':
                    # skip if vars is inside memory access
                    continue
                for i in operand.vars_read:
                    if hasattr(i, 'var'):
                        src_vars_read.append(i.var.name)
            else:  # SSAVariable object
                if hasattr(operand, 'var'):
                    src_vars_read.append(operand.var.name)

    log_debug("[memaccess_self] src_vars_read: "+str(src_vars_read))
    for src_var in src_vars_read:
        if src_var in dest_vars_read:
            return True
    return False


def conditional_unused(instr):
    """Check if conditional flags are set but no usage

    Args:
        instr (MediumLevelILInstruction): mlil instruction object.

    Returns:
        bool: True if conditional flags are set but not used else False.
    """
    log_debug("enter conditional_unused: "+hex(instr.address))

    # link to macro:
    # https://api.binary.ninja/_modules/binaryninja/enums.html#MediumLevelILOperation  # noqa: E501
    if instr.operation.value == 8:  # MLIL_VAR, just a single variable and no assignment
        # ex: test instruction without usage
        # ignore if it is part of bool operation for a JCC instruction
        cur_i = instr.instr_index + 1
        while instr.function[cur_i].address == instr.address:
            # native instruction can be broken down into multiple il instructions
            # if it is broken down, they will still share same VA
            if hasattr(instr.function[cur_i], 'dest') and  \
                    hasattr(instr.function[cur_i].dest, 'type') and  \
                    str(instr.function[cur_i].dest.type) == 'bool':
                return False
            cur_i += 1
        return True

    # check if top level operation is mathematical operations. Should not be
    if instr.operation.value in range(18, 45) or instr.operation.value in range(83, 90):
        # ignore if it is part of bool operation for a JCC instruction
        cur_i = instr.instr_index

        try:
            while instr.function[cur_i].address == instr.address:
                # native instruction can be broken down into multiple il instructions
                # if it is broken down, they will still share same VA
                if hasattr(instr.function[cur_i], 'dest') and  \
                        hasattr(instr.function[cur_i].dest, 'type') and  \
                        str(instr.function[cur_i].dest.type) == 'bool':
                    return False
                cur_i += 1
        except:
            # make sure original instruction index has corresponding instruction
            # if not return True
            pass

        return True
    return False
