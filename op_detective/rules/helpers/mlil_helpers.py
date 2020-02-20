from binaryninja import *


def is_instr_set_flag(instr):
    """
    """
    # semantic model of a flag
    if not isinstance(instr.dest, SSAVariable):
        return False
    # checking for semantic model of a flag
    ssa_var = instr.dest
    var_name = ssa_var.var.name.split('#')[0]
    if '_' in var_name:
        var_name = var_name.split('_')[0]

    for possible_var in instr.vars_read:
        if hasattr(possible_var, 'var'):
            if possible_var.var.name.startswith(var_name):
                prev_var_ver = possible_var
                break
    else:
        return False
    usages = instr.function.get_ssa_var_uses(prev_var_ver)

    # usage in `instr` and to assign a temp var
    if not any([u for u in usages if u.address == instr.address]):
        return False

    for u in usages:
        if u.address != instr.address:
            continue
        if hasattr(u, 'dest') and isinstance(u.dest, SSAVariable) and \
                u.dest.var.name.startswith('temp'):
            return True

    return False


def is_reg_reassigned_in_bb(cur_func, cur_index, reg_value):
#    log_debug('[is_reg_reassigned_in_bb]: enter '+str(cur_func))
    cur_instr = cur_func.ssa_form[cur_index]
    # instr at index is not
    # last instr of bb
    while (cur_instr.operation.value not in
            [58, 57, 48, 49, 50, 55, 74, 75, 56]):
        # check if current instruction is an assignment to `reg_value`
        # and is not a PHI operation
        if cur_instr.operation.name == 'MLIL_SET_VAR_SSA' and \
                isinstance(cur_instr.dest, SSAVariable):
            if cur_instr.dest.var.source_type.value == 1 and \
                    cur_instr.dest.var.storage == reg_value:
                # reg is used again
                return True
        cur_index += 1
#        log_debug('[is_reg_reassigned_in_bb]: cur_index '+str(cur_index)+' '+'cur_func: '+str(cur_func))
        try:
            cur_instr = cur_func.ssa_form[cur_index]
        except:
            return False
    return False


def is_reg_no_longer_used(ssa_var, instr):
    """Return if it is final variable version used in function that is not part of
    a PHI operation
    """
    # not live. But is it the final used version?
    # NOTE: need to be llil since we do not care
    # about var memory version
    # loop through each basic block
    # check version of register at end
    # if version is greater, check usages
    # if just PHI operation, ignore
    # else, it is not live
    # NOTE: subsequent usage do not always increment version by 1
    if ssa_var.var.source_type.value != 1: # make sure it is RegisterVariableSourceType
        return False
    reg_value = ssa_var.var.storage
    cur_index = instr.instr_index + 1
    cur_func = instr.function
    cur_bb = instr.il_basic_block
    analysis_queue = list()
    seen = set()

    if is_reg_reassigned_in_bb(cur_func, cur_index, reg_value):
        return False
    analysis_queue.extend(cur_bb.outgoing_edges)
    seen.add(cur_bb)

    while len(analysis_queue) != 0:
        cur_bb = analysis_queue.pop(0).target
        cur_index = cur_bb[0].instr_index
        if is_reg_reassigned_in_bb(cur_func, cur_index, reg_value):
            return False

        if cur_bb.outgoing_edges and cur_bb not in seen:
            analysis_queue.extend(cur_bb.outgoing_edges)
            seen.add(cur_bb)
    return True
