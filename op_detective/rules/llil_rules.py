from .helpers import contain_type, get_type, match_tree, llil2tree, Tree

from binaryninja.enums import LowLevelILOperation, RegisterValueType
from binaryninja.lowlevelil import (LowLevelILInstruction, ILRegister)
from binaryninja.log import log_debug


def stack_pointer_oddity(instr, bv, isa_specific_data):
    """
    (1) stack pointer should not be assigned a constant
    (2) in a memory operation (LLIL_LOAD), stack pointer should only be
        in LLIL_ADD or LLIL_SUB
    (3) usage of stack pointer should be in a memory access
    """
    log_debug("[stack_pointer_oddity]: entry "+hex(instr.address))

    # ignore stack pointer usages relating to function prologue/epilogue
    if not instr.function.get_medium_level_il_instruction_index(instr.instr_index):
        return False

    # ignore stack pointer operations for restoring stack frame
    if instr.il_basic_block[-1].operation.value in [57, 58]:
        return False

    # ignore instructions that are not completely lifted
    if instr.operation.name == 'LLIL_UNIMPL_MEM':
        return False

    stack_ptrs = list()
    if not isa_specific_data:
        stack_ptrs = isa_specific_data['stack_pointers']
    else:
        stack_ptrs.append(bv.arch.stack_pointer) 
    for stack_ptr in stack_ptrs:
        if not contain_type(instr, ILRegister, stack_ptr, temp=[]):
            continue
        log_debug("[stack_pointer_oddity]: contain_type({}, {}, {}) "
            .format(str(instr), str(ILRegister), str(stack_ptr)))
        log_debug("[stack_pointer_oddity]: contains stack_ptr "+str(stack_ptr))

        # check for memory access with stack pointer
        stack_semantics_add = list()
        stack_semantics_load = list()
        stack_semantics_store = list()
        get_type(instr, LowLevelILInstruction,
                 'LLIL_ADD', stack_semantics_add, 'operation.name')
        get_type(instr, LowLevelILInstruction,
                 'LLIL_STORE', stack_semantics_store, 'operation.name')
        get_type(instr, LowLevelILInstruction,
                 'LLIL_LOAD', stack_semantics_load, 'operation.name')
        log_debug("[stack_pointer_oddity]: stack semantics "+str(stack_semantics_add))
        if contain_type(instr, LowLevelILInstruction, 'LLIL_LOAD', temp=[]) or \
                contain_type(instr, LowLevelILInstruction, 'LLIL_STORE', temp=[]):
            # stack pointer used in memory access
            if (not any([il for il in stack_semantics_add if il.left.operation.name == 'LLIL_REG' and il.left.src.name == stack_ptr])) and \
                    (not any([il for il in stack_semantics_store if il.dest.operation.name == 'LLIL_REG' and il.dest.src.name == stack_ptr])) and \
                    (not any([il for il in stack_semantics_load if il.src.operation.name == 'LLIL_REG' and il.src.src.name == stack_ptr])):
                log_debug('[stack_pointer_oddity]: found(1)')
                return True
        # copying stack pointer value is fine
        elif (hasattr(instr, 'dest') and hasattr(instr, 'src') and hasattr(instr.src, 'src') and
                isinstance(instr.dest, ILRegister) and 
                instr.operation.name == 'LLIL_SET_REG' and 
                instr.src.operation.name == 'LLIL_REG' and 
                stack_ptr == instr.src.src.name):
            pass
        else:
            # adding or substracting stack offsets
            # have to take care of 'esp = esp + 4' or 'lea, [esp+0x38]'
            if not (hasattr(instr, 'dest') and hasattr(instr, 'src') and \
                    isinstance(instr.dest, ILRegister) and \
                    instr.src.operation.value in [22, 24] and \
                    stack_ptr in [str(i) for i in instr.src.tokens]):
                # the only other acceptable form: esp = esp + <const>
                # 22, 24 == LLIL_ADD, LLIL_SUB
                log_debug('[stack_pointer_oddity]: found(2) at :'+hex(instr.address))
                return True
    return False


def crazy_mem_offset(instr, bv):
    """
    """
    log_debug("[crazy_mem_offset]: entry "+hex(instr.address))
    # check dest for constant
    if instr.operation.name == 'LLIL_STORE_SSA':
        const_ils = list()
        get_type(instr.dest, LowLevelILInstruction, 'LLIL_CONST',
                 const_ils, 'operation.name')
        log_debug("[crazy_mem_offset]: "+str(const_ils))
        for c in const_ils:
            log_debug("[crazy_mem_offset]: const value "+str(c.value.value))
            if bv.is_offset_readable(c.value.value) or bv.is_offset_writable(c.value.value):
                log_debug("[crazy_mem_offset]: offset is a valid virtual address")
                continue
            # greater than a certain value and less than a certain value
            if c.constant > 0x100000 or c.constant < -0x100000:
                return True

    # check src for constant
    if not hasattr(instr, 'src'):
        return False
    load_ils = list()
    get_type(instr.src, LowLevelILInstruction,
             'LLIL_LOAD_SSA', load_ils, 'operation.name')

    for load_il in load_ils:
        const_ils = list()
        get_type(load_il, LowLevelILInstruction,
                 'LLIL_CONST', const_ils, 'operation.name')
        if not const_ils:
            continue
        for c in const_ils:
            if bv.is_offset_readable(c.value.value) or \
                    bv.is_offset_writable(c.value.value):
                log_debug("[crazy_mem_offset]: offset is a valid virtual address")
                continue
            # greater than a certain value and less than a certain value
            if c.constant > 0x100000 or c.constant < -0x100000:
                return True
    return False


def type_discrepency_ptr_in_mult_div(instr):
    """
    """
    log_debug("[type_discrepency_ptr_in_mult_div]: entry "+hex(instr.address))
    # check if it is multiply or division operation
    if instr.operation.name != 'LLIL_SET_REG':
        return False
    if instr.src.operation.value not in range(36, 43):
        # division and multiply values
        # LLIL_MUL, LLIL_MULU_DP, LLIL_MULS_DP, LLIL_DIVU
        # LLIL_DIVU_DP, LLIL_DIVS, LLIL_DIVS_DP
        return False

    # check if reg is also used as memory pointer
    # reg_oi: register of interest
    reg_oi = instr.ssa_form.dest
    if isinstance(reg_oi, ILRegister):
        return False
    log_debug("[type_discrepency_ptr_in_mult_div]: reg_io "+repr(reg_oi)+" at "+hex(instr.address))
    for reg_use_il in instr.function.get_ssa_reg_uses(reg_oi):
        # dereference in destination
        mem_dest_struct = Tree(
            llil_type='LLIL_STORE',
            childs=[Tree(llil_type='LLIL_REG', childs=[Tree(llil_type='F')])])
        # dereference in source
        mem_src_struct = Tree(
            llil_type='LLIL_LOAD',
            childs=[Tree(llil_type='LLIL_REG', childs=[Tree(llil_type='F')])])

        # check for dereference in destination
        llil_tree = Tree()
        llil2tree(reg_use_il, llil_tree)
        if ((match_tree(mem_dest_struct, llil_tree) and
                mem_dest_struct.childs[0].childs[0].llil_type == str(reg_oi.reg))):
            if reg_use_il.size == 1:
                # memory access size is same as counter size. So, it is okay
                return False
            return True

        # check for dereference in source
        if not hasattr(reg_use_il, 'src'):
            return False
        llil_tree = Tree()
        llil2tree(reg_use_il.src, llil_tree)
        if ( (match_tree(mem_src_struct, llil_tree) and
                mem_src_struct.childs[0].childs[0].llil_type == str(reg_oi.reg)) ):
            load_ils = list()
            get_type(reg_use_il.src, LowLevelILInstruction,
                     'LLIL_LOAD', load_ils, 'operation.name')
            for li in load_ils:
                if li.dest.reg == reg_oi.reg and li.size == 1:
                    return False
            return True
    return False


def jmp_dest_nonexist(instr, bv):
    """Check if jump destination is in mapped address space.

    Args:
        instr (LowLevelILInstruction): llil instruction object.
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        bool: True if jump destination is not in mapped address space,
              else False.
    """
    if not instr.dest.operation == LowLevelILOperation.LLIL_CONST_PTR:
        return False
    return not bv.is_offset_executable(instr.dest.value.value)


def memaccess_src_dest_discrepancy(instr, bv):
    """Check that memory access on an instruction level is authentic.

    (1) memory pointer not stored in register of correct size.
    (2) memory pointer value accessed in a register of smaller size.

    Args:
        instr (LowLevelILInstruction): llil instruction object.
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        bool: True if memory access is not authentic, else False.
    """
    llil_tree = Tree()
    llil2tree(instr, llil_tree)
    # create structure we want to match against `llil_tree`
    matching_struct = Tree(
        llil_type='LLIL_STORE',
        childs=[Tree(llil_type='LLIL_REG', childs=[Tree(llil_type='F')])])
    if not match_tree(matching_struct, llil_tree):
        return False

    dest_reg = matching_struct.childs[0].childs[0].llil_type
    if bv.arch.regs[dest_reg].full_width_reg != dest_reg:
        return True

    regs_in_il = list()
    get_type(instr, LowLevelILInstruction, 'ILRegister', result=regs_in_il)
    for reg in regs_in_il:
        reg_name = bv.arch.get_reg_name(reg.index)
        if bv.arch.regs[reg_name].size != bv.arch.address_size and \
                bv.arch.regs[reg_name].full_width_reg == dest_reg:
            return True
    return False


def memaccess_nonexist(instr, bv):
    """Check if instruction is accessing memory that does not exist.

    Args:
        instr (LowLevelILInstruction): llil instruction object.
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        bool: True if instruction is accessing nonexistent memory, else False.
    """
    if not contain_type(instr.dest, LowLevelILInstruction, 'LLIL_CONST_PTR', temp=[]):
        return False
    if instr.dest.value.type == RegisterValueType.UndeterminedValue:
        return False
    if contain_type(instr.dest, LowLevelILInstruction, 'LLIL_REG', temp=[]):
        return False
    if instr.dest.value.type == RegisterValueType.StackFrameOffset:
        return False
    if not bv.is_offset_writable(instr.dest.value.value):
        return True
    return False


def call_dest_nonexist(instr, bv):
    """Check if destination of CALL exists in address space.

    Args:
        instr (LowLevelILInstruction): llil instruction object.
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.

    Returns:
        bool: True if instruction is accessing nonexistent memory, else False.
    """
    if instr.dest.value.type == RegisterValueType.UndeterminedValue:
        return False
    if contain_type(instr, LowLevelILInstruction, 'LLIL_REG', temp=[]):
        return False
    if not bv.get_function_at(instr.dest.value.value):
        return True
    return False
