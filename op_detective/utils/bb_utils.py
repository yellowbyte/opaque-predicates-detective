from binaryninja.log import log_debug  # noqa: F401


def get_last_bb_instr(bb):
    """Given BasicBlock `bb`, retrieve address of last instruction.
    `bb.end` gives you the address of the first byte after the current `bb`

    Args:
        bb (BasicBlock): the BasicBlock that you want the last instruction
                         address of.

    Returns:
        VA: VA of last instruction in long
    """
    return bb.start + (bb.length-bb[-1][-1])


def get_code_ref_bbs(bv, addr):
    """Given address `addr`, find all bb starts that references `addr`.

    Args:
        addr (int): VA.

    Returns:
        list: int list, where each int is a bb start address.
    """
    bbs_start = list()
    # `addr` does not have code references in disassembly
    if not bv.get_code_refs(addr):
        return list()

    for code_ref in bv.get_code_refs(addr):
        if not bv.get_functions_containing(code_ref.address):
            continue
        for func in bv.get_functions_containing(code_ref.address):
            # skip overlapped basic blocks
            if len(bv.get_basic_blocks_at(code_ref.address)) != 1:
                continue
            bbs_start.append(func.get_basic_block_at(code_ref.address).start)
    return bbs_start


def bb2ilbb(bb, il_type, bv):
    """Convert bb to specified il bb.

    We want to reason at the original basic block boundaries.
    There is no exposed BinaryNinja API to go from original basic
    block to `il_type` basic block. This function will allow us
    identify original basic block start the il instruction belongs to.

    An easier approach is to use `bv.get_basic_blocks_at(il.address)`,
    but for obfuscated code, overlapping instructions could cause the
    above code to return multiple basic blocks for a VA. In that case,
    we will have no idea which basic block the il instruction being
    analyzed belongs to.

    Args:
        bb (BasicBlock): original basic block object.
        il_type (str): 'llil' or 'mlil'.

    Returns:
        list: il instruction list.
    """
    il_bb = list()
    addr_list = list()
    cur_func = bb.function
    il_func = getattr(cur_func, il_type)

    # retrieve list of instruction addresses in og bb
    current_addr = bb.start
    for instr in bb:
        addr_list.append(current_addr)
        current_addr += instr[1]
    if current_addr != bb.end:
        addr_list.append(current_addr)

    # filter `addr_list` to addr that only exists in `il_type`
    # retrieves list of addresses @ specified il
    addr_list = [a for a in addr_list if il_func.get_instruction_start(a)]
    assert len(addr_list) != 0

    # retrieve il instructions that share the same addresses that exist in og
    # bb's instructions
    cur_il_i = il_func.get_instruction_start(addr_list[0])  # returns il index
    try:
        while True:
            if il_func[cur_il_i].address <= addr_list[-1]:
                if il_func[cur_il_i].address in addr_list:
                    il_bb.append(il_func[cur_il_i])
                cur_il_i += 1
            else:
                break
    except:
        return il_bb

    return il_bb
