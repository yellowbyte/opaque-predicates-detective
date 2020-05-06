from .op_detective import get_last_bb_instr

from collections import namedtuple

from binaryninja import *


OpaquePredicateInfo = namedtuple('OpaquePredicateInfo', 'if_addr bb_edge rules')


def patch_op(patches, total_conds, bv):
    """
    """
    for patch in patches:
        # final filter: check if OP basic block still at beginning of a basic block
        # if not, it is not the original OP
        if not patch.bb_edge.target.function.get_basic_block_at \
                (patch.bb_edge.target.start):
            continue
        if patch.bb_edge.target.function.get_basic_block_at \
                (patch.bb_edge.target.start).start != patch.bb_edge.target.start:
            continue

        log_debug('[authentic op]: 0x{0:02X}'.format(patch.bb_edge.target.start))
        log_info('0x{0:02X}:{1}'.format(patch.bb_edge.target.start, list(set(patch.rules))))
    log_info('@total_conds:'+str(total_conds))


def identify_authentic_op(total_patch_locations, total_conds, metadata, bv, patch=True):
    """
    Future Work.
    """
    patch_op(total_patch_locations, total_conds, bv)
 

def find_op(bv, analyses=list(), metadata=None, status=None):
    """Analysis main().

    Retrieve each basic block from binary and pass each to respective basic
    block analysis: `bb_analysis`, `bb_mlil_analysis`, and `bb_llil_analysis`.

    Args:
        bv (BinaryView): top-level binary view handler. Lots of
                         interesting methods can be accessed.
        status (FindOpaqueInBackground): plugin main.

    Returns:
        None: each analysis will log their respective findings.
    """
    cur_pass_patch_locations = list()
    seen_bbs = set()
    total_conds_seen = 0

    for func in bv.functions:

        for bb in func.basic_blocks:

            # bb does not end with JCC, so ignore
            if len(bb.outgoing_edges) != 2:
                continue

            # evaluate both branches
            # (does not differentiate between True/False branch)
            # but for our purpose, we don't need to
            if bb in seen_bbs:
                continue

            total_conds_seen += 1 
            for branch in bb.outgoing_edges:

                # bb has multiple incoming edges, so ignore
                if len(branch.target.incoming_edges) != 1:
                    continue

                # ignore authentic bb
                if branch.target.start in metadata.good_bbs:
                    continue

                # core analysis
                alerted_rules_in_bb = list()
                last_instr_addr = get_last_bb_instr(bb)  # if_addr

                for analysis in analyses:
                    analysis_result = analysis(bv, branch.target, 
                                               branch.target.start, metadata)
                    if analysis_result:
                        alerted_rules_in_bb.extend(analysis_result)

                if alerted_rules_in_bb:  # list not empty
                    # format: (OP addr, binja branch object, rule list)
                    cur_pass_patch_locations.append(
                        OpaquePredicateInfo(last_instr_addr, branch,
                                            alerted_rules_in_bb)
                    )
            seen_bbs.add(bb)
    return (cur_pass_patch_locations, total_conds_seen)
