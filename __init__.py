from op_detective import (bb_llil_analysis, bb_mlil_analysis, bb_analysis,
                                  get_authentic_bbs, get_non_generic_spec)

from op_helpers import *

from collections import namedtuple, defaultdict

from binaryninja import *


COMPILER = 'gcc'
AnalysisMetadata = namedtuple('AnalysisMetadata', 'compiler spec good_bbs')


def find_op_setup(bv, status=None):
    """
    Perform necessary setup before core analysis
    """
    # maybe binja will find more functions
    # same as following in GUI:
    #     Tools -> Run Analysis Module -> Linear Sweep
    bv.update_analysis_and_wait()

    log_to_stdout(LogLevel.DebugLog)
    log_to_file(LogLevel.DebugLog, '/home/yellowbyte/binja_log')
    metadata = AnalysisMetadata(compiler=COMPILER,
                                spec=get_non_generic_spec(),
                                good_bbs=get_authentic_bbs(bv))
    analysis = [
        bb_analysis,
        bb_mlil_analysis,
        bb_llil_analysis,
    ]

    (total_patch_locations, total_conds) = find_op(bv, analyses=analysis,
            metadata=metadata, status=status)

    log_debug("")
    log_debug("--- after pass of whole binary ---")
    log_debug("")

    # determine OP authenticity
    identify_authentic_op(total_patch_locations, total_conds, metadata, bv, patch=True)


class FindOpaqueInBackground(BackgroundTaskThread):
    def __init__(self, bv, msg):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv

    def run(self):
        find_op_setup(self.bv, self)


def find_opaque_in_background(bv):
    """Start `FindOpaqueInBackground`
    """
    background_task = FindOpaqueInBackground(bv, "Finding opaque predicates")
    background_task.start()


PluginCommand.register("Opaque Predicate Detective",
                       "find opaque predicate", find_opaque_in_background)
