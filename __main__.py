import sys

from OpaquePredicatesDetective import find_op_setup

from binaryninja import *


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("requires 2 arguments of this form:\n\t"
              "python OpaquePredicatesDetective [binary] [result file]")
        sys.exit()
    filepath = sys.argv[1]
    stats_filepath = sys.argv[2]

    bv = BinaryViewType.get_view_of_file(filepath)
    if bv is None:
        print("Couldn't open {}".format(filepath))
        sys.exit()

    log_to_file(LogLevel.InfoLog, stats_filepath)
    find_op_setup(bv, status=None)
