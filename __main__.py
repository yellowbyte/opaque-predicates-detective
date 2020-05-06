###
### Headless execution of OpaquePredicatesDetective
### ex1: python3 -m OpaquePredicatesDetective [binary]  -o [result file]
### ex2: python3 -m OpaquePredicatesDetective [binary]
###

import sys
import click

from OpaquePredicatesDetective import find_op_setup

from binaryninja import *


@click.command()
@click.argument("filepath")
@click.argument("stats_filepath", required=False)
@click.option("--output", "-o", is_flag=True, help="output to file")
def main(filepath, stats_filepath, output):
    """
    """
    bv = BinaryViewType.get_view_of_file(filepath)
    if bv is None:
        print("Couldn't open {}".format(filepath))
        sys.exit()

    if output:
        log_to_file(LogLevel.InfoLog, stats_filepath)
    else:
        log_to_stdout(LogLevel.InfoLog)

    find_op_setup(bv, status=None)


if __name__ == "__main__":
    main()
