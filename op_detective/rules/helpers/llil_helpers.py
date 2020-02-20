from operator import attrgetter
from collections import namedtuple

from binaryninja import *


class Tree(object):
    """AST Tree

    Args:
        llil_type (str): ex., LLIL_ADD, LLIL_IF
        llil_data (long): ex., for type long, store actual value
        childs (list): list of Tree objects
        indent (int): number of spaces to use when pretty-printing Tree object

    Attributes:
        llil_type (str): ex., LLIL_ADD, LLIL_IF
        llil_data (long): ex., for type long, store actual value
        childs (list): list of Tree objects
        _indent (int): number of spaces to use when pretty-printing Tree object
    """
    def __init__(self, llil_type=None, llil_data=None, childs=None, indent=2):
        self.llil_type = llil_type
        self.llil_data = llil_data
        self.childs = list()
        self._indent = indent
        if childs is not None:
            for child in childs:
                self.add_child(child)

    def add_child(self, node):
        """Add child to Tree object

        Args:
            node (Tree): child to be added
        """
        assert isinstance(node, Tree)
        self.childs.append(node)

    def traverse(self):
        """Pretty-print current Tree object
        """
        def traverse_helper(tree, level=0):
            log_debug(' ' * (level) + tree.llil_type)
            if tree.childs:
                for child in tree.childs:
                    traverse_helper(child, level + 1)

        traverse_helper(tree=self, level=self._indent)


def match_tree(potential_il_tree, og_il_tree):
    """Check if `potential_il_tree` is a subtree of `og_il_tree`.

    wrt. the following special cases:
        llil_type = 'X': free pass. Node can contain anything
        llil_type = 'F': fill in
                         if llil_type == 'long', fill in data to llil_data

    Args:
        potential_il_tree (Tree): self-constructed Tree
        og_il_tree (Tree): Tree created from llil2tree

    Returns:
        bool: True if `potential_il_tree` is a subtree of `og_il_tree`,
              else False.
    """
    # llil_type at respective tree node does not match
    if (potential_il_tree.llil_type != 'X'
            and potential_il_tree.llil_type != 'F') \
            and (potential_il_tree.llil_type != og_il_tree.llil_type):
        return False

    # special case: 'F'
    if potential_il_tree.llil_type == 'F':
        if og_il_tree.llil_type == 'long':
            potential_il_tree.llil_type = og_il_tree.llil_data
        else:
            potential_il_tree.llil_type = og_il_tree.llil_type

    # recurse: BFS
    for i, child in enumerate(potential_il_tree.childs):
        # special case: 'X'
        if child.llil_type == 'X':
            continue
        return True and match_tree(child, og_il_tree.childs[i])
    return True


def llil2tree(il, tree):
    """Create Tree object in `tree` from `il`.

    Args:
        il (LowLevelILInstruction): llil instruction object.
        tree (Tree): Tree object.

    Returns:
        None: output in arg `tree`.
    """
    # root
    if not tree.llil_type:
        tree.llil_type = get_llil_str(il)

    # recurse
    if isinstance(il, LowLevelILInstruction):
        il_ops = il.operands

        for child_il in il_ops:
            # create and add subtree
            cur_type = get_llil_str(child_il)
            if cur_type == 'long':
                cur_node = Tree(llil_type=cur_type, llil_data=child_il)
            else:
                cur_node = Tree(llil_type=cur_type)
            tree.add_child(cur_node)

        # recurse on all subtrees
        for i, tree_node in enumerate(tree.childs):
            # list is positional. works out
            llil2tree(il_ops[i], tree_node)


def contain_type(il, llil_type, val, temp=[]):
    """Check if LowLevelILInstruction `il` contains expression `il_type`
       of value `val`.

    ex: llil_type = LowLevelILInstruction. val = 'ILRegister'.
    ex: llil_type = ILRegister. val = 'eax'.
    ex: llil_type = long. val = 'long'.

    Args:
        il (LowLevelILInstruction): llil instruction object.
        llil_type
            (LowLevelILInstruction, ILRegister, long): objects that made up of
                                                       LowLevelILInstruction.
        val (str): objects that made up of LowLvelILInstruction in string.
        result (list): final output list containing objects of
                       type `llil_type`.

    Returns:
        bool: True if `il` contains expression `il_type` of value `val`,
              else False.
    """
    if isinstance(il, LowLevelILInstruction):
        temp.extend(il.operands)
    if isinstance(il, llil_type):
        if get_llil_str(il) == val:
            return True
    while temp:
        cur_il = temp.pop()
        return True and contain_type(cur_il, llil_type, val, temp)
    return False


def get_type(il, llil_type, val, result=[], method='__str__'):
    """Return list of `llil_type` that exists in `il` with `val`.

    ex: llil_type = LowLevelILInstruction. val = 'ILRegister'.
    ex: llil_type = ILRegister. val = 'eax'.
    ex: llil_type = long. val = 'long'.

    Args:
        il (LowLevelILInstruction): llil instruction object.
        llil_type
            (LowLevelILInstruction, ILRegister, long): objects that made up of
                                                       LowLevelILInstruction.
        val (str): objects that made up of LowLvelILInstruction in string.
        result (list): final output list containing objects of
                       type `llil_type`.

    Returns:
        None: result in arg `result`.
    """
    if isinstance(il, llil_type):
        if attrgetter(method)(il) == val:
            result.append(il)
    if isinstance(il, llil_type):
        for o in il.operands:
            get_type(o, llil_type, val, result=result, method=method)


def get_llil_str(il):
    """Retrieve corresponding string from llil object.

    Args:
        il (LowLevelILInstruction): llil instruction object.

    Returns:
        str: string representation for that llil object.
             (1) LowLevelILInstruction (string).
             (2) ILRegister (string).
             (3) builtin long (string).
    """
    if isinstance(il, LowLevelILInstruction):
        value = il.operation.name
    elif isinstance(il, ILRegister):
        value = str(il)
    else:
        value = 'long'  # else type long
    return value
