# <p align='center'> Opaque Predicates Detective </p>

![OP Detective](op_detective.png)

## Introduction: 
Previous approaches to generically identify opaque predicates work by identifying if a conditional branch contains an invariant expression. Our approach generically identify opaque predicates from a different perspective: __the damage caused by the obfuscation__. The damage is localized at the basic block level (or at the function level) regardless of how an opaque predicate's invariant expression is constructed. This approach allows us to also detect an opaque predicate whose invariant expression is constructed across multiple processes! 

IDA also detects opaque predicates from the damage but its approach cannot identify the exact superfluous branch, [which allows for the creation of stealthier opaque predicates](https://github.com/yellowbyte/analysis-of-anti-analysis/blob/develop/research/the_return_of_disassembly_desynchronization/the_return_of_disassembly_desynchronization.md).

There are two main types of damage resulting from opaque predicates: code bloat or disassembly desynchronization. __Current implementation focuses on detecting opaque predicates when the damage is disassembly desynchronization__. Disassembly desynchronization is a umbrella term for obfuscation techniques that disrupt static disassembly by the creative placement of junk bytes (random data bytes) into the instruction stream such that a disassembler will parse those junk bytes as code instructions. In the case of an opaque predicate, junk bytes are inserted into the target basic block of the opaque predicate's superfluous branch. To identify opaque predicates' superfluous branches, we analyze each conditional branch's outgoing basic blocks for __illogical behaviors__ (which can manifest from code instructions that are actually junk bytes). Note that identifying the superfluous branch will allow us to trace back to the offending opaque predicate.

Future work will look into detecting opaque predicates when the damage is code bloat.

## Detective in Action:
Current implementation is a [BinaryNinja](https://binary.ninja) plugin.

This plugin is not available through BinaryNinja's plugin manager yet! I plan to make some updates to the code (e.g. code readability, code cleanup) before performing all the necessary steps to have this plugin be available through plugin manager. In the meantime, it can be installed [manually](https://docs.binary.ninja/guide/plugins.html#manual-installation).

How to run plugin: 
![Plugin Run](whole.png)

Output:
![Plugin Output](current_output.png)

Note that the printed virtual addresses (highlighed in green) are the target addresses of the superfluous branches. (The addresses can easily be changed to the addresses of the opaque conditional statements if desired.)

## Paper Citation

(to be updated)

Authors: Yu-Jye Tung, Ian G. Harris
