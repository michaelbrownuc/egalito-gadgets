#include <iostream>
#include <vector>
#include <sstream>

#include "sanitizevolatileregisters.h"
#include "operation/mutator.h"
#include "instr/concrete.h"

#include "disasm/disassemble.h"


/// SanitizeVolatileRegistersPass : Poisons compiler-placed return GPIs by exploiting calling conventions. Specifically, X86-64 calling conventions 
/// mark RCX, and R8-11 as volatile registers not used for return values. We can sanitize these registers before returning from a function without 
/// impacting normal program functionality. These instructions greatly impair gadget functionality, limiting gadget diversity and utility.

/// Compatibility note: GCC will violate the calling convention w.r.t. caller-saved registers at levels O2, O3, and Os. Specifically, it will not 
/// insert save/restore instructions for caller-saved registers in the caller code if the called function does not use the register. Use of this 
/// pass on GCC binaries produced at level O2, O3, and Os will likely result in unsound behavior in its current form.

/// TODO: Improve this pass with intra- and inter-procedural data-flow analysis to achieve compatbility with GCC O2+ optimizations.

void SanitizeVolatileRegistersPass::visit(Module *module) {
    recurse(module->getFunctionList());
}

void SanitizeVolatileRegistersPass::visit(Function* function) {
    // Find all return instructions
	for (auto block : CIter::children(function)){
		for (auto instr : CIter::children(block)){
			auto semantic = instr->getSemantic();
   			if(dynamic_cast<ReturnInstruction *>(semantic)) {
        		poisonReturn(instr);
    		}	
		}
	}

    // TODO Can also poison indirect calls - but can't XOR any register carrying parameters, so check those.

	return;
}

void SanitizeVolatileRegistersPass::poisonReturn(Instruction* instr){
    // Insert a string of register sanitization operations before the return 
    Block* parent_block = (Block *)instr->getParent();
    ChunkMutator block_m(parent_block, true);
    
    block_m.insertBeforeJumpTo(instr, Disassemble::instruction({0x48, 0x31, 0xC9}));  // XOR RCX, RCX
    block_m.insertBeforeJumpTo(instr, Disassemble::instruction({0x4D, 0x31, 0xC0}));  // XOR R8, R8
    block_m.insertBeforeJumpTo(instr, Disassemble::instruction({0x4D, 0x31, 0xC9}));  // XOR R9, R9
    block_m.insertBeforeJumpTo(instr, Disassemble::instruction({0x4D, 0x31, 0xD2}));  // XOR R10, R10
    block_m.insertBeforeJumpTo(instr, Disassemble::instruction({0x4D, 0x31, 0xDB}));  // XOR R11, R11
    
    // Update function to account for new block size
    ChunkMutator func_m((Function *) parent_block->getParent(), true); 
}