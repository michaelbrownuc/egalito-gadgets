#include <iostream>
#include <vector>
#include <sstream>

#include "mergereturn.h"
#include "operation/mutator.h"
#include "instr/concrete.h"

/// MergeReturnPass : Reduces the number of total gadgets in the binary by ensuring that each function has precisely 1 return statement. This pass identifies all returns and in the function and rewrites them to direct jump instructions to one arbitrarily chosen return function. This reduces the prevalance of compiler placed return bytes in the binary.

/// TODO List: There are opportunities to optimize this pass. Most are inline.  Other opportunities listed here.
/// 1) EDGE CASE: The return we are getting rid of may be the target of other jumps (conditional or direct). In this case we can eliminate the return and hook the pre-existing jump up directly to the cannonical return. It may be worth analyzing our options for the return target to choose one that does not have this benefit. It is worth noting that this may incur penalties on AMD branch predictors if this eliminates a rep retn and instead hooks up the conditional jump to regular return. Consider this problem when improving this pass.
/// 2) EDGE CASE: Returns to be merged have common instruction "prefixes". We can choose cannonical return based on the longest common prefix, and eliminate both returns and short prefixes, replacing with a jump from the eliminated instructions to appropraite prefix point.
void MergeReturnPass::visit(Module *module) {
    recurse(module->getFunctionList());
}

void MergeReturnPass::visit(Function* function) {
	std::vector<Instruction*> rets;
	std::string name = function->getName();	
	
	// VERBOSITY commented out for verbosity purposes.
	//std::cout << "  Merge Return Pass is analyzing function: " << name << std::endl;

	// Checks all instructions for return instructions, stores pointers for later.
	for (auto block : CIter::children(function)){
		for (auto instr : CIter::children(block)){
			auto semantic = instr->getSemantic();
   			if(dynamic_cast<ReturnInstruction *>(semantic)) {
        			rets.push_back(instr);
    			}	
		}
	}
	
	// Performs a return merge on the function if it has multiple return instructions.
	if(rets.size() > 1){
		std::cout << "    Merging returns for function: " << function->getName() << std::endl;

		// Make the first discovered return instruction the target for all other
		Instruction* ret_target = rets[0];

		// Rewrite all returns except the target as jumps to the target.
		for (unsigned int i=1; i<rets.size(); ++i){
			Instruction* instr = rets[i];		
			auto semantic = instr->getSemantic();

			// Create new direct jump instruction linked to the single return we will keep
			auto newSem = new ControlFlowInstruction(X86_INS_JMP, instr, "\xe9", "jmp", 4);
			newSem->setLink(new NormalLink(ret_target, Link::SCOPE_INTERNAL_JUMP));
        	instr->setSemantic(newSem);

			// Tell Egalito we updated the size of this block.
			ChunkMutator(instr->getParent(), true).modifiedChildSize(instr, newSem->getSize() - semantic->getSize());  
			delete semantic;
		}
		ChunkMutator(function, true);
	}	
	
	return;
}
