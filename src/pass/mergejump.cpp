#include <iostream>
#include <vector>
#include <sstream>

#include "mergejump.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "instr/register.h"

/// MergeJumpPass : Reduces the number of total gadgets in the binary by ensuring that each function has precisely 1 indirect jump statement per target register statement. This pass identifies all indirect jumps and in the function and rewrites them to direct jump instructions to one arbitrarily chosen indirect jump instruction per target register. This reduces the prevalance of compiler placed indirect jump bytes in the binary.
/// TODO: For functions that do no use all registers (likely) it is possible that we can consolidate all indirect jumps in a single function.  Preference is to use an unsed volatile register and add register copies to make all indirect calls to the same register, which allows them to be merged like returns.  Less preferred is to find an unused non-volatile register, and push its value in function prologue, use it consolidate jumps, and pop its value in the epilogue.

/// TODO List: There are opportunities to optimize this pass. They are the same as the opportunites to improve the merge return pass
/// 1) EDGE CASE: The return we are getting rid of may be the sole target of a jump (conditional or direct). In this case we can eliminate the return and hook the pre-existing jump up directly to the preserved return. It may be worth analyzing our options for the return target to choose one that does not have this benefit. It is worht noting that this may incur penalties on AMD branch predictors if this eliminates a rep retn and instead hooks up the conditional jump to regular return. Consider this problem when improving this pass.
void MergeJumpPass::visit(Module *module) {
    recurse(module->getFunctionList());
	
	// Report stats
	std::cout << " Total merged jumps: " << totalMerged << std::endl;
}

void MergeJumpPass::visit(Function* function) {
	std::map<Register, std::vector<Instruction*>> jumps_map;
	std::string name = function->getName();	
	
	// VERBOSITY commented out for verbosity purposes.	
	// std::cout << "  Merge Jump Pass is analyzing function: " << name << std::endl;

	// Checks all instructions for indirect jump instructions, stores mapping of target registers to instruction pointers for later.
	for (auto block : CIter::children(function)){
		for (auto instr : CIter::children(block)){
			auto semantic = instr->getSemantic();
   			if(IndirectJumpInstruction* ij = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
				Register found_reg = ij->getRegister();
				
				// Check to see if a vector of instruction pointers already exists
				if(jumps_map.count(found_reg) > 0){
					jumps_map[found_reg].push_back(instr);
				}
				else{
					jumps_map.emplace(std::make_pair(found_reg, std::vector<Instruction*>()));
					jumps_map[found_reg].push_back(instr);
				}
    		}	
		}
	}

	/* VERBOSITY commented out for verbosity purposes. 
	if(jumps_map.size() > 1)
		std::cout << "    Function " << function->getName() << " has indirect jumps that target " << jumps_map.size() << " registers." << std::endl;   */
	
	// Performs a jump merge within the function if it has multiple indirect jump instructions targeting the same register.
	std::map<Register, std::vector<Instruction*>>::iterator it = jumps_map.begin();
	bool mutated = false;

	while(it !=  jumps_map.end()){
		if(it->second.size() > 1){
			mutated = true;
			
			// VERBOSITY commented out for verbosity purposes.
			//std::cout << "    Merging " << it->second.size() << " jumps to register: " << it->first << " for function: " << function->getName() << std::endl;
			
			totalMerged += it->second.size()-1;


			// Make the first discovered indirect jump instruction the target for all others.		
			Instruction* jump_target = it->second[0];

			// Rewrite all jumps to this register except the target as jumps to the target.
			for (unsigned int i=1; i<it->second.size(); ++i){
				Instruction* instr = it->second[i];		
				auto semantic = instr->getSemantic();

				// Create new direct jump instruction linked to the single return we will keep
				auto newSem = new ControlFlowInstruction(X86_INS_JMP, instr, "\xe9", "jmp", 4);
				newSem->setLink(new NormalLink(jump_target, Link::SCOPE_INTERNAL_JUMP));
						instr->setSemantic(newSem);

				// Tell Egalito we updated the size of this block.
				ChunkMutator(instr->getParent(), true).modifiedChildSize(instr, newSem->getSize() - semantic->getSize());  
				delete semantic;
			}
		}
		++it;
	}	

	if(mutated)
		ChunkMutator(function, true);
	
	return;
}
