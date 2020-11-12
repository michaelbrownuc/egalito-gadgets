#include <iostream>
#include <vector>
#include <sstream>

#include "widenbarriers.h"
#include "operation/mutator.h"
#include "instr/concrete.h"

#include "disasm/disassemble.h"


/// WidenBarriersPass : Reduces the number of total gadgets in the binary by eliminating GPIs that occur at the boundary of two instructions.
/// This occurs when one instruction ends in 0xff, 0x0f, or 0xcd and the next instruction starts with a byte that combines to encode a GPI.  

void WidenBarriersPass::visit(Module *module) {
    recurse(module->getFunctionList());
	
	// Report stats
	std::cout << " Total barriers widened: " << totalWidened << std::endl;
}

void WidenBarriersPass::visit(Function* function) {
    // Iterate through all instructions check their last byte
	for (auto block : CIter::children(function)){
		for (auto instr : CIter::children(block)){
			AssemblyPtr assm = instr->getSemantic()->getAssembly();
            
            // Check that there is assembly for this semantic
            if(assm){
                // Get the last byte of the instruction                               
                std::string last_byte = getByteAsString(assm->getBytes(), assm->getSize()-1);
                
                if(last_byte == "ff"){
                    if(AssemblyPtr next_assm = getNextContiguousAssembly(instr)){
                        std::string next_byte = getByteAsString(next_assm->getBytes(), 0);
                
                        // Check the next byte for a GPI encoding (based on first byte)
                        if(next_byte == "20" || next_byte == "21" || next_byte == "22" ||
                           next_byte == "23" || next_byte == "26" || next_byte == "27" ||
                           next_byte == "e0" || next_byte == "e1" || next_byte == "e2" ||
                           next_byte == "e3" || next_byte == "e4" || next_byte == "e6" || next_byte == "e7" ||
                           next_byte == "10" || next_byte == "11" || next_byte == "12" ||
                           next_byte == "13" || next_byte == "16" || next_byte == "17" ||
                           next_byte == "d0" || next_byte == "d1" || next_byte == "d2" ||
                           next_byte == "d3" || next_byte == "d4" || next_byte == "d6" || next_byte == "D7") {
                            // VERBOSTIY commented out for verbosity purposes.
                            //std::cout << "Found a GPI in " << function->getName() << ": " << last_byte << next_byte << ". Widening the intra-instruction barrier." << std::endl;    
                            widenBarrier(instr);
                        }
                    }                    
                }   
                else if(last_byte == "0f"){
                    if(AssemblyPtr next_assm = getNextContiguousAssembly(instr)){
                        std::string next_byte = getByteAsString(next_assm->getBytes(), 0);
                
                        // Check the next byte for a GPI encoding (based on first byte)
                        if( next_byte == "34" || next_byte == "05" ){
                            // VERBOSTIY commented out for verbosity purposes.
                            //std::cout << "Found a GPI in " << function->getName() << ": " << last_byte << next_byte << ". Widening the intra-instruction barrier." << std::endl;    
                            widenBarrier(instr);
                        }
                    }
                }                
                else if(last_byte == "cd"){
                    if(AssemblyPtr next_assm = getNextContiguousAssembly(instr)){
                        std::string next_byte = getByteAsString(next_assm->getBytes(), 0);
                
                        // Check the next byte for a GPI encoding (based on first byte)
                        if( next_byte == "80" ){
                            // VERBOSTIY commented out for verbosity purposes.
                            //std::cout << "Found a GPI in " << function->getName() << ": " << last_byte << next_byte << ". Widening the intra-instruction barrier." << std::endl;    
                            widenBarrier(instr);
                        }
                    }
                }
            }           	
		}
	}

	return;
}

// Returns the next contiguous instructions assembly pointer, or null if there is no next instruction or there is assembly for the next instruction.
AssemblyPtr WidenBarriersPass::getNextContiguousAssembly(Instruction* instr){
    // First: Try to get the instruction's next sibling
    Instruction* next = dynamic_cast<Instruction*>(instr->getNextSibling());

    // Second: Try to get the first instruction of the next Block
    if(!next)
        if(Block* next_block = dynamic_cast<Block*>(instr->getParent()->getNextSibling()))
            next = dynamic_cast<Instruction*>(next_block->getChildren()->getIterable()->get(0));
    
    // Last: If we have an instruction, return its assembly (could be null), otherwise return null
    if(next)
        return next->getSemantic()->getAssembly();
    else 
        return nullptr;    
}

std::string WidenBarriersPass::getByteAsString(const char* bytes, int pos){
    char buffer[3];
    sprintf(buffer, "%02x", (unsigned)bytes[pos] & 0xff);                
    return std::string(buffer);
}

void WidenBarriersPass::widenBarrier(Instruction* instr){
    // Insert a no-op between the instructions 
    Block* parent_block = (Block *)instr->getParent();
    ChunkMutator block_m(parent_block, true);
    block_m.insertAfter(instr, Disassemble::instruction({0x90}));
    
    // Update function to account for new block size
    ChunkMutator func_m((Function *) parent_block->getParent(), true); 

    // Record stats
    ++totalWidened;
}