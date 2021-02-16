#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

#include "offsetsledding.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/temp.h"

/// Searches through jump instruction offsets for unintended CRA gadgets encoded within them. When one is found, this function eliminates
/// the unintended gadget in the binary by inserting small NOP sleds prior to jump and call targets to push the encoding away from a gadget encoding.
/// This is meant to be used iteratively as each sled will affect all subsequent offsets. Addresses must be reassigned after each operation.
/// Visitation is profile guided. For each function in the profile, a random branch is selected for correction.
void OffsetSleddingPass::visit(OffsetSleddingProfile profile) {
	// Iterate through each function. Don't want to recurse - we want to be able to return after a single correction.
    for(auto iter = profile.begin(); iter != profile.end(); ++iter){
        // Select a random instruction to fix
        auto rand = iter->second->begin();
        std::advance(rand, std::rand() % iter->second->size());
        Instruction* instr = *rand;
        auto semantic = instr->getSemantic();
        ControlFlowInstruction* cfi = dynamic_cast<ControlFlowInstruction*>(semantic);
        
        // Get the size of the sled needed
        int sled = containsUnintendedGadgets(cfi->calculateDisplacement());                
        Instruction* targetInstruction = dynamic_cast<Instruction*>(cfi->getLink()->getTarget());
        
        // A sled size greater than 0 indicates a gadget was found.
        // Since this pass is limited to near jumps, sled sizes should be small (1 or 2) in almost all cases.  
        // Might have sleds of size 256/512 for huge functions.
        if(sled > 0 && targetInstruction){                            
            /* VERBOSITY commented out for verbosity purposes.
            address_t target_address = cfi->getLink()->getTargetAddress();
            std::cout << " In function " << func->getName();
            std::cout << " Control Flow Instruction " << cfi->getMnemonic() << " at address: ";
            std::cout << std::hex << instr->getAddress();
            std::cout << " targets address: " ;
            std::cout << std::hex << target_address;
            std::cout << " with displacement: ";
            std::cout << std::hex << cfi->calculateDisplacement();
            //std::cout << " that encodes unintended gadgets, requiring a sled of size: " << std::dec << sled << std::endl;                                 
            */

            // For postive displacements, sleds must go before the target instruction to change encoding
            if(cfi->calculateDisplacement() > 0){                       
                ChunkMutator mutator((Block *)targetInstruction->getParent(), true);
                while(sled > 0){
                    mutator.insertBefore(targetInstruction, Disassemble::instruction({0x90}));
                    --sled;
                }
            }
            // For negative displacements, the sled must go before jump to change the encoding.
            else{
                ChunkMutator mutator((Block *) instr->getParent(), true);
                while(sled > 0){
                    mutator.insertBeforeJumpTo(instr, Disassemble::instruction({0x90}));
                    --sled;
                }
            }

            // Update function to account for new block size
            ChunkMutator m(iter->first, true);                           
            
        }        
    }    
}


/// Scans a program and generates a profile of branches that encode gadget-producing instructions (GPIs).
OffsetSleddingProfile OffsetSleddingPass::generateProfile(Program* program){
    OffsetSleddingProfile profile;

    for(auto module : CIter::children(program)){
        for(Function* func : CIter::children(module->getFunctionList())){
            for (auto block : CIter::children(func)){
                for (auto instr : CIter::children(block)){
                    auto semantic = instr->getSemantic();
                    ControlFlowInstruction* cfi = dynamic_cast<ControlFlowInstruction*>(semantic);
                    // Limit our pass to RIP relative jump instructions (conditional and unconditional)
                    if (cfi && cfi->getLink()->isRIPRelative()) {  
                        // Check if the displacement encodes a gadget producing instruction
                        int sled = containsUnintendedGadgets(cfi->calculateDisplacement());
                        Instruction* targetInstruction = dynamic_cast<Instruction*>(cfi->getLink()->getTarget());                        
                        if(sled > 0 && targetInstruction){
                            // Add to profile
                            auto loc = profile.find(func);
                            if(loc != profile.end()){
                                loc->second->push_back(instr);
                            }
                            else{                                                                
                                std::vector<Instruction*>* branches = new std::vector<Instruction*>();
                                branches->push_back(instr);
                                profile.insert({func, branches});
                            }                        
                        }
                    }
                }
            }
        }
    }
    return profile;
}

/// Determines if the displacement encodes a gadget producing instruction. Returns 0 if no unintended gadget is found. 
/// If found, returns the necessary sled size to change the encoding.
/// NOTE: We can optimize this further by reducing the sled size by lower order byte values. For now we just use a full 256. 
int OffsetSleddingPass::containsUnintendedGadgets(diff_t displacement){
	// First step is to convert the displacement to a searchable string
    std::ostringstream oss;
	oss << std::setw(16) << std::setfill('0') << std::hex << displacement;
	std::string formatted = oss.str();
    std::string disp = "0000000000000000";
    // Need to reorder the bytes to match encoding order. This part is kinda dirty. Probably a better way.
    disp[0] = formatted[14]; disp[1] = formatted[15];
    disp[2] = formatted[12]; disp[3] = formatted[13];
    disp[4] = formatted[10]; disp[5] = formatted[11];
    disp[6] = formatted[8]; disp[7] = formatted[9];
    disp[8] = formatted[6]; disp[9] = formatted[7];
    disp[10] = formatted[4]; disp[11] = formatted[5];
    disp[12] = formatted[2]; disp[13] = formatted[3];
    disp[14] = formatted[0]; disp[15] = formatted[1];

    // Check the seachable string for gadget encoding bytes. If found, calculate sled and return.
	// ret (ROP)
	size_t index = disp.find("c3");
	if(index != std::string::npos && index % 2 == 0){
        if(displacement < 0)
            return pow(256, index/2)*2;  // Doubling required to avoid turning one encoding into it's adjacent one.
        else
            return pow(256, index/2);
    }  
		
	// ret <imm> (ROP)
	index = disp.find("c2");
	if(index != std::string::npos && index % 2 == 0){
        if(displacement > 0)
            return pow(256, index/2)*2;
        else
            return pow(256, index/2);
    }

	// retf (ROP)
	index = disp.find("ca");
	if(index != std::string::npos && index % 2 == 0) {
        if(displacement > 0)
            return pow(256, index/2)*2;
        else
            return pow(256, index/2);
    }

	// retf <imm> (ROP)
	index = disp.find("cb");
	if(index != std::string::npos && index % 2 == 0){
        if(displacement < 0)
            return pow(256, index/2)*2;
        else
            return pow(256, index/2);
    }  
	
	// jmp|call reg|[reg] (JOP/COP)
	index = disp.find("ff");
	if(index != std::string::npos && index % 2 == 0){
		std::string next_byte = disp.substr(index+2, 2);
		if(next_byte == "20" || next_byte == "21" || next_byte == "22" ||
		   next_byte == "23" || next_byte == "26" || next_byte == "27" ||
		   next_byte == "e0" || next_byte == "e1" || next_byte == "e2" ||
		   next_byte == "e3" || next_byte == "e4" || next_byte == "e6" ||
		   next_byte == "e7" ||
		   next_byte == "10" || next_byte == "11" || next_byte == "12" ||
		   next_byte == "13" || next_byte == "16" || next_byte == "17" ||
		   next_byte == "d0" || next_byte == "d1" || next_byte == "d2" ||
		   next_byte == "d3" || next_byte == "d4" || next_byte == "d6" ||
		   next_byte == "D7") return pow(256, index/2);
	}

	// jmp|call reg|[reg] (JOP/COP) X64 32-bit addressing mode
	index = disp.find("67ff");
	if(index != std::string::npos && index % 2 == 0){
		std::string next_byte = disp.substr(index+4, 2);
		if(next_byte == "20" || next_byte == "21" || next_byte == "22" ||
		   next_byte == "23" || next_byte == "26" || next_byte == "27" ||
		   next_byte == "e0" || next_byte == "e1" || next_byte == "e2" ||
		   next_byte == "e3" || next_byte == "e4" || next_byte == "e6" ||
		   next_byte == "e7" ||
		   next_byte == "10" || next_byte == "11" || next_byte == "12" ||
		   next_byte == "13" || next_byte == "16" || next_byte == "17" ||
		   next_byte == "d0" || next_byte == "d1" || next_byte == "d2" ||
		   next_byte == "d3" || next_byte == "d4" || next_byte == "d6" ||
		   next_byte == "D7" ) return pow(256, index/2);
	}
	
	// int 0x80 (Syscall)
	index = disp.find("cd80");
	if(index != std::string::npos && index % 2 == 0) return pow(256, index/2);
	
	// sysenter(Syscall)
	index = disp.find("0f34");
	if(index != std::string::npos && index % 2 == 0) return pow(256, index/2);

	// syscall (Syscall)
	index = disp.find("0f05");
	if(index != std::string::npos && index % 2 == 0) return pow(256, index/2);
	
    // No gadget encodings found.
	return 0;
}
