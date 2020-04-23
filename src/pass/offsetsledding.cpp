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
/// Returns true if a gadget was found and was corrected, false if there are no corrections to make.
bool OffsetSleddingPass::visit(Program* program) {
    // Maintain a map of problematic calls to funcitons
    std::map<Function*, std::vector<Instruction*>> problem_call_map;

	// Iterate through each function. Don't want to recurse - we want to be able to return after a single correction.
	for(auto module : CIter::children(program)){
        for(Function* func : CIter::children(module->getFunctionList())){
            // TODO DELET THIS - Debug print
            std::cout << "Analyzing function: " << func->getName() << std::endl;

            for (auto block : CIter::children(func)){
                for (auto instr : CIter::children(block)){
                    auto semantic = instr->getSemantic();
                    if(ControlFlowInstruction* cfi = dynamic_cast<ControlFlowInstruction*>(semantic)){  
                        // Limit our pass to RIP relative links
                        if(cfi->getLink()->isRIPRelative()){
                            // Check if the displacement encodes a gadget producing instruction
                            int sled = containsUnintendedGadgets(cfi->calculateDisplacement());                
                            
                            // Check the size of the sled needed. 0 indicates no gadget found. Move on.
                            if(sled == 0)
                                continue;
                            // If the sled size needed is relatively small (arbitrarily chosen value), we should fix this immediately. 
                            else if(sled > 0 && sled <= 16){

                                {
                                    TemporaryLogLevel tll1("chunk", 20);
                                    TemporaryLogLevel tll2("disasm", 20);
                                    ChunkDumper dump;
                                    func->accept(&dump);
                                }
            

                                // TODO DELET THIS - Debug print
                                address_t target_address = cfi->getLink()->getTargetAddress();
                                std::cout << "  Control Flow Instruction " << cfi->getMnemonic() << " at address: ";
                                std::cout << std::hex << instr->getAddress();
                                std::cout << " targets address: " ;
                                std::cout << std::hex << target_address;
                                std::cout << " with displacement: ";
                                std::cout << std::hex << cfi->calculateDisplacement();
                                std::cout << " that encodes unintended gadgets, requiring a sled of size: " << std::dec << sled << std::endl;
                                ////

                                // TODO: DELET THIS
                                std::cout << "    Greedily adding small sled." << std::endl;
                                
                                if(dynamic_cast<Function*>(cfi->getLink()->getTarget())){
                                    std::cout << "ITS A FUNCTION. SKIPPING FOR NOW." << std::endl;
                                    continue;
                                }
                                else if (Instruction* targetInstruction = dynamic_cast<Instruction*>(cfi->getLink()->getTarget())){
                                    {
                                        // Insert Sled                       
                                        ChunkMutator mutator((Block *)targetInstruction->getParent(), true);
                                        while(sled > 0){
                                            auto nop = Disassemble::instruction({0x90});
                                            std::cout << "NOP size is " << nop->getSize() << std::endl;
                                            mutator.insertBeforeJumpTo(targetInstruction, nop);
                                            --sled;
                                        }
                                    }
                                    {
                                        ChunkMutator m(func, true);
                                        //ChunkMutator m2((Function *)targetInstruction->getParent()->getParent(), true);
                                    }

                                    for(auto i : CIter::children((Block*)targetInstruction->getParent())) {
                                        std::cout << "instruction " << i->getName() << " has offset? " << (dynamic_cast<OffsetPosition*>(i->getPosition()) ? "offset":"no")
                                            << " prev sibling? " << i->getPreviousSibling()
                                            << " parent? " << i->getParent() << "\n";
                                    }
                                }

                                {
                                    TemporaryLogLevel tll1("chunk", 20);
                                    TemporaryLogLevel tll2("disasm", 20);
                                    ChunkDumper dump;
                                    func->accept(&dump);
                                }
                                
                                return true;
                            }
                            // If the sled size needed is large, we catalog it for later. Smaller operations may resolve it, or we can find the most efficient way to handle it.
                            else if(sled > 16){
                                //TODO DELET THIS
                                std::cout << "    Cataloging large sled for later." << std::endl;
                            }
                            else  std::cout << "    ERROR: Negative sled value encountered. This should not happen. Ignoring." << std::endl;
                        }
                    }
                }
            }
        }
        // TODO: Insert function order swapping code here later.
    }

    // If the scan completes without returning early, it's time to choose a harder optimization from the catalog.
    return false;
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
