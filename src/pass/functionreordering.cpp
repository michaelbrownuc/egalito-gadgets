#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <utility>

#include "functionreordering.h"
#include "offsetsledding.h"  // for containsUnintendedGadgets()
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "chunk/dump.h"
#include "log/temp.h"


/// Searches through call instruction offsets for unintended CRA gadgets encoded within them. This pass eliminates found unintended gadgets
/// in the binary by performing re-ordering of the functions in the module to shift encodings to ones that do not encode gadgets.
/// This is meant to be used iteratively as each re-ordering may introduce new GPIs. Addresses must be reassigned after each re-ordering and 
/// re-checked. Visitation is randomized and greedy because changing function orders can have unpredictable effects on offsets.
FunctionOrder FunctionReorderingPass::visit(FunctionReorderingProfile profile, FunctionOrder order) {    
    // Select a random profile item
    auto rand = profile.begin();
    std::advance(rand, std::rand() % profile.size());

    // Select a random function to move, get the number of bytes to move it
    int mover_idx = std::rand() % (rand->second->size() + 1);
    Function* mover;
    int bytes_to_move = 0;

    if(mover_idx == 0){
        // Move the source
        mover = rand->first;

        // Find max sled among all problematic links
        for(auto tgt_iter = rand->second->begin(); tgt_iter != rand->second->end(); ++tgt_iter)
            if(tgt_iter->second > bytes_to_move)
                bytes_to_move = tgt_iter->second; 
    }
    else{
        // Move one of the destinations
        auto tgt_iter = rand->second->begin();
        std::advance(tgt_iter, mover_idx-1);
        mover = tgt_iter->first;
        bytes_to_move = tgt_iter->second;
    }
    
    //std::cout << "    Moving:" << mover->getName() << " requires shift of =" << bytes_to_move << std::endl;

    // Select a random direction to move
    bool move_back = std::rand() % 2;
    
    // Get index of the function to be moved, execute the move
    auto mov_iter = std::find(order.begin(), order.end(), mover);
    size_t index = mov_iter - order.begin();

    while(bytes_to_move > 0){
        int moved_by = 0;

        Function* temp = order[index];
        
        if(move_back){
            // Bounds check
            if(index == 0)
                break;

            moved_by = order[index-1]->getSize();
            order[index] = order[index-1];
            order[index-1] = temp; 
            --index;
        }
        else{
            // Bounds check
            if(index >= order.size()-1)
                break;

            moved_by = order[index+1]->getSize();
            order[index] = order[index+1];
            order[index+1] = temp; 
            ++index;
        }

        bytes_to_move -= moved_by;
    }

    return order;
}


/// Scans a program and generates a profile of calls that encode gadget-producing instructions (GPIs).
FunctionReorderingProfile FunctionReorderingPass::generateProfile(Program* program){
    FunctionReorderingProfile profile;

    for(auto module : CIter::children(program)){
        for(Function* func : CIter::children(module->getFunctionList())){
            for (auto block : CIter::children(func)){
                for (auto instr : CIter::children(block)){
                    auto semantic = instr->getSemantic();
                    ControlFlowInstruction* cfi = dynamic_cast<ControlFlowInstruction*>(semantic);                    
                    if (cfi && cfi->getLink()->isRIPRelative()) {  
                        // Check if the displacement encodes a gadget producing instruction
                        int sled = OffsetSleddingPass::containsUnintendedGadgets(cfi->calculateDisplacement());

                        // We care only about long sleds  (TODO can try setting this comparison back to 0 and see if reoprdering this way works without negative impacts)         
                        if(sled > 2){  
                            // Get the target of the call, may not be a function
                            Function* target_func = dynamic_cast<Function*>(cfi->getLink()->getTarget());
                            if(target_func){ 
                            
                                // Add to profile
                                FunctionTarget target = std::make_pair(target_func, sled);
                                auto loc = profile.find(func);
                                if(loc != profile.end()){
                                    loc->second->push_back(target);
                                }
                                else{                                                                
                                    std::vector<FunctionTarget>* targets = new std::vector<FunctionTarget>();
                                    targets->push_back(target);
                                    profile.insert({func, targets});
                                }   
                            }                    
                        }
                    }
                }
            }
        }
    }
    return profile;
}
