#ifndef EGALITO_PASS_OFFSET_SLEDDING_H
#define EGALITO_PASS_OFFSET_SLEDDING_H

#include "chunk/program.h"
#include "chunk/concrete.h"

using OffsetSleddingProfile = std::map<Function*, std::vector<Instruction*>*>;


/// This pass behaves differently than others. It is meant to be called iteratively, making a single edit per function and 
/// returning so addresses can be re-assigned.  As a result, it does not extend ChunkPass.
class OffsetSleddingPass {
    
public:
    static void visit(OffsetSleddingProfile profile);
    static OffsetSleddingProfile generateProfile(Program* program);
    static int containsUnintendedGadgets(diff_t displacement);    
};


#endif