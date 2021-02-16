#ifndef EGALITO_PASS_FUNCTION_REORDERING_H
#define EGALITO_PASS_FUNCTION_REORDERING_H

#include "chunk/program.h"
#include "chunk/concrete.h"

using FunctionTarget = std::pair<Function*, int>;           // Target function of a problematic encoding and the sled size required
using FunctionReorderingProfile = std::map<Function*, std::vector<FunctionTarget>*>;  // Map of source function to all problematic targets
using FunctionOrder = std::vector<Function*>;


/// This pass behaves differently than others. It is meant to be called iteratively, making a single function list reordering attempt and 
/// returning so addresses can be re-assigned.  As a result, it does not extend ChunkPass.
class FunctionReorderingPass {
    
public:
    static FunctionOrder visit(FunctionReorderingProfile profile, FunctionOrder order);
    static FunctionReorderingProfile generateProfile(Program* program);
};


#endif