#ifndef EGALITO_PASS_OFFSET_SLEDDING_H
#define EGALITO_PASS_OFFSET_SLEDDING_H

#include "chunk/program.h"

/// This pass behaves differently than others. It is meant to be called by the conductor iteratively, making a single edit and returning so addresses 
/// can be re-assigned.  As a result, it does not extend ChunkPass and has a boolean return value.
class OffsetSleddingPass {
    
public:
    static bool visit(Program* program);

private:
    static int containsUnintendedGadgets(diff_t displacement);
};


#endif