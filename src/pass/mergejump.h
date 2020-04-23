#ifndef EGALITO_PASS_MERGE_JUMP_H
#define EGALITO_PASS_MERGE_JUMP_H

#include "chunkpass.h"

class MergeJumpPass : public ChunkPass {
    
public:
    virtual void visit(Module *module);

protected:
    virtual void visit(Function *function);
};


#endif
