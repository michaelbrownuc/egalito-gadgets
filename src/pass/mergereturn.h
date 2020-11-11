#ifndef EGALITO_PASS_MERGE_RETURN_H
#define EGALITO_PASS_MERGE_RETURN_H

#include "chunkpass.h"

class MergeReturnPass : public ChunkPass {
    
public:
    virtual void visit(Module *module);

protected:
    virtual void visit(Function *function);
    int totalMerged = 0;
};


#endif
