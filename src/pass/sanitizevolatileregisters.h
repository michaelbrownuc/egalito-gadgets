#ifndef EGALITO_SANITIZE_VOLATILE_REGISTERS_H
#define EGALITO_SANITIZE_VOLATILE_REGISTERS_H

#include "chunkpass.h"
#include "instr/assembly.h"

class SanitizeVolatileRegistersPass : public ChunkPass {
    
public:
    virtual void visit(Module *module);

protected:
    virtual void visit(Function *function);

private:
    void poisonReturn(Instruction* instr);
};


#endif