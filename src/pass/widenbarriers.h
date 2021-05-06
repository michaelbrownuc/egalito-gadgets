#ifndef EGALITO_WIDEN_BARRIERS_H
#define EGALITO_WIDEN_BARRIERS_H

#include "chunkpass.h"
#include "instr/assembly.h"

class WidenBarriersPass : public ChunkPass {
    
public:
    virtual void visit(Module *module);

protected:
    virtual void visit(Function *function);
    int totalWidened = 0;

private:
    AssemblyPtr getNextContiguousAssembly(Instruction* instr);
    std::string getByteAsString(const char* bytes, int pos);
    void widenBarrier(Instruction* instr);
};


#endif