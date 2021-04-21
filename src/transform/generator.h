#ifndef EGALITO_TRANSFORM_GENERATOR_H
#define EGALITO_TRANSFORM_GENERATOR_H

#include <vector>
#include "sandbox.h"

class PLTTrampoline;

class Generator {
private:
    Sandbox *sandbox;
    bool useDisps;
public:
    Generator(Sandbox *sandbox, bool useDisps = true)
        : sandbox(sandbox), useDisps(useDisps) {}

    void assignAddresses(Program *program);
    void generateCode(Program *program);

    void assignAddresses(Program *program, const std::vector<Function *> &order);
    void generateCode(Program *program, const std::vector<Function *> &order);

    void assignAddresses(Module *module);
    void generateCode(Module *module);

    void assignAddresses(Module *module, const std::vector<Function *> &order);
    void generateCode(Module *module, const std::vector<Function *> &order);

    // For function generation
    void assignAddressForFunction(Function *function);
    void generateCodeForFunction(Function *function);

    // For JIT-Shuffling. Assign an address and generate code.
    void assignAndGenerate(Function *function);
    void assignAndGenerate(PLTTrampoline *trampoline);

    // For testing purposes only. Jumps directly to main, skipping init.
    void jumpToSandbox(Module *module, const char *function = "main");

    // Made public for function re-ordering passes
    std::vector<Function *> pickFunctionOrder(Module *module);

private:    
    void pickFunctionAddressInSandbox(Function *function);
    void pickPLTAddressInSandbox(PLTTrampoline *trampoline);
};

#endif
