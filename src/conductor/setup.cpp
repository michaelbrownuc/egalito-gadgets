#include <cassert>
#include <cstring>
#include <climits>  // for PATH_MAX
#include <unistd.h>  // for readlink
#include "config.h"
#include "setup.h"
#include "conductor.h"
#include "passes.h"
#include "transform/generator.h"
#include "load/segmap.h"
#include "load/emulator.h"
#include "chunk/dump.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "pass/clearspatial.h"
#include "pass/dumplink.h"
#include "util/feature.h"
#include "generate/uniongen.h"
#include "generate/mirrorgen.h"
#include "generate/kernelgen.h"
#include "log/registry.h"
#include "log/log.h"
#include "log/temp.h"

address_t runEgalito(ElfMap *elf, ElfMap *egalito);

ConductorSetup *egalito_conductor_setup __attribute__((weak));
Conductor *egalito_conductor __attribute__((weak));

void ConductorSetup::parseEgalito(bool fromArchive) {
#ifdef EGALITO_PATH
    const char *path = EGALITO_PATH;
#else
    const char *name = "/libegalito.so";
    char path[PATH_MAX];
    auto sz = readlink("/proc/self/exe", path, PATH_MAX);
    path[sz] = 0;
    std::strcpy(std::strrchr(path, '/'), name);
#endif
    LOG(1, "egalito is at " << path);

    this->egalito = new ElfMap(path);
    Module *egalitoModule = nullptr;
    if(fromArchive) {
        auto library = conductor->getProgram()->getLibraryList()
            ->byRole(Library::ROLE_EGALITO);
        egalitoModule = library->getModule();
        conductor->parseEgalitoElfSpaceOnly(egalito, egalitoModule, path);
    }
    else {
        egalitoModule = conductor->parseEgalito(egalito, path);
    }

    LoaderEmulator::getInstance().setup(conductor);
}

void ConductorSetup::createNewProgram() {
    this->conductor = new Conductor();
    ::egalito_conductor = conductor;
    this->elf = nullptr;
    this->egalito = nullptr;
}

Module *ConductorSetup::parseElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    createNewProgram();
    return injectElfFiles(executable, withSharedLibs, injectEgalito);
}

Module *ConductorSetup::injectElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    return injectElfFiles(executable, Library::ROLE_UNKNOWN, withSharedLibs, injectEgalito);
}

Module *ConductorSetup::injectElfFiles(const char *executable, Library::Role role,
    bool withSharedLibs, bool injectEgalito) {

    if(!conductor) createNewProgram();

    // executable can be a shared library. this->elf stores main module
    auto firstModule = conductor->parseAnything(executable, role);
    if(firstModule->getLibrary()->getRole() == Library::ROLE_MAIN) {
        this->elf = firstModule->getElfSpace()->getElfMap();
        findEntryPointFunction();
    }

    if(injectEgalito) {
        this->parseEgalito();
    }
    else {
        // !!! this should be done differently
        LoaderEmulator::getInstance().setupForExecutableGen(conductor);
    }

    if(withSharedLibs) {
        conductor->parseLibraries();
    }

    if(true || withSharedLibs) {
        conductor->resolvePLTLinks();
    }
    conductor->resolveData(withSharedLibs);
    conductor->resolveTLSLinks();
    conductor->resolveVTables();

#ifndef RELEASE_BUILD
    conductor->check();
#endif

    // At this point, all the effort for resolving the links should have
    // been performed (except for special cases)

    setBaseAddresses();
    return firstModule;
}

void ConductorSetup::parseEgalitoArchive(const char *archive) {
    this->conductor = new Conductor();

    this->elf = nullptr;
    this->egalito = nullptr;

    conductor->parseEgalitoArchive(archive);
    //this->parseEgalito(true);  // add ElfSpace to libegalito.so module

    for(auto module : CIter::modules(conductor->getProgram())) {
        auto library = module->getLibrary();
        if(true || library->getRole() == Library::ROLE_EGALITO
            || library->getRole() == Library::ROLE_LIBCPP) {

            auto elfMap = new ElfMap(library->getResolvedPathCStr());
            conductor->parseEgalitoElfSpaceOnly(elfMap, module,
                library->getResolvedPathCStr());
        }
    }

    // !!! has to be earlier than resolveData()
    setBaseAddresses();

    if(false) {
        conductor->resolvePLTLinks();
    }
    conductor->resolveData(false, true);
    conductor->resolveTLSLinks();
    conductor->resolveVTables();
}

void ConductorSetup::setBaseAddresses() {
    int i = 0;
    for(auto module : CIter::modules(conductor->getProgram())) {
        auto elfMap = module->getElfSpace()
            ? module->getElfSpace()->getElfMap() : nullptr;
        // this address has to be low enough to express negative offset in
        // jump table slots (to represent an index)
#if 0 // use 0x1X000000 for module addrs (X starts at 0)
        if(setBaseAddress(module, elfMap, 0x10000000 + i*0x1000000)) {
#else // use 0x0X000000 for module addrs (X starts at 1)
        if(setBaseAddress(module, elfMap, (i+1)*0x1000000)) {
#endif
            i ++;
        }
    }

    ClearSpatialPass clearSpatial;
    for(auto module : CIter::modules(conductor->getProgram())) {
        auto baseAddress = module->getBaseAddress();
        for(auto region : CIter::regions(module)) {
            region->updateAddressFor(baseAddress);
            module->accept(&clearSpatial);
        }
    }
}

void ConductorSetup::injectLibrary(const char *filename) {
    if(auto elfmap = new ElfMap(filename)) {
        auto module = conductor->parseAddOnLibrary(elfmap);
        setBaseAddress(module, elfmap, 0xb0000000);

        for(auto region : CIter::regions(module)) {
            region->updateAddressFor(elfmap->getBaseAddress());
        }
    }
    conductor->resolvePLTLinks();
}

std::vector<Module *> ConductorSetup::addExtraLibraries(
    const std::vector<std::string> &filenames) {

    std::map<std::string, Module *> pathMap;
    unsigned long maxAddress = 0;
    for(auto module : CIter::modules(conductor->getProgram())) {
        maxAddress = std::max(maxAddress, module->getBaseAddress());

        pathMap[module->getElfSpace()->getFullPath()] = module;
    }

    std::vector<Module *> modules;

    for(auto filenameCpp : filenames) {
        auto filename = filenameCpp.c_str();

        if(pathMap.count(filenameCpp)) {
            modules.push_back(pathMap[filenameCpp]);
        }
        else if(auto elfmap = new ElfMap(filename)) {
            auto module = conductor->parseExtraLibrary(elfmap, filename);
            maxAddress += 0x60000000;
            setBaseAddress(module, elfmap, maxAddress);

            for(auto region : CIter::regions(module)) {
                region->updateAddressFor(elfmap->getBaseAddress());
            }

            modules.push_back(module);
        }
        else modules.push_back(nullptr);
    }

    conductor->resolvePLTLinks();
    conductor->resolveData(true);
    conductor->resolveTLSLinks();
    conductor->resolveVTables();

    return modules;
}

void ConductorSetup::ensureBaseAddresses() {
    unsigned long maxAddress = 0;
    for(auto module : CIter::modules(conductor->getProgram())) {
        maxAddress = std::max(maxAddress, module->getBaseAddress());
    }

    for(auto module : CIter::modules(conductor->getProgram())) {
        if(module->getBaseAddress() != 0) continue;
        maxAddress += 0x100000000;

        auto elfMap = module->getElfSpace()
            ? module->getElfSpace()->getElfMap() : nullptr;

        setBaseAddress(module, elfMap, maxAddress);
    }
}

Sandbox *ConductorSetup::makeLoaderSandbox() {
    auto backing = MemoryBacking(sandboxBase, 10 * 0x1000 * 0x1000);
    sandboxBase += 10 * 0x1000 * 0x1000;
#ifdef LINUX_KERNEL_MODE
    auto sandbox = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
#else
    auto sandbox = new SandboxImpl<MemoryBacking,
        AlignedWatermarkAllocator<MemoryBacking>>(backing);
#endif
    //this->sandbox = sandbox;
    return sandbox;
}

ShufflingSandbox *ConductorSetup::makeShufflingSandbox() {
    auto backing = MemoryBacking(sandboxBase, 1 * 0x1000 * 0x1000);
    sandboxBase += 2 * 0x1000 * 0x1000;
    auto sandbox1 = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);

    auto backing2 = MemoryBacking(sandboxBase, 1 * 0x1000 * 0x1000);
    sandboxBase += 2 * 0x1000 * 0x1000;
    auto sandbox2 = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing2);
    return new DualSandbox<SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>>(sandbox1, sandbox2);
}

Sandbox *ConductorSetup::makeFileSandbox(const char *outputFile) {
    auto backing = MemoryBacking(SANDBOX_BASE_ADDRESS, MAX_SANDBOX_SIZE);
    return new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
}

Sandbox *ConductorSetup::makeStaticExecutableSandbox(const char *outputFile) {
    auto backing = MemoryBufferBacking(SANDBOX_BASE_ADDRESS, MAX_SANDBOX_SIZE);
    return new SandboxImpl<MemoryBufferBacking,
        AlignedWatermarkAllocator<MemoryBufferBacking>>(backing);
}

Sandbox *ConductorSetup::makeKernelSandbox(const char *outputFile) {
    auto backing = MemoryBufferBacking(LINUX_KERNEL_CODE_BASE, MAX_SANDBOX_SIZE);
    return new SandboxImpl<MemoryBufferBacking,
        AlignedWatermarkAllocator<MemoryBufferBacking>>(backing);
}

bool ConductorSetup::generateStaticExecutable(const char *outputFile) {
    auto sandbox = makeStaticExecutableSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto program = conductor->getProgram();

    //auto generator = StaticGen(program, backing);
    auto generator = UnionGen(program, backing);
    generator.preCodeGeneration();

    {
        //moveCode(sandbox, true);  // calls sandbox->finalize()
        moveCodeAssignAddresses(sandbox, true);
        generator.afterAddressAssign();
        {
            // get data sections; allow links to change bytes in data sections
            SegMap::mapAllSegments(this);
            ConductorPasses(conductor).newExecutablePasses(program);
        }
        copyCodeToNewAddresses(sandbox, true);
        moveCodeMakeExecutable(sandbox);
    }

    //generator.generate(outputFile);
    generator.generateContent(outputFile);
    return true;
}

//TODO: make this an iterative address assignment / transform loop
//      this one might be different, check how they use base addresses for the lib code. if the base addresses are hugely different we can perform multiple transforms (1 per base address)
bool ConductorSetup::generateStaticExecutableWithGadgetElimination(const char *outputFile) {
    auto sandbox = makeStaticExecutableSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto program = conductor->getProgram();

    //auto generator = StaticGen(program, backing);
    auto generator = UnionGen(program, backing);
    generator.preCodeGeneration();

    {
        //moveCode(sandbox, true);  // calls sandbox->finalize()
        moveCodeAssignAddresses(sandbox, true);
        generator.afterAddressAssign();
        {
            // get data sections; allow links to change bytes in data sections
            SegMap::mapAllSegments(this);
            ConductorPasses(conductor).newExecutablePasses(program);
        }
        copyCodeToNewAddresses(sandbox, true);
        moveCodeMakeExecutable(sandbox);
    }

    //generator.generate(outputFile);
    generator.generateContent(outputFile);
    return true;
}

bool ConductorSetup::generateMirrorELF(const char *outputFile) {
    auto sandbox = makeStaticExecutableSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto program = conductor->getProgram();

    auto generator = MirrorGen(program, backing);
    generator.preCodeGeneration();

    {
        //moveCode(sandbox, true);  // calls sandbox->finalize()
        moveCodeAssignAddresses(sandbox, true);
        generator.afterAddressAssign();
        {
            // get data sections; allow links to change bytes in data sections
            SegMap::mapAllSegments(this);
            ConductorPasses(conductor).newMirrorPasses(program);
        }
        copyCodeToNewAddresses(sandbox, true);
        moveCodeMakeExecutable(sandbox);
    }

    //generator.generate(outputFile);
    generator.generateContent(outputFile);
    return true;
}

//TODO: make this an iterative address assignment / transform loop
bool ConductorSetup::generateMirrorELFWithGadgetElimination(const char *outputFile) {
    auto program = conductor->getProgram();
    
    auto sandbox = makeStaticExecutableSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto generator = MirrorGen(program, backing);
    generator.preCodeGeneration();

    moveCodeAssignAddresses(sandbox, true);
    
    // Perform gadget elimination via offsets iteratively. Iterations are capped to ensure termination.
    int optsCap = 1;
    int optsDone = 0;

    while(optsDone < optsCap && ConductorPasses(conductor).searchJumpOffsetsAndSled(program)){
        std::cout << "ALERT:  A Gadget was eliminated. Need to redo addresses" << std::endl;
        ++optsDone;
        sandbox = makeStaticExecutableSandbox(outputFile);
        backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
        generator = MirrorGen(program, backing);
        generator.preCodeGeneration();
        moveCodeAssignAddresses(sandbox, true);
    }

    generator.afterAddressAssign();
    {
        // get data sections; allow links to change bytes in data sections
        SegMap::mapAllSegments(this);
        ConductorPasses(conductor).newMirrorPasses(program);
    }
    copyCodeToNewAddresses(sandbox, true);
    moveCodeMakeExecutable(sandbox);
    

    //generator.generate(outputFile);
    generator.generateContent(outputFile);
    return true;
}

bool ConductorSetup::generateMirrorELF(const char *outputFile,
    const std::vector<Function *> &order) {

    auto sandbox = makeStaticExecutableSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto program = conductor->getProgram();

    auto generator = MirrorGen(program, backing);
    generator.preCodeGeneration();

    {
        ////moveCode(sandbox, true);  // calls sandbox->finalize()
        //moveCodeAssignAddresses(sandbox, true);
        Generator(sandbox, true).assignAddresses(conductor->getProgram(), order);
        generator.afterAddressAssign();
        {
            // get data sections; allow links to change bytes in data sections
            SegMap::mapAllSegments(this);
            ConductorPasses(conductor).newMirrorPasses(program);
        }
        //copyCodeToNewAddresses(sandbox, true);
        Generator(sandbox, true).generateCode(conductor->getProgram(), order);
        moveCodeMakeExecutable(sandbox);
    }

    //generator.generate(outputFile);
    generator.generateContent(outputFile);
    return true;
}

bool ConductorSetup::generateKernel(const char *outputFile) {
    auto sandbox = makeKernelSandbox(outputFile);
    auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
    auto program = conductor->getProgram();

    auto generator = KernelGen(program, backing);
    generator.preCodeGeneration();

    {
        //moveCode(sandbox, true);  // calls sandbox->finalize()
        moveCodeAssignAddresses(sandbox, true);
        generator.afterAddressAssign();
        if(0) {
            // get data sections; allow links to change bytes in data sections
            SegMap::mapAllSegments(this);
            ConductorPasses(conductor).newExecutablePasses(program);
        }
        copyCodeToNewAddresses(sandbox, true);
        moveCodeMakeExecutable(sandbox);
    }

    generator.generateContent(outputFile);
    return true;
}

void ConductorSetup::moveCode(Sandbox *sandbox, bool useDisps) {
    // 1. assign new addresses to all code
    moveCodeAssignAddresses(sandbox, useDisps);

    // 2. copy code to the new addresses
    copyCodeToNewAddresses(sandbox, useDisps);

    // 3. make code executable, or change permissions
    moveCodeMakeExecutable(sandbox);
}

void ConductorSetup::moveCodeAssignAddresses(Sandbox *sandbox, bool useDisps) {
    Generator(sandbox, useDisps).assignAddresses(conductor->getProgram());
}

void ConductorSetup::copyCodeToNewAddresses(Sandbox *sandbox, bool useDisps) {
    Generator(sandbox, useDisps).generateCode(conductor->getProgram());
}

void ConductorSetup::moveCodeMakeExecutable(Sandbox *sandbox) {
    sandbox->finalize();
}

void ConductorSetup::dumpElfSpace(ElfSpace *space) {
    ChunkDumper dumper;
    space->getModule()->accept(&dumper);
}

void ConductorSetup::dumpFunction(const char *function, ElfSpace *space) {
    Function *f = nullptr;
    if(space) {
        f = ChunkFind2(conductor)
            .findFunctionInModule(function, space->getModule());
    }
    else {
        f = ChunkFind2(conductor).findFunction(function);
    }

    ChunkDumper dumper;
    if(f) {
        f->accept(&dumper);
    }
    else {
        LOG(1, "Warning: can't find function [" << function << "] to dump");
    }
}

void ConductorSetup::findEntryPointFunction() {
    auto module = conductor->getProgram()->getMain();
    if(!module) return;
    address_t elfEntry = elf->getEntryPoint();

    if(auto f = CIter::spatial(module->getFunctionList())->find(elfEntry)) {
        LOG(0, "found entry function [" << f->getName() << "]");
        conductor->getProgram()->setEntryPoint(f);
    }
    else {
        LOG(0, "WARNING: can't find entry point!");
    }
}

address_t ConductorSetup::getEntryPoint() {
    return getConductor()->getProgram()->getEntryPointAddress();
}

bool ConductorSetup::setBaseAddress(Module *module, ElfMap *map, address_t base) {
    module->setBaseAddress(base);
    if(!map) {
        // If the map is not present, we loaded from an archive and should
        // assign a base address. However, we should not assign a base address
        // if the module is not position-independent. Module should store
        // whether it is position-independent in the future.
        return /*false*/ true;
    }

    if(map->isSharedLibrary()) {
        LOG(1, "set base address to " << std::hex << base);
        map->setBaseAddress(base);
        return true;
    }
    else {
        map->setBaseAddress(0);
    }

    return false;
}
