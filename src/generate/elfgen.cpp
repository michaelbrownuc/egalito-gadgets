#include <set>
#include <cstring>
#include <fstream>
#include <sstream>  // for generating section names
#include <elf.h>
#include <sys/stat.h>  // for chmod
#include "elfgen.h"
#include "log/registry.h"
#include "log/log.h"

ElfGen::Metadata::Metadata() : segmentList(SEGMENT_TYPES),
    stringTableList(STRING_TABLE_TYPES) {
    int idx = SEGMENT_TYPES;
    while(idx-- >= 0)
        segmentList[idx] = new Segment();

    stringTableList[SH] = new Section(".shstrtab");
    stringTableList[DYN] = new Section(".dynstr");
    stringTableList[SYM] = new Section(".strtab");
}

ElfGen::Metadata::~Metadata() {
    for(auto segment : segmentList)
        delete segment;
}

ElfGen::ElfGen(ElfSpace *space, MemoryBacking *backing, std::string filename,
    const char *interpreter) : elfSpace(space), backing(backing),
    filename(filename), interpreter(interpreter) {
    // data = Metadata();
    if(!interpreter) {
        this->interpreter = space->getElfMap()->getInterpreter();
    }
}

void ElfGen::generate() {
    // {  // add null entry to shdr list
    //     Section nullSection("");
    //     addShdr(&nullSection, SHT_NULL);
    // }

    makeHeader();
    makeRWData();
    makeText();
    makeSymbolInfo();
    if(elfSpace->getElfMap()->isDynamic()) {
        // makeDynamicSymbolInfo();
        // makePLT();
        // makeDynamic();
        // dynamicSegment->setAddress(getNextFreeAddress(VISIBLESegment));
        // dynamicSegment->setFileOff(getNextFreeOffset());
    }
    // phdrTableSegment->setAddress(getNextFreeAddress(dynamicSegment));
    // phdrTableSegment->setFileOff(getNextFreeOffset());
    // LOG(1, "Next free addr: " << getNextFreeAddress(phdrTableSegment));
    // hiddenSegment->setFileOff(getNextFreeOffset());
    updateOffsetAndAddress();
    makeShdrTable();
    makePhdrTable();
    updateHeader();

    // Write to file
    std::ofstream fs(filename, std::ios::out | std::ios::binary);
    for(auto segment : data.getSegmentList()) {
        if(segment->getSections().size() == 0)
            continue; // HERE
        LOG(1, "serialize segment at " << segment->getFirstSection()->getName());
        fs << *segment;
    }
    fs.close();

    chmod(filename.c_str(), 0755);
}

void ElfGen::makeRWData() {// Elf Header
    auto elfMap = elfSpace->getElfMap();
    Elf64_Phdr *rodata = nullptr;
    Elf64_Phdr *rwdata = nullptr;
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<Elf64_Phdr *>(original);
        if(segment->p_type == PT_LOAD) {
            if(segment->p_flags == (PF_R | PF_X)) rodata = segment;
            if(segment->p_flags == (PF_R | PF_W)) rwdata = segment;
        }
    }
    // Read Write data
    if(rwdata) {  // some executables may have no data to load!
        char *loadRWVirtualAdress = elfMap->getCharmap() + rodata->p_offset; // HERE
        data[Metadata::RWDATA]->add(new Section(".old_rw", static_cast<void *>(loadRWVirtualAdress), rwdata->p_memsz));
        data[Metadata::RWDATA]->setFileOff(rwdata->p_offset);
        data[Metadata::RWDATA]->setAddress(rwdata->p_vaddr);
        data[Metadata::RWDATA]->setPhdrInfo(rwdata->p_type, rwdata->p_flags, rwdata->p_align);
    }
}

void ElfGen::makeText() {
    size_t loadOffset = getNextFreeOffset();
    loadOffset += 0xfff - ((loadOffset + 0xfff) & 0xfff);

    // split separate pages into their own LOAD sections
    std::set<address_t> pagesUsed;
    for(auto func : CIter::functions(elfSpace->getModule())) {
        address_t start = func->getAddress() & ~0xfff;
        address_t end = ((func->getAddress() + func->getSize()) + 0xfff) & ~0xfff;
        for(address_t page = start; page < end; page += 0x1000) {
            LOG(1, "code uses page " << std::hex << page);
            pagesUsed.insert(page);
        }
    }

    std::set<address_t>::iterator i = pagesUsed.begin();
    size_t totalSize = 0;
    while(i != pagesUsed.end()) {
        size_t size = 0;
        std::set<address_t>::iterator j = i;
        while(j != pagesUsed.end() && (*j) == (*i) + size) {
            j++;
            size += 0x1000;
        }

        LOG(1, "map " << std::hex << *i << " size " << size);

        // intentionally leave VISIBLE Segment set after last iteration
        data[Metadata::VISIBLE]->setAddress(backing->getBase() + totalSize);
        data[Metadata::VISIBLE]->setFileOff(loadOffset + totalSize);
        data[Metadata::VISIBLE]->setPhdrInfo(PT_LOAD, PF_R | PF_X, 0x1000);
        std::ostringstream sectionName;
        sectionName << ".text.0x" << std::hex << *i;
        auto textSection = new Section(sectionName.str().c_str(), (const uint8_t *)*i, size);
        data[Metadata::VISIBLE]->add(textSection);

        totalSize += size;
        i = j;
    }

    // Interp
    auto elfMap = elfSpace->getElfMap();
    if(elfMap->isDynamic()) {
        Section *interpSection = new Section(".interp", elfMap->getInterpreter(), std::strlen(interpreter) + 1);
        data[Metadata::INTERP]->add(interpSection);
        data[Metadata::INTERP]->setPhdrInfo(PT_INTERP, PF_R, 0x1);
        // data[Metadata::INTERP]->setAddress();

        data[Metadata::VISIBLE]->add(interpSection);
    }
}

void ElfGen::makeSymbolInfo() {
    // Symbol Table
    Section *symtab = new Section(".symtab");

    std::vector<char> strtabData;
    size_t count = 0;
    {  // add null symbol
        strtabData.push_back('\0');
        Elf64_Sym symbol;
        symbol.st_name = 0;
        symbol.st_info = 0;
        symbol.st_other = STV_DEFAULT;
        symbol.st_shndx = 0;
        symbol.st_value = 0;
        symbol.st_size = 0;
        symtab->add(static_cast<void *>(&symbol), sizeof(symbol));
        count ++;
    }

    for(auto func : CIter::functions(elfSpace->getModule())) {
        // add name to string table
        auto name = func->getName();
        auto index = strtabData.size();
        strtabData.insert(strtabData.end(), name.begin(), name.end());
        strtabData.push_back('\0');

        // generate new Symbol from new address
        Elf64_Sym sym = generateSymbol(func, func->getSymbol(), index);
        symtab->add(static_cast<void *>(&sym), sizeof(sym));
        count ++;

        for(auto alias : func->getSymbol()->getAliases()) {
            // add name to string table
            auto name = std::string(alias->getName());
            auto index = strtabData.size();
            strtabData.insert(strtabData.end(), name.begin(), name.end());
            strtabData.push_back('\0');

            // generate new Symbol from new address
            Elf64_Sym sym = generateSymbol(func, alias, index);
            symtab->add(static_cast<void *>(&sym), sizeof(sym));
            count ++;
        }
    }

    data.getStrTable(Metadata::SYM)->add(strtabData.data(), strtabData.size());

    data[Metadata::HIDDEN]->add(symtab);
    data[Metadata::HIDDEN]->add(data.getStrTable(Metadata::SYM));

    // HERE
    // int strtab_id = addShdr(strtab, SHT_STRTAB);
    // addShdr(symtab, SHT_SYMTAB, strtab_id);
    // data.getLastShdr().second->sh_info = count;
}
#if 0
void ElfGen::makeDynamicSymbolInfo() {
    // Symbol Table
    Section *dsymtab = new Section(".dsymtab");
    std::vector<char> dstrtabData = {'\0'};
    for(auto symbol : *elfSpace->getDynamicSymbolList()) {
        // add name to string table
        std::string name = symbol->getName();
        auto index = dstrtabData.size();
        dstrtabData.insert(dstrtabData.end(), name.begin(), name.end());
        dstrtabData.push_back('\0');

        // generate new Symbol from new address
        Elf64_Sym sym = generateSymbol(nullptr, symbol, index);
        dsymtab->add(static_cast<void *>(&sym), sizeof(sym));
    }

    data.getStrTable(Metadata::DYN)->add(dstrtabData.data(), dstrtabData.size());

    data[Metadata::HIDDEN]->add(dsymtab);
    data[Metadata::HIDDEN]->add(data.getStrTable(Metadata::DYN));

    // HERE
    // int dstrtab_id = addShdr(dstrtab, SHT_STRTAB);
    // addShdr(dsymtab, SHT_DYNSYM, dstrtab_id);
}

void ElfGen::makePLT() {
    auto elfMap = elfSpace->getElfMap();

    Elf64_Shdr *pltShdr = new Elf64_Shdr();
    memcpy(pltShdr, elfMap->findSectionHeader(".plt"), sizeof(Elf64_Shdr));
    pltShdr->sh_name = data.getShdrListSize();
    Section *pltSection = new Section(".plt");
    data.addShdr(pltSection, pltShdr);

    Elf64_Shdr *relaPltShdr = new Elf64_Shdr();
    memcpy(relaPltShdr, elfMap->findSectionHeader(".rela.plt"), sizeof(Elf64_Shdr));
    relaPltShdr->sh_name = data.getShdrListSize();
    Section *relaPltSection = new Section(".rela.plt");
    data.addShdr(relaPltSection, relaPltShdr);
}

void ElfGen::makeDynamic() {
    dynamicSegment = new Segment();
    Section *dynamicSection = new Section(".dynamic");

    std::vector<Elf64_Dyn> dynamicData;
    auto elfMap = elfSpace->getElfMap();
    Elf64_Phdr *oldDynamic = nullptr;
    for(auto original : elfMap->getSegmentList()) {
        auto segment = static_cast<Elf64_Phdr *>(original);
        if(segment->p_type == PT_DYNAMIC) {
            oldDynamic = segment;
            break;
        }
    }
    unsigned long *oldList = reinterpret_cast<unsigned long *>(
        elfMap->getCopyBaseAddress() + oldDynamic->p_offset);
    while(oldList[0] != DT_NULL) {
        Elf64_Sxword tag = oldList[0];
        auto value = oldList[1];
        if(tag == DT_NEEDED) {
            const char *lib = elfMap->getDynstrtab() + value;
            LOG(1, "I think the lib is [" << lib << "]");
            auto index = dstrtab->getSize();
            dstrtab->add(lib, std::strlen(lib) + 1);

            dynamicData.push_back({tag, index});
        }
        oldList += 2;
    }
    dynamicData.push_back({DT_NULL, 0});
    dynamicSection->add(static_cast<void *>(dynamicData.data()),
        dynamicData.size() * sizeof(Elf64_Dyn));

    dynamicSegment->add(dynamicSection);
    addShdr(dynamicSection, SHT_DYNAMIC);
    addSegment(dynamicSegment, PT_DYNAMIC, PF_R | PF_W, 0x8);
}
#endif

void ElfGen::makePhdrTable() {
    // Note: we overwrite the previous phdrs list. This only works if we have
    // at most as many entries as were originally present.
    data[Metadata::PHDR_TABLE]->setPhdrInfo(PT_PHDR, PF_R | PF_X, 8);
    data[Metadata::PHDR_TABLE]->setFileOff(sizeof(Elf64_Ehdr));
    data[Metadata::PHDR_TABLE]->setAddress(0);
    std::vector<Elf64_Phdr *> phdrList;
    for(auto seg : data.getSegmentList()) {
        if(seg == data[Metadata::HIDDEN] || seg == data[Metadata::HEADER]) continue;
        phdrList.push_back(seg->makePhdr());
    }
    Section *phdrTable = new Section(".phdr_table");
    {
        Elf64_Phdr *entry = phdrList[0];  // assume first phdr is the PHDR entry
        entry->p_memsz = (phdrList.size() + 1) * sizeof(Elf64_Phdr);
        entry->p_filesz = entry->p_memsz;
    }
    for(auto phdr : phdrList) {
        phdrTable->add(static_cast<void *>(phdr), sizeof(Elf64_Phdr));
    }
    data[Metadata::PHDR_TABLE]->add(phdrTable);
    data[Metadata::PHDR_TABLE]->setPhdrInfo(PT_PHDR, PF_R | PF_X, 0x8);
}

void ElfGen::makeShdrTable() {
    // Allocate new space for the shdrs, and don't map them into memory.
    // NOTE: shstrtab must be the last section in the ELF (to set e_shstrndx).
    // addShdr(shstrtab, SHT_STRTAB);
    auto shdrTable = new Section(".shdr_table");
    for(auto seg : data.getSegmentList()) {
        for(auto sec : seg->getSections()) {
            if(sec->hasShdr()) {
                shdrTable->add(sec->makeShdr(0), sizeof(Elf64_Shdr)); // HERE
                data.getStrTable(Metadata::SH)->add(sec->getName().c_str(),
                    sec->getName().size() + 1);
            }
        }
    }
    // HERE
    // modify sh string table location in file
    // data.getLastShdr().second->sh_size = shstrtab->getSize();
    // data.getLastShdr().second->sh_offset = getNextFreeOffset(); // HERE
    data[Metadata::HIDDEN]->add(data.getStrTable(Metadata::SH));
    data[Metadata::HIDDEN]->add(shdrTable);
    data[Metadata::HIDDEN]->add(shdrTable);
}

void ElfGen::makeHeader() { // NEEDS TO BE UPDATED
    // Elf Header
    auto elfMap = elfSpace->getElfMap();
    data[Metadata::HEADER]->setFileOff(0);
    data[Metadata::HEADER]->setAddress(0);
    data[Metadata::HEADER]->add(new Section(".elfheader", elfMap->getMap(), sizeof(Elf64_Ehdr)));
    // Update entry point in existing segment
    Elf64_Ehdr *header = data[Metadata::HEADER]->getFirstSection()->castAs<Elf64_Ehdr>();
    address_t entry_pt = 0;
    if(auto start = CIter::named(elfSpace->getModule()->getFunctionList())
        ->find("_start")) {

        entry_pt = elfSpace->getElfMap()->getBaseAddress()
            + start->getAddress();
    }
    header->e_entry = entry_pt;
}

void ElfGen::updateOffsetAndAddress() {
    size_t idx = 0;
    while(++idx < Metadata::SEGMENT_TYPES) {
        auto t = static_cast<Metadata::SegmentType>(idx);
        auto prevT = static_cast<Metadata::SegmentType>(idx - 1);
        if(data[t]->getFileOff() == 0) {
            data[t]->setFileOff(getNextFreeOffset());
        }
        if(data[t]->getAddress() == 0) {
            if(t != Metadata::HIDDEN) // Do not update the address
                data[t]->setAddress(getNextFreeAddress(data[prevT]));
        }
    }
}

void ElfGen::updateHeader() {
    Elf64_Ehdr *header = data[Metadata::HEADER]->getFirstSection()->castAs<Elf64_Ehdr>();
    header->e_phoff = data[Metadata::PHDR_TABLE]->getFileOff();
    header->e_phnum = data[Metadata::PHDR_TABLE]->getFirstSection()->getSize() / sizeof(Elf64_Phdr);
    Section *shdrTable = data[Metadata::HIDDEN]->findSection(".shdr_table");
    header->e_shoff = shdrTable->getFileOff(); // HERE
    header->e_shnum = shdrTable->getSize() / sizeof(Elf64_Shdr); // HERE
    // header->e_shstrndx = data.getShdrListSize() - 1;  // assume .shstrtab is last // HERE
}

size_t ElfGen::getNextFreeOffset() {
    size_t maxOffset = 0;
    for(auto seg : data.getSegmentList()) {
        auto offset = seg->getFileOff() + seg->getSize();
        if(offset > maxOffset) maxOffset = offset;
    }
    return maxOffset;
}

address_t ElfGen::getNextFreeAddress(Segment *segment) {
    address_t maxAddress = 0;
    for(auto sec : segment->getSections()) {
        auto address = sec->getAddress() + sec->getSize();
        if(address > maxAddress) maxAddress = address;
    }
    return maxAddress;
}

Elf64_Sym ElfGen::generateSymbol(Function *func, Symbol *sym, size_t strtabIndex) {
    Elf64_Sym symbol;
    symbol.st_name = static_cast<Elf64_Word>(strtabIndex);
    symbol.st_info = ELF64_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_other = STV_DEFAULT;
    symbol.st_shndx = func ? 1 : 3;  // dynamic symbols have func==nullptr
    symbol.st_value = func ? func->getAddress() : 0;
    symbol.st_size = func ? func->getSize() : 0;
    return std::move(symbol);
}
