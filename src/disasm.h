#pragma once

#include <cstdint>
#include <string>

#include "memory.h"

namespace k0 {

struct DecodedInsn {
    uint16_t addr = 0;
    uint8_t length = 0;
    uint8_t bytes[4] = {};
    std::string mnemonic;
    std::string operands;
    bool valid = false;
    bool is_call = false;
    bool is_branch = false;
    bool is_stop_flow = false;  // ret, reti, retb, unconditional br, brk
    bool has_target = false;
    uint16_t target_addr = 0;

    std::string Format() const;
    std::string FormatWithBytes() const;
};

const char *LookupSfrName(uint16_t addr, MachineProfile profile = MachineProfile::Kx2);
DecodedInsn DisassembleAt(const K0Bus &bus, uint16_t addr);

}  // namespace k0
