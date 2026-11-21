#include "disasm.h"

#include <cstdio>

namespace k0 {

namespace {

const char *const kReg8Names[8] = { "X", "A", "C", "B", "E", "D", "L", "H" };
const char *const kReg16Names[4] = { "AX", "BC", "DE", "HL" };
const char *const kAluMnemonics[8] = { "add", "sub", "addc", "subc", "cmp", "and", "or", "xor" };

inline uint16_t ReadWordAt(const K0Bus &bus, uint16_t addr) {
    const uint8_t lo = bus.PeekByte(addr);
    const uint8_t hi = bus.PeekByte(static_cast<uint16_t>(addr + 1u));
    return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
}

inline uint16_t DecodeSaddr(uint8_t off) {
    return static_cast<uint16_t>(off < 0x20u ? (0xFF00u + off) : (0xFE00u + off));
}

inline uint16_t ResolveRel(uint16_t next_pc, uint8_t disp) {
    return static_cast<uint16_t>(static_cast<int32_t>(next_pc) + static_cast<int8_t>(disp));
}

std::string Hex8(uint8_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0%02Xh", v);
    return buf;
}

std::string Hex16(uint16_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0%04Xh", v);
    return buf;
}

std::string FormatSfrOrAddr(const K0Bus &bus, uint16_t addr) {
    if (addr == 0xFF1Cu) return "SP";
    if (addr == 0xFF1Eu) return "PSW";
    if (const char *nm = LookupSfrName(addr, bus.Profile())) {
        return nm;
    }
    return Hex16(addr);
}

std::string FormatSaddr(const K0Bus &bus, uint8_t off) {
    const uint16_t addr = DecodeSaddr(off);
    if (addr == 0xFF1Eu) return "PSW";
    if (addr >= 0xFF00u) {
        if (const char *nm = LookupSfrName(addr, bus.Profile())) {
            return nm;
        }
    }
    return Hex16(addr);
}

std::string FormatSaddrSp(const K0Bus &bus, uint8_t off) {
    const uint16_t addr = DecodeSaddr(off);
    if (addr == 0xFF1Cu) return "SP";
    return FormatSaddr(bus, off);
}

std::string FormatBitSaddr(const K0Bus &bus, uint8_t off, uint8_t bit) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s.%u", FormatSaddr(bus, off).c_str(), bit & 7u);
    return buf;
}

std::string FormatBitSfr(const K0Bus &bus, uint8_t off, uint8_t bit) {
    char buf[64];
    const uint16_t addr = static_cast<uint16_t>(0xFF00u + off);
    std::snprintf(buf, sizeof(buf), "%s.%u", FormatSfrOrAddr(bus, addr).c_str(), bit & 7u);
    return buf;
}

}  // namespace

const char *LookupSfrName(uint16_t addr, MachineProfile profile) {
    if (addr < 0xFF00u) return nullptr;
    if (profile == MachineProfile::Legacy0831) {
        switch (addr) {
        case 0xFF00u: return "P0";
        case 0xFF01u: return "P1";
        case 0xFF02u: return "P2";
        case 0xFF03u: return "P3";
        case 0xFF04u: return "P4";
        case 0xFF05u: return "P5";
        case 0xFF06u: return "P6";
        case 0xFF07u: return "P7";
        case 0xFF08u: return "P8";
        case 0xFF09u: return "P9";
        case 0xFF17u: return "ADCR00";
        case 0xFF1Au: return "SIO30";
        case 0xFF1Bu: return "SIO31";
        case 0xFF1Cu: return "SPL";
        case 0xFF1Du: return "SPH";
        case 0xFF1Eu: return "PSW";
        case 0xFF1Fu: return "IIC0";
        case 0xFF41u: return "WTNM0";
        case 0xFF42u: return "WDCS";
        case 0xFF80u: return "ADM00";
        case 0xFF81u: return "ADS00";
        case 0xFFA8u: return "IICC0";
        case 0xFFA9u: return "IICS0";
        case 0xFFAAu: return "IICCL0";
        case 0xFFB0u: return "CSIM30";
        case 0xFFB8u: return "CSIM31";
        case 0xFFE0u: return "IF0L";
        case 0xFFE1u: return "IF0H";
        case 0xFFE2u: return "IF1L";
        case 0xFFE3u: return "IF1H";
        case 0xFFE4u: return "MK0L";
        case 0xFFE5u: return "MK0H";
        case 0xFFE6u: return "MK1L";
        case 0xFFE7u: return "MK1H";
        case 0xFFE8u: return "PR0L";
        case 0xFFE9u: return "PR0H";
        case 0xFFEAu: return "PR1L";
        case 0xFFEBu: return "PR1H";
        case 0xFFF9u: return "WDTM";
        default: return nullptr;
        }
    }

    switch (addr) {
    case 0xFF00u: return "P0";
    case 0xFF01u: return "P1";
    case 0xFF02u: return "P2";
    case 0xFF03u: return "P3";
    case 0xFF04u: return "P4";
    case 0xFF05u: return "P5";
    case 0xFF06u: return "P6";
    case 0xFF07u: return "P7";
    case 0xFF08u: return "ADCR";
    case 0xFF09u: return "ADCRH";
    case 0xFF0Au: return "RXB6";
    case 0xFF0Bu: return "TXB6";
    case 0xFF0Cu: return "P12";
    case 0xFF0Du: return "P13";
    case 0xFF0Eu: return "P14";
    case 0xFF0Fu: return "SIO10";
    case 0xFF10u: return "TM00";
    case 0xFF12u: return "CR000";
    case 0xFF14u: return "CR010";
    case 0xFF16u: return "TM50";
    case 0xFF17u: return "CR50";
    case 0xFF18u: return "CMP00";
    case 0xFF19u: return "CMP10";
    case 0xFF1Au: return "CMP01";
    case 0xFF1Bu: return "CMP11";
    case 0xFF1Cu: return "SPL";
    case 0xFF1Du: return "SPH";
    case 0xFF1Eu: return "PSW";
    case 0xFF1Fu: return "TM51";
    case 0xFF20u: return "PM0";
    case 0xFF21u: return "PM1";
    case 0xFF22u: return "PM2";
    case 0xFF23u: return "PM3";
    case 0xFF24u: return "PM4";
    case 0xFF25u: return "PM5";
    case 0xFF26u: return "PM6";
    case 0xFF27u: return "PM7";
    case 0xFF28u: return "ADM";
    case 0xFF29u: return "ADS";
    case 0xFF2Cu: return "PM12";
    case 0xFF2Eu: return "PM14";
    case 0xFF2Fu: return "ADPC";
    case 0xFF30u: return "PU0";
    case 0xFF31u: return "PU1";
    case 0xFF33u: return "PU3";
    case 0xFF34u: return "PU4";
    case 0xFF35u: return "PU5";
    case 0xFF36u: return "PU6";
    case 0xFF37u: return "PU7";
    case 0xFF3Cu: return "PU12";
    case 0xFF3Eu: return "PU14";
    case 0xFF40u: return "CKS";
    case 0xFF41u: return "CR51";
    case 0xFF43u: return "TMC51";
    case 0xFF48u: return "EGP";
    case 0xFF49u: return "EGN";
    case 0xFF4Au: return "SIO11";
    case 0xFF4Cu: return "SOTB11";
    case 0xFF4Fu: return "ISC";
    case 0xFF50u: return "ASIM6";
    case 0xFF53u: return "ASIS6";
    case 0xFF55u: return "ASIF6";
    case 0xFF56u: return "CKSR6";
    case 0xFF57u: return "BRGC6";
    case 0xFF58u: return "ASICL6";
    case 0xFF60u: return "SDR0L";
    case 0xFF61u: return "SDR0H";
    case 0xFF62u: return "MDA0LL";
    case 0xFF63u: return "MDA0LH";
    case 0xFF64u: return "MDA0HL";
    case 0xFF65u: return "MDA0HH";
    case 0xFF66u: return "MDB0L";
    case 0xFF67u: return "MDB0H";
    case 0xFF68u: return "DMUC0";
    case 0xFF69u: return "TMHMD0";
    case 0xFF6Au: return "TCL50";
    case 0xFF6Bu: return "TMC50";
    case 0xFF6Cu: return "TMHMD1";
    case 0xFF6Du: return "TMCYC1";
    case 0xFF6Eu: return "KRM";
    case 0xFF6Fu: return "WTM";
    case 0xFF70u: return "ASIM0";
    case 0xFF71u: return "BRGC0";
    case 0xFF72u: return "RXB0";
    case 0xFF73u: return "ASIS0";
    case 0xFF74u: return "TXS0";
    case 0xFF80u: return "CSIM10";
    case 0xFF81u: return "CSIC10";
    case 0xFF84u: return "SOTB10";
    case 0xFF88u: return "CSIM11";
    case 0xFF89u: return "CSIC11";
    case 0xFF8Cu: return "TCL51";
    case 0xFF99u: return "WDTE";
    case 0xFF9Fu: return "OSCCTL";
    case 0xFFA0u: return "RCM";
    case 0xFFA1u: return "MCM";
    case 0xFFA2u: return "MOC";
    case 0xFFA3u: return "OSTC";
    case 0xFFA4u: return "OSTS";
    case 0xFFA5u: return "IIC0";
    case 0xFFA6u: return "IICC0";
    case 0xFFA7u: return "SVA0";
    case 0xFFA8u: return "IICCL0";
    case 0xFFA9u: return "IICX0";
    case 0xFFAAu: return "IICS0";
    case 0xFFABu: return "IICF0";
    case 0xFFACu: return "RESF";
    case 0xFFB0u: return "TM01";
    case 0xFFB2u: return "CR001";
    case 0xFFB4u: return "CR011";
    case 0xFFB6u: return "TMC01";
    case 0xFFB7u: return "PRM01";
    case 0xFFB8u: return "CRC01";
    case 0xFFB9u: return "TOC01";
    case 0xFFBAu: return "TMC00";
    case 0xFFBBu: return "PRM00";
    case 0xFFBCu: return "CRC00";
    case 0xFFBDu: return "TOC00";
    case 0xFFBEu: return "LVIM";
    case 0xFFBFu: return "LVIS";
    case 0xFFC0u: return "PFCMD";
    case 0xFFC1u: return "FLM0";
    case 0xFFC4u: return "FLPMC";
    case 0xFFC5u: return "FLCTL";
    case 0xFFC6u: return "FLADRH";
    case 0xFFC7u: return "FLSTS";
    case 0xFFC8u: return "FLADRL";
    case 0xFFC9u: return "FLADRM";
    case 0xFFCAu: return "FLREG";
    case 0xFFE0u: return "IF0L";
    case 0xFFE1u: return "IF0H";
    case 0xFFE2u: return "IF1L";
    case 0xFFE3u: return "IF1H";
    case 0xFFE4u: return "MK0L";
    case 0xFFE5u: return "MK0H";
    case 0xFFE6u: return "MK1L";
    case 0xFFE7u: return "MK1H";
    case 0xFFE8u: return "PR0L";
    case 0xFFE9u: return "PR0H";
    case 0xFFEAu: return "PR1L";
    case 0xFFEBu: return "PR1H";
    case 0xFFF0u: return "IMS";
    case 0xFFF3u: return "BANK";
    case 0xFFF4u: return "IXS";
    case 0xFFF5u: return "PROD";
    case 0xFFFBu: return "PCC";
    default: return nullptr;
    }
}

std::string DecodedInsn::Format() const {
    if (!valid) {
        return "???";
    }
    if (operands.empty()) {
        return mnemonic;
    }
    std::string padded = mnemonic;
    while (padded.size() < 8) {
        padded.push_back(' ');
    }
    return padded + operands;
}

std::string DecodedInsn::FormatWithBytes() const {
    char hex[20] = {};
    size_t pos = 0;
    for (uint8_t i = 0; i < length && i < 4; ++i) {
        pos += static_cast<size_t>(std::snprintf(hex + pos, sizeof(hex) - pos, "%02X ", bytes[i]));
    }
    while (pos < 12) {
        hex[pos++] = ' ';
    }
    hex[pos] = '\0';

    char line[160];
    std::snprintf(line, sizeof(line), "%04X: %s %s", addr, hex, Format().c_str());
    return line;
}

DecodedInsn DisassembleAt(const K0Bus &bus, uint16_t addr) {
    DecodedInsn out;
    out.addr = addr;

    auto fetch = [&](uint8_t off) -> uint8_t {
        const uint8_t b = bus.PeekByte(static_cast<uint16_t>(addr + off));
        if (off < 4) {
            out.bytes[off] = b;
        }
        return b;
    };
    auto set_len = [&](uint8_t len) {
        out.length = len;
        for (uint8_t i = 0; i < len && i < 4; ++i) {
            out.bytes[i] = bus.PeekByte(static_cast<uint16_t>(addr + i));
        }
    };
    auto word_at = [&](uint8_t off) -> uint16_t {
        return ReadWordAt(bus, static_cast<uint16_t>(addr + off));
    };

    const uint8_t op = fetch(0);

    // 0x31 prefixed
    if (op == 0x31u) {
        const uint8_t op2 = fetch(1);
        const uint8_t nib = op2 >> 4;
        const uint8_t lo = op2 & 0x0Fu;

        if ((op2 & 0x80u) == 0 && (lo == 0x0Au || lo == 0x0Bu)) {
            set_len(2);
            out.valid = true;
            out.mnemonic = kAluMnemonics[nib];
            out.operands = (lo == 0x0Au) ? "A, [HL+C]" : "A, [HL+B]";
            return out;
        }
        switch (op2) {
        case 0x80u: set_len(2); out.valid = true; out.mnemonic = "rol4"; out.operands = "[HL]"; return out;
        case 0x90u: set_len(2); out.valid = true; out.mnemonic = "ror4"; out.operands = "[HL]"; return out;
        case 0x82u: set_len(2); out.valid = true; out.mnemonic = "divuw"; out.operands = "C"; return out;
        case 0x88u: set_len(2); out.valid = true; out.mnemonic = "mulu"; out.operands = "X"; return out;
        case 0x8Au: set_len(2); out.valid = true; out.mnemonic = "xch"; out.operands = "A, [HL+C]"; return out;
        case 0x8Bu: set_len(2); out.valid = true; out.mnemonic = "xch"; out.operands = "A, [HL+B]"; return out;
        case 0x98u: set_len(2); out.valid = true; out.mnemonic = "br"; out.operands = "AX"; out.is_branch = true; out.is_stop_flow = true; return out;
        default: break;
        }

        const uint8_t bit = nib & 7u;
        const char *br_mnem = nullptr;
        switch (op2 & 0x8Fu) {
        case 0x01u: br_mnem = "btclr"; break;
        case 0x03u: br_mnem = "bf"; break;
        case 0x05u: br_mnem = "btclr"; break;
        case 0x06u: br_mnem = "bt"; break;
        case 0x07u: br_mnem = "bf"; break;
        case 0x0Du: br_mnem = "btclr"; break;
        case 0x0Eu: br_mnem = "bt"; break;
        case 0x0Fu: br_mnem = "bf"; break;
        case 0x85u: br_mnem = "btclr"; break;
        case 0x86u: br_mnem = "bt"; break;
        case 0x87u: br_mnem = "bf"; break;
        default:
            set_len(2);
            out.valid = false;
            out.mnemonic = "db";
            out.operands = Hex8(op);
            return out;
        }

        out.valid = true;
        out.mnemonic = br_mnem;
        out.is_branch = true;
        out.has_target = true;

        char buf[64];
        if ((op2 & 0x8Fu) <= 0x07u && (op2 & 0x0Fu) != 0x05u && (op2 & 0x0Fu) != 0x06u && (op2 & 0x0Fu) != 0x07u) {
            // saddr.bit (0x01, 0x03)
            set_len(4);
            const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 4u), fetch(3));
            out.target_addr = tgt;
            std::snprintf(buf, sizeof(buf), "%s, $%s", FormatBitSaddr(bus, fetch(2), bit).c_str(), Hex16(tgt).c_str());
        } else if ((op2 & 0x8Fu) <= 0x07u) {
            // sfr.bit (0x05, 0x06, 0x07)
            set_len(4);
            const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 4u), fetch(3));
            out.target_addr = tgt;
            std::snprintf(buf, sizeof(buf), "%s, $%s", FormatBitSfr(bus, fetch(2), bit).c_str(), Hex16(tgt).c_str());
        } else if ((op2 & 0x80u) == 0) {
            // A.bit (0x0D, 0x0E, 0x0F)
            set_len(3);
            const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 3u), fetch(2));
            out.target_addr = tgt;
            std::snprintf(buf, sizeof(buf), "A.%u, $%s", bit, Hex16(tgt).c_str());
        } else {
            // [HL].bit (0x85, 0x86, 0x87)
            set_len(3);
            const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 3u), fetch(2));
            out.target_addr = tgt;
            std::snprintf(buf, sizeof(buf), "[HL].%u, $%s", bit, Hex16(tgt).c_str());
        }
        out.operands = buf;
        return out;
    }

    // 0x61 prefixed
    if (op == 0x61u) {
        const uint8_t op2 = fetch(1);
        set_len(2);
        if (op2 == 0xD0u || op2 == 0xD8u || op2 == 0xF0u || op2 == 0xF8u) {
            const uint8_t rb = static_cast<uint8_t>(((op2 >> 4) & 0x02u) | ((op2 >> 3) & 0x01u));
            out.valid = true;
            out.mnemonic = "sel";
            out.operands = "RB" + std::to_string(rb);
            return out;
        }
        if (op2 == 0x80u) {
            out.valid = true;
            out.mnemonic = "adjba";
            return out;
        }
        if (op2 == 0x90u) {
            out.valid = true;
            out.mnemonic = "adjbs";
            return out;
        }
        if ((op2 & 0x80u) == 0) {
            const uint8_t alu = (op2 >> 4) & 7u;
            const uint8_t reg = op2 & 7u;
            const bool a_dst = (op2 & 0x08u) != 0;
            if (a_dst && reg == 1u) {
                out.valid = false;
                out.mnemonic = "db";
                out.operands = Hex8(op);
                return out;
            }
            out.valid = true;
            out.mnemonic = kAluMnemonics[alu];
            out.operands = a_dst ? (std::string("A, ") + kReg8Names[reg])
                                 : (std::string(kReg8Names[reg]) + ", A");
            return out;
        }
        const uint8_t bit = (op2 >> 4) & 7u;
        char buf[32];
        switch (op2 & 0x0Fu) {
        case 0x09u: out.valid = true; out.mnemonic = "mov1"; std::snprintf(buf, sizeof(buf), "A.%u, CY", bit); out.operands = buf; return out;
        case 0x0Au: out.valid = true; out.mnemonic = "set1"; std::snprintf(buf, sizeof(buf), "A.%u", bit); out.operands = buf; return out;
        case 0x0Bu: out.valid = true; out.mnemonic = "clr1"; std::snprintf(buf, sizeof(buf), "A.%u", bit); out.operands = buf; return out;
        case 0x0Cu: out.valid = true; out.mnemonic = "mov1"; std::snprintf(buf, sizeof(buf), "CY, A.%u", bit); out.operands = buf; return out;
        case 0x0Du: out.valid = true; out.mnemonic = "and1"; std::snprintf(buf, sizeof(buf), "CY, A.%u", bit); out.operands = buf; return out;
        case 0x0Eu: out.valid = true; out.mnemonic = "or1";  std::snprintf(buf, sizeof(buf), "CY, A.%u", bit); out.operands = buf; return out;
        case 0x0Fu: out.valid = true; out.mnemonic = "xor1"; std::snprintf(buf, sizeof(buf), "CY, A.%u", bit); out.operands = buf; return out;
        default:
            out.valid = false;
            out.mnemonic = "db";
            out.operands = Hex8(op);
            return out;
        }
    }

    // 0x71 prefixed
    if (op == 0x71u) {
        const uint8_t op2 = fetch(1);
        const uint8_t bit = (op2 >> 4) & 7u;
        if (op2 == 0x00u) {
            set_len(2);
            out.valid = true;
            out.mnemonic = "stop";
            return out;
        }
        if (op2 == 0x10u) {
            set_len(2);
            out.valid = true;
            out.mnemonic = "halt";
            return out;
        }
        char buf[64];
        if ((op2 & 0x80u) != 0) {
            set_len(2);
            switch (op2 & 0x0Fu) {
            case 0x01u: out.valid = true; out.mnemonic = "mov1"; std::snprintf(buf, sizeof(buf), "[HL].%u, CY", bit); out.operands = buf; return out;
            case 0x02u: out.valid = true; out.mnemonic = "set1"; std::snprintf(buf, sizeof(buf), "[HL].%u", bit); out.operands = buf; return out;
            case 0x03u: out.valid = true; out.mnemonic = "clr1"; std::snprintf(buf, sizeof(buf), "[HL].%u", bit); out.operands = buf; return out;
            case 0x04u: out.valid = true; out.mnemonic = "mov1"; std::snprintf(buf, sizeof(buf), "CY, [HL].%u", bit); out.operands = buf; return out;
            case 0x05u: out.valid = true; out.mnemonic = "and1"; std::snprintf(buf, sizeof(buf), "CY, [HL].%u", bit); out.operands = buf; return out;
            case 0x06u: out.valid = true; out.mnemonic = "or1";  std::snprintf(buf, sizeof(buf), "CY, [HL].%u", bit); out.operands = buf; return out;
            case 0x07u: out.valid = true; out.mnemonic = "xor1"; std::snprintf(buf, sizeof(buf), "CY, [HL].%u", bit); out.operands = buf; return out;
            default: out.valid = false; out.mnemonic = "db"; out.operands = Hex8(op); return out;
            }
        }
        set_len(3);
        const uint8_t target = fetch(2);
        switch (op2 & 0x0Fu) {
        case 0x01u: out.valid = true; out.mnemonic = "mov1"; out.operands = FormatBitSaddr(bus, target, bit) + ", CY"; return out;
        case 0x04u: out.valid = true; out.mnemonic = "mov1"; out.operands = "CY, " + FormatBitSaddr(bus, target, bit); return out;
        case 0x05u: out.valid = true; out.mnemonic = "and1"; out.operands = "CY, " + FormatBitSaddr(bus, target, bit); return out;
        case 0x06u: out.valid = true; out.mnemonic = "or1";  out.operands = "CY, " + FormatBitSaddr(bus, target, bit); return out;
        case 0x07u: out.valid = true; out.mnemonic = "xor1"; out.operands = "CY, " + FormatBitSaddr(bus, target, bit); return out;
        case 0x09u: out.valid = true; out.mnemonic = "mov1"; out.operands = FormatBitSfr(bus, target, bit) + ", CY"; return out;
        case 0x0Au: out.valid = true; out.mnemonic = "set1"; out.operands = FormatBitSfr(bus, target, bit); return out;
        case 0x0Bu: out.valid = true; out.mnemonic = "clr1"; out.operands = FormatBitSfr(bus, target, bit); return out;
        case 0x0Cu: out.valid = true; out.mnemonic = "mov1"; out.operands = "CY, " + FormatBitSfr(bus, target, bit); return out;
        case 0x0Du: out.valid = true; out.mnemonic = "and1"; out.operands = "CY, " + FormatBitSfr(bus, target, bit); return out;
        case 0x0Eu: out.valid = true; out.mnemonic = "or1";  out.operands = "CY, " + FormatBitSfr(bus, target, bit); return out;
        case 0x0Fu: out.valid = true; out.mnemonic = "xor1"; out.operands = "CY, " + FormatBitSfr(bus, target, bit); return out;
        default:
            set_len(2);
            out.valid = false;
            out.mnemonic = "db";
            out.operands = Hex8(op);
            return out;
        }
    }

    // Callt [0040h..007Eh]
    if ((op & 0xC1u) == 0xC1u) {
        set_len(1);
        out.valid = true;
        out.mnemonic = "callt";
        const uint16_t vec = static_cast<uint16_t>(0x0040u + (op & 0x3Eu));
        out.operands = "[" + Hex16(vec) + "]";
        out.is_call = true;
        out.has_target = true;
        out.target_addr = ReadWordAt(bus, vec);
        return out;
    }

    // Single-register 1-byte/2-byte groups
    if ((op & 0xF8u) == 0x30u && op != 0x31u) {
        set_len(1); out.valid = true; out.mnemonic = "xch"; out.operands = std::string("A, ") + kReg8Names[op & 7u]; return out;
    }
    if ((op & 0xF8u) == 0x40u) {
        set_len(1); out.valid = true; out.mnemonic = "inc"; out.operands = kReg8Names[op & 7u]; return out;
    }
    if ((op & 0xF8u) == 0x50u) {
        set_len(1); out.valid = true; out.mnemonic = "dec"; out.operands = kReg8Names[op & 7u]; return out;
    }
    if ((op & 0xF8u) == 0x60u && op != 0x61u) {
        set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = std::string("A, ") + kReg8Names[op & 7u]; return out;
    }
    if ((op & 0xF8u) == 0x70u && op != 0x71u) {
        set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = std::string(kReg8Names[op & 7u]) + ", A"; return out;
    }
    if ((op & 0xF8u) == 0xA0u) {
        set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = std::string(kReg8Names[op & 7u]) + ", #" + Hex8(fetch(1)); return out;
    }

    // Bit set1/clr1/bt/callf
    if ((op & 0x8Fu) == 0x0Au) {
        set_len(2);
        const uint8_t b = (op >> 4) & 7u;
        const uint8_t off = fetch(1);
        out.valid = true;
        if (op == 0x7Au && off == 0x1Eu) {
            out.mnemonic = "ei";
        } else {
            out.mnemonic = "set1";
            out.operands = FormatBitSaddr(bus, off, b);
        }
        return out;
    }
    if ((op & 0x8Fu) == 0x0Bu) {
        set_len(2);
        const uint8_t b = (op >> 4) & 7u;
        const uint8_t off = fetch(1);
        out.valid = true;
        if (op == 0x7Bu && off == 0x1Eu) {
            out.mnemonic = "di";
        } else {
            out.mnemonic = "clr1";
            out.operands = FormatBitSaddr(bus, off, b);
        }
        return out;
    }
    if ((op & 0x8Fu) == 0x0Cu) {
        set_len(2);
        const uint16_t tgt = static_cast<uint16_t>(0x0800u + ((op >> 4) << 8) + fetch(1));
        out.valid = true;
        out.mnemonic = "callf";
        out.operands = "!" + Hex16(tgt);
        out.is_call = true;
        out.has_target = true;
        out.target_addr = tgt;
        return out;
    }
    if ((op & 0x8Fu) == 0x8Cu) {
        set_len(3);
        const uint8_t b = (op >> 4) & 7u;
        const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 3u), fetch(2));
        out.valid = true;
        out.mnemonic = "bt";
        out.operands = FormatBitSaddr(bus, fetch(1), b) + ", $" + Hex16(tgt);
        out.is_branch = true;
        out.has_target = true;
        out.target_addr = tgt;
        return out;
    }

    // 16-bit rp instructions
    if ((op & 0xF9u) == 0x10u) {
        set_len(3); out.valid = true; out.mnemonic = "movw";
        out.operands = std::string(kReg16Names[(op >> 1) & 3u]) + ", #" + Hex16(word_at(1));
        return out;
    }
    if ((op & 0xF9u) == 0x80u) {
        set_len(1); out.valid = true; out.mnemonic = "incw"; out.operands = kReg16Names[(op >> 1) & 3u]; return out;
    }
    if ((op & 0xF9u) == 0x90u) {
        set_len(1); out.valid = true; out.mnemonic = "decw"; out.operands = kReg16Names[(op >> 1) & 3u]; return out;
    }
    if ((op & 0xF9u) == 0xB0u) {
        set_len(1); out.valid = true; out.mnemonic = (op & 1u) ? "push" : "pop"; out.operands = kReg16Names[(op >> 1) & 3u]; return out;
    }
    if ((op & 0xF9u) == 0xC0u && op != 0xC0u) {
        set_len(1); out.valid = true; out.mnemonic = "movw"; out.operands = std::string("AX, ") + kReg16Names[(op >> 1) & 3u]; return out;
    }
    if ((op & 0xF9u) == 0xD0u && op != 0xD0u) {
        set_len(1); out.valid = true; out.mnemonic = "movw"; out.operands = std::string(kReg16Names[(op >> 1) & 3u]) + ", AX"; return out;
    }
    if ((op & 0xF9u) == 0xE0u && op != 0xE0u) {
        set_len(1); out.valid = true; out.mnemonic = "xchw"; out.operands = std::string("AX, ") + kReg16Names[(op >> 1) & 3u]; return out;
    }

    // ALU A, {addr16, [HL+imm], #imm, saddr, [HL]} and ALU saddr, #imm
    const uint8_t alu_grp = (op >> 4) & 7u;
    const uint8_t alu_lo = op & 0x0Fu;
    if ((op & 0x80u) == 0) {
        if (alu_lo == 0x08u) { set_len(3); out.valid = true; out.mnemonic = kAluMnemonics[alu_grp]; out.operands = "A, !" + Hex16(word_at(1)); return out; }
        if (alu_lo == 0x09u) { set_len(2); out.valid = true; out.mnemonic = kAluMnemonics[alu_grp]; out.operands = "A, [HL+" + Hex8(fetch(1)) + "]"; return out; }
        if (alu_lo == 0x0Du) { set_len(2); out.valid = true; out.mnemonic = kAluMnemonics[alu_grp]; out.operands = "A, #" + Hex8(fetch(1)); return out; }
        if (alu_lo == 0x0Eu) { set_len(2); out.valid = true; out.mnemonic = kAluMnemonics[alu_grp]; out.operands = "A, " + FormatSaddr(bus, fetch(1)); return out; }
        if (alu_lo == 0x0Fu) { set_len(1); out.valid = true; out.mnemonic = kAluMnemonics[alu_grp]; out.operands = "A, [HL]"; return out; }
    } else if (alu_lo == 0x08u) {
        set_len(3);
        out.valid = true;
        out.mnemonic = kAluMnemonics[alu_grp];
        out.operands = FormatSaddr(bus, fetch(1)) + ", #" + Hex8(fetch(2));
        return out;
    }

    // Individual opcodes
    switch (op) {
    case 0x00u: set_len(1); out.valid = true; out.mnemonic = "nop"; return out;
    case 0x01u: set_len(1); out.valid = true; out.mnemonic = "not1"; out.operands = "CY"; return out;
    case 0x02u: set_len(3); out.valid = true; out.mnemonic = "movw"; out.operands = "AX, !" + Hex16(word_at(1)); return out;
    case 0x03u: set_len(3); out.valid = true; out.mnemonic = "movw"; out.operands = "!" + Hex16(word_at(1)) + ", AX"; return out;
    case 0x04u: {
        set_len(3);
        const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 3u), fetch(2));
        out.valid = true; out.mnemonic = "dbnz"; out.operands = FormatSaddr(bus, fetch(1)) + ", $" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt;
        return out;
    }
    case 0x05u: set_len(1); out.valid = true; out.mnemonic = "xch"; out.operands = "A, [DE]"; return out;
    case 0x07u: set_len(1); out.valid = true; out.mnemonic = "xch"; out.operands = "A, [HL]"; return out;
    case 0x11u: set_len(3); out.valid = true; out.mnemonic = "mov"; out.operands = FormatSaddr(bus, fetch(1)) + ", #" + Hex8(fetch(2)); return out;
    case 0x13u: set_len(3); out.valid = true; out.mnemonic = "mov"; out.operands = FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))) + ", #" + Hex8(fetch(2)); return out;
    case 0x20u: set_len(1); out.valid = true; out.mnemonic = "set1"; out.operands = "CY"; return out;
    case 0x21u: set_len(1); out.valid = true; out.mnemonic = "clr1"; out.operands = "CY"; return out;
    case 0x22u: set_len(1); out.valid = true; out.mnemonic = "push"; out.operands = "PSW"; return out;
    case 0x23u: set_len(1); out.valid = true; out.mnemonic = "pop"; out.operands = "PSW"; return out;
    case 0x24u: set_len(1); out.valid = true; out.mnemonic = "ror"; out.operands = "A, 1"; return out;
    case 0x25u: set_len(1); out.valid = true; out.mnemonic = "rorc"; out.operands = "A, 1"; return out;
    case 0x26u: set_len(1); out.valid = true; out.mnemonic = "rol"; out.operands = "A, 1"; return out;
    case 0x27u: set_len(1); out.valid = true; out.mnemonic = "rolc"; out.operands = "A, 1"; return out;
    case 0x81u: set_len(2); out.valid = true; out.mnemonic = "inc"; out.operands = FormatSaddr(bus, fetch(1)); return out;
    case 0x83u: set_len(2); out.valid = true; out.mnemonic = "xch"; out.operands = "A, " + FormatSaddr(bus, fetch(1)); return out;
    case 0x85u: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "A, [DE]"; return out;
    case 0x87u: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "A, [HL]"; return out;
    case 0x89u: set_len(2); out.valid = true; out.mnemonic = "movw"; out.operands = "AX, " + FormatSaddrSp(bus, fetch(1)); return out;
    case 0x8Au: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "dbnz"; out.operands = "C, $" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x8Bu: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "dbnz"; out.operands = "B, $" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x8Du: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "bc"; out.operands = "$" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x8Eu: set_len(3); out.valid = true; out.mnemonic = "mov"; out.operands = "A, !" + Hex16(word_at(1)); return out;
    case 0x8Fu: set_len(1); out.valid = true; out.mnemonic = "reti"; out.is_stop_flow = true; return out;
    case 0x91u: set_len(2); out.valid = true; out.mnemonic = "dec"; out.operands = FormatSaddr(bus, fetch(1)); return out;
    case 0x93u: set_len(2); out.valid = true; out.mnemonic = "xch"; out.operands = "A, " + FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))); return out;
    case 0x95u: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "[DE], A"; return out;
    case 0x97u: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "[HL], A"; return out;
    case 0x99u: set_len(2); out.valid = true; out.mnemonic = "movw"; out.operands = FormatSaddrSp(bus, fetch(1)) + ", AX"; return out;
    case 0x9Au: {
        set_len(3); const uint16_t tgt = word_at(1);
        out.valid = true; out.mnemonic = "call"; out.operands = "!" + Hex16(tgt);
        out.is_call = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x9Bu: {
        set_len(3); const uint16_t tgt = word_at(1);
        out.valid = true; out.mnemonic = "br"; out.operands = "!" + Hex16(tgt);
        out.is_branch = true; out.is_stop_flow = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x9Du: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "bnc"; out.operands = "$" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0x9Eu: set_len(3); out.valid = true; out.mnemonic = "mov"; out.operands = "!" + Hex16(word_at(1)) + ", A"; return out;
    case 0x9Fu: set_len(1); out.valid = true; out.mnemonic = "retb"; out.is_stop_flow = true; return out;
    case 0xA9u: set_len(2); out.valid = true; out.mnemonic = "movw"; out.operands = "AX, " + FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))); return out;
    case 0xAAu: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "A, [HL+C]"; return out;
    case 0xABu: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "A, [HL+B]"; return out;
    case 0xADu: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "bz"; out.operands = "$" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0xAEu: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = "A, [HL+" + Hex8(fetch(1)) + "]"; return out;
    case 0xAFu: set_len(1); out.valid = true; out.mnemonic = "ret"; out.is_stop_flow = true; return out;
    case 0xB9u: set_len(2); out.valid = true; out.mnemonic = "movw"; out.operands = FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))) + ", AX"; return out;
    case 0xBAu: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "[HL+C], A"; return out;
    case 0xBBu: set_len(1); out.valid = true; out.mnemonic = "mov"; out.operands = "[HL+B], A"; return out;
    case 0xBDu: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "bnz"; out.operands = "$" + Hex16(tgt);
        out.is_branch = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0xBEu: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = "[HL+" + Hex8(fetch(1)) + "], A"; return out;
    case 0xBFu: set_len(1); out.valid = true; out.mnemonic = "brk"; out.is_call = true; return out;
    case 0xCAu: set_len(3); out.valid = true; out.mnemonic = "addw"; out.operands = "AX, #" + Hex16(word_at(1)); return out;
    case 0xCEu: set_len(3); out.valid = true; out.mnemonic = "xch"; out.operands = "A, !" + Hex16(word_at(1)); return out;
    case 0xDAu: set_len(3); out.valid = true; out.mnemonic = "subw"; out.operands = "AX, #" + Hex16(word_at(1)); return out;
    case 0xDEu: set_len(2); out.valid = true; out.mnemonic = "xch"; out.operands = "A, [HL+" + Hex8(fetch(1)) + "]"; return out;
    case 0xEAu: set_len(3); out.valid = true; out.mnemonic = "cmpw"; out.operands = "AX, #" + Hex16(word_at(1)); return out;
    case 0xEEu: set_len(4); out.valid = true; out.mnemonic = "movw"; out.operands = FormatSaddrSp(bus, fetch(1)) + ", #" + Hex16(word_at(2)); return out;
    case 0xF0u: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = "A, " + FormatSaddr(bus, fetch(1)); return out;
    case 0xF2u: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = FormatSaddr(bus, fetch(1)) + ", A"; return out;
    case 0xF4u: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = "A, " + FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))); return out;
    case 0xF6u: set_len(2); out.valid = true; out.mnemonic = "mov"; out.operands = FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))) + ", A"; return out;
    case 0xFAu: {
        set_len(2); const uint16_t tgt = ResolveRel(static_cast<uint16_t>(addr + 2u), fetch(1));
        out.valid = true; out.mnemonic = "br"; out.operands = "$" + Hex16(tgt);
        out.is_branch = true; out.is_stop_flow = true; out.has_target = true; out.target_addr = tgt; return out;
    }
    case 0xFEu: set_len(4); out.valid = true; out.mnemonic = "movw"; out.operands = FormatSfrOrAddr(bus, static_cast<uint16_t>(0xFF00u + fetch(1))) + ", #" + Hex16(word_at(2)); return out;
    default:
        set_len(1);
        out.valid = false;
        out.mnemonic = "db";
        out.operands = Hex8(op);
        return out;
    }
}

}  // namespace k0
