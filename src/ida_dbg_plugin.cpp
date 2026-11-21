#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <netnode.hpp>

#include "disasm.h"
#include "log.h"
#include "machine.h"
#include "module_path.h"

namespace {

constexpr pid_t kPid = 1;
constexpr thid_t kTid = 1;
constexpr uint16_t kDefaultRomEnd = 0xC000u;
constexpr uint16_t kDefaultExpRamStart = 0xF400u;
constexpr uint16_t kDefaultExpRamEnd = 0xF800u;

const uchar kSoftBptBytes[1] = { 0xBFu };  // BRK opcode byte (breakpoints are non-intrusive; flash stays untouched)

enum RegClassMask : uchar {
    RC_GENERAL = 1u << 0,
    RC_BANKS   = 1u << 1,
    RC_INTC    = 1u << 2,
    RC_SYS     = 1u << 3,
    RC_TIMERS  = 1u << 4,
};

const char *const kRegClasses[] = {
    "General registers",
    "Register banks",
    "Interrupt controller",
    "System & Clock",
    "Timers",
    nullptr
};

const register_info_t kRegisters[] = {
    // General registers (RC_GENERAL)
    { "PC",     REGISTER_IP | REGISTER_ADDRESS, RC_GENERAL, dt_word,  nullptr, 0 },
    { "SP",     REGISTER_SP | REGISTER_ADDRESS, RC_GENERAL, dt_word,  nullptr, 0 },
    { "PSW",    0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "AX",     REGISTER_ADDRESS,               RC_GENERAL, dt_word,  nullptr, 0 },
    { "BC",     REGISTER_ADDRESS,               RC_GENERAL, dt_word,  nullptr, 0 },
    { "DE",     REGISTER_ADDRESS,               RC_GENERAL, dt_word,  nullptr, 0 },
    { "HL",     REGISTER_ADDRESS,               RC_GENERAL, dt_word,  nullptr, 0 },
    { "A",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "X",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "B",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "C",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "D",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "E",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "H",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "L",      0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "RB",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },
    { "CY",     0,                              RC_GENERAL, dt_byte,  nullptr, 0 },

    // Register banks (RC_BANKS)
    { "RB0_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB0_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB1_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB2_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_AX", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_BC", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_DE", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },
    { "RB3_HL", 0,                              RC_BANKS,   dt_word,  nullptr, 0 },

    // Interrupt controller (RC_INTC)
    { "IF0L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF0H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF1L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "IF1H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK0L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK0H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK1L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "MK1H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR0L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR0H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR1L",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "PR1H",   0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "EGP",    0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "EGN",    0,                              RC_INTC,    dt_byte,  nullptr, 0 },
    { "KRM",    0,                              RC_INTC,    dt_byte,  nullptr, 0 },

    // System & Clock (RC_SYS)
    { "IMS",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "IXS",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "BANK",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "PCC",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSCCTL", 0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "RCM",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "MCM",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "MOC",    0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSTC",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "OSTS",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "WDTE",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "RESF",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "LVIM",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "LVIS",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "PFCMD",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "FLPMC",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "FLCTL",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "FLREG",  0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "PROD",   0,                              RC_SYS,     dt_byte,  nullptr, 0 },
    { "CYCLES", REGISTER_READONLY,              RC_SYS,     dt_qword, nullptr, 0 },

    // Timers (RC_TIMERS)
    { "TM00",   0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TMC00",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "CR000",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "CR010",  0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TM01",   0,                              RC_TIMERS,  dt_word,  nullptr, 0 },
    { "TMC01",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TM50",   0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "CR50",   0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TMC50",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TM51",   0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "CR51",   0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TMC51",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TMHMD0", 0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "CMP00",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "TMHMD1", 0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "CMP01",  0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
    { "WTM",    0,                              RC_TIMERS,  dt_byte,  nullptr, 0 },
};

enum RegBackingKind : uint8_t {
    BACK_PC = 0,
    BACK_SP,
    BACK_PSW,
    BACK_RP,
    BACK_R8,
    BACK_RB,
    BACK_CY,
    BACK_BANK_RP,
    BACK_SFR8,
    BACK_SFR16,
    BACK_CYCLES,
};

struct RegBackingDesc {
    RegBackingKind kind;
    uint16_t param0;
    uint8_t param1;
};

const RegBackingDesc kRegBacking[] = {
    // General registers
    { BACK_PC,      0,         0 },
    { BACK_SP,      0,         0 },
    { BACK_PSW,     0,         0 },
    { BACK_RP,      k0::RP_AX, 0 },
    { BACK_RP,      k0::RP_BC, 0 },
    { BACK_RP,      k0::RP_DE, 0 },
    { BACK_RP,      k0::RP_HL, 0 },
    { BACK_R8,      k0::REG_A, 0 },
    { BACK_R8,      k0::REG_X, 0 },
    { BACK_R8,      k0::REG_B, 0 },
    { BACK_R8,      k0::REG_C, 0 },
    { BACK_R8,      k0::REG_D, 0 },
    { BACK_R8,      k0::REG_E, 0 },
    { BACK_R8,      k0::REG_H, 0 },
    { BACK_R8,      k0::REG_L, 0 },
    { BACK_RB,      0,         0 },
    { BACK_CY,      0,         0 },

    // Register banks
    { BACK_BANK_RP, k0::RP_AX, 0 },
    { BACK_BANK_RP, k0::RP_BC, 0 },
    { BACK_BANK_RP, k0::RP_DE, 0 },
    { BACK_BANK_RP, k0::RP_HL, 0 },
    { BACK_BANK_RP, k0::RP_AX, 1 },
    { BACK_BANK_RP, k0::RP_BC, 1 },
    { BACK_BANK_RP, k0::RP_DE, 1 },
    { BACK_BANK_RP, k0::RP_HL, 1 },
    { BACK_BANK_RP, k0::RP_AX, 2 },
    { BACK_BANK_RP, k0::RP_BC, 2 },
    { BACK_BANK_RP, k0::RP_DE, 2 },
    { BACK_BANK_RP, k0::RP_HL, 2 },
    { BACK_BANK_RP, k0::RP_AX, 3 },
    { BACK_BANK_RP, k0::RP_BC, 3 },
    { BACK_BANK_RP, k0::RP_DE, 3 },
    { BACK_BANK_RP, k0::RP_HL, 3 },

    // Interrupt controller
    { BACK_SFR8,    0xFFE0u,   0 },
    { BACK_SFR8,    0xFFE1u,   0 },
    { BACK_SFR8,    0xFFE2u,   0 },
    { BACK_SFR8,    0xFFE3u,   0 },
    { BACK_SFR8,    0xFFE4u,   0 },
    { BACK_SFR8,    0xFFE5u,   0 },
    { BACK_SFR8,    0xFFE6u,   0 },
    { BACK_SFR8,    0xFFE7u,   0 },
    { BACK_SFR8,    0xFFE8u,   0 },
    { BACK_SFR8,    0xFFE9u,   0 },
    { BACK_SFR8,    0xFFEAu,   0 },
    { BACK_SFR8,    0xFFEBu,   0 },
    { BACK_SFR8,    0xFF48u,   0 },
    { BACK_SFR8,    0xFF49u,   0 },
    { BACK_SFR8,    0xFF6Eu,   0 },

    // System & Clock
    { BACK_SFR8,    0xFFF0u,   0 },
    { BACK_SFR8,    0xFFF4u,   0 },
    { BACK_SFR8,    0xFFF3u,   0 },
    { BACK_SFR8,    0xFFFBu,   0 },
    { BACK_SFR8,    0xFF9Fu,   0 },
    { BACK_SFR8,    0xFFA0u,   0 },
    { BACK_SFR8,    0xFFA1u,   0 },
    { BACK_SFR8,    0xFFA2u,   0 },
    { BACK_SFR8,    0xFFA3u,   0 },
    { BACK_SFR8,    0xFFA4u,   0 },
    { BACK_SFR8,    0xFF99u,   0 },
    { BACK_SFR8,    0xFFACu,   0 },
    { BACK_SFR8,    0xFFBEu,   0 },
    { BACK_SFR8,    0xFFBFu,   0 },
    { BACK_SFR8,    0xFFC0u,   0 },
    { BACK_SFR8,    0xFFC4u,   0 },
    { BACK_SFR8,    0xFFC5u,   0 },
    { BACK_SFR8,    0xFFCAu,   0 },
    { BACK_SFR8,    0xFFF5u,   0 },
    { BACK_CYCLES,  0,         0 },

    // Timers
    { BACK_SFR16,   0xFF10u,   0 },
    { BACK_SFR8,    0xFFBAu,   0 },
    { BACK_SFR16,   0xFF12u,   0 },
    { BACK_SFR16,   0xFF14u,   0 },
    { BACK_SFR16,   0xFFB0u,   0 },
    { BACK_SFR8,    0xFFB6u,   0 },
    { BACK_SFR8,    0xFF16u,   0 },
    { BACK_SFR8,    0xFF17u,   0 },
    { BACK_SFR8,    0xFF6Bu,   0 },
    { BACK_SFR8,    0xFF1Fu,   0 },
    { BACK_SFR8,    0xFF41u,   0 },
    { BACK_SFR8,    0xFF43u,   0 },
    { BACK_SFR8,    0xFF69u,   0 },
    { BACK_SFR8,    0xFF18u,   0 },
    { BACK_SFR8,    0xFF6Cu,   0 },
    { BACK_SFR8,    0xFF1Au,   0 },
    { BACK_SFR8,    0xFF6Fu,   0 },
};

static_assert(qnumber(kRegBacking) == qnumber(kRegisters),
              "kRegBacking must stay aligned with kRegisters");

int FindRegIdxByExactName(const char *name) {
    if (!name || !*name) {
        return -1;
    }
    for (size_t i = 0; i < qnumber(kRegisters); ++i) {
        if (strieq(kRegisters[i].name, name)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool ResolveRegInfo(const char *name, const char **main_regname, bitrange_t *bitrange) {
    if (!name || !*name) {
        return false;
    }

    const int exact = FindRegIdxByExactName(name);
    if (exact >= 0) {
        if (main_regname) {
            *main_regname = kRegisters[exact].name;
        }
        if (bitrange) {
            const uint16 bits = (kRegisters[exact].dtype == dt_qword) ? 64
                              : (kRegisters[exact].dtype == dt_word)  ? 16
                              :                                         8;
            *bitrange = bitrange_t(0, bits);
        }
        return true;
    }

    struct RegAliasInfo {
        const char *alias;
        const char *target;
        uint16 bit_ofs;
        uint16 bit_len;
    };
    static const RegAliasInfo kAliases[] = {
        { "R0",  "X",  0,  8 },
        { "R1",  "A",  0,  8 },
        { "R2",  "C",  0,  8 },
        { "R3",  "B",  0,  8 },
        { "R4",  "E",  0,  8 },
        { "R5",  "D",  0,  8 },
        { "R6",  "L",  0,  8 },
        { "R7",  "H",  0,  8 },
        { "RP0", "AX", 0, 16 },
        { "RP1", "BC", 0, 16 },
        { "RP2", "DE", 0, 16 },
        { "RP3", "HL", 0, 16 },
        { "SPL", "SP", 0,  8 },
        { "SPH", "SP", 8,  8 },
        { "RB0", "RB", 0,  8 },
        { "RB1", "RB", 0,  8 },
        { "RB2", "RB", 0,  8 },
        { "RB3", "RB", 0,  8 },
    };

    for (const auto &a : kAliases) {
        if (strieq(a.alias, name)) {
            if (main_regname) {
                *main_regname = a.target;
            }
            if (bitrange) {
                *bitrange = bitrange_t(a.bit_ofs, a.bit_len);
            }
            return true;
        }
    }
    return false;
}

int FindRegIdxByName(const char *name) {
    const char *canonical = nullptr;
    if (!ResolveRegInfo(name, &canonical, nullptr) || !canonical) {
        return -1;
    }
    return FindRegIdxByExactName(canonical);
}

uchar ToIdaSegPerm(uint8_t perm) {
    uchar p = 0;
    if (perm & MEM_PERM_READ)  p |= SEGPERM_READ;
    if (perm & MEM_PERM_WRITE) p |= SEGPERM_WRITE;
    if (perm & MEM_PERM_EXEC)  p |= SEGPERM_EXEC;
    return p;
}

int WatchTypeFromBpt(bpttype_t type) {
    switch (type) {
    case BPT_WRITE: return 1;
    case BPT_READ:  return 2;
    case BPT_RDWR:  return 3;
    default:        return 0;
    }
}

void IdaLogCallback(const char *line) {
    if (line && *line) {
        msg("%s\n", line);
    }
}

bool ContainsAsciiICase(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) {
        return false;
    }
    return stristr(haystack, needle) != nullptr;
}

struct k0dbg_plugmod_t;
k0dbg_plugmod_t *g_active_plugmod = nullptr;

struct idd_listener_t final : public event_listener_t {
    k0dbg_plugmod_t *pm = nullptr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct idp_k0_listener_t final : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct ui_listener_t final : public event_listener_t {
    bool debugger_selected = false;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct k0dbg_plugmod_t final : public plugmod_t {
    k0::K0Machine machine;
    std::deque<debug_event_t> event_queue;
    std::unordered_set<uint16_t> ida_exec_bpts;
    std::atomic<bool> pause_requested{false};
    bool is_running = false;
    bool attached = false;
    bool hooks_installed = false;
    bool idc_registered = false;
    resume_mode_t resmod = RESMOD_NONE;
    bool ignore_bpt_once = false;
    uint16_t entry_pc = 0;
    std::string custom_prog_rom_path;
    std::string custom_ea_path;

    idd_listener_t idd_listener;
    idp_k0_listener_t idp_listener;
    ui_listener_t ui_listener;

    k0dbg_plugmod_t() {
        g_active_plugmod = this;
        idd_listener.pm = this;
        InstallHooks();
        RegisterIdcFunctions();
    }

    ~k0dbg_plugmod_t() override {
        set_log_callback(nullptr);
        UnregisterIdcFunctions();
        UninstallHooks();
        if (g_active_plugmod == this) {
            g_active_plugmod = nullptr;
        }
    }

    bool idaapi run(size_t arg) override;

    void InstallHooks();
    void UninstallHooks();
    void RegisterIdcFunctions();
    void UnregisterIdcFunctions();
    std::string PluginDirectory() const;
    bool LoadFlashAsset(bool is_prog_rom, const char *override_path, bool reset_to_default);
    void AutoLoadFlashImages();
    void ResetSessionState();
    void DetectLayoutFromIdb(MachineProfile *profile_out,
                             uint16_t *rom_end_out,
                             uint16_t *exp_start_out,
                             uint16_t *exp_end_out,
                             uint16_t *ram_start_out) const;
    void LoadSegmentsFromIdb();
    uint16_t DetermineEntryPc(uint16_t rom_end) const;
    void QueueEvent(const debug_event_t &ev);
    void QueueStopEvent(const k0::StopInfo &stop, bool from_single_step);
    uint64_t ReadRegByIdx(size_t idx) const;
    void WriteRegByIdx(size_t idx, uint64_t val);
    void InvalidateBusCacheOnChange(uint8_t prev_bank, uint8_t prev_ovl) const;
    void WriteRegAndInvalidate(size_t idx, uint64_t val);
    ssize_t HandleIddEvent(ssize_t code, va_list va);
    ssize_t HandleRexec(const char *cmdline);
};

debugger_t g_debugger = {
    IDD_INTERFACE_VERSION,
    "k0emu",
    DEBUGGER_ID_6811_EMULATOR,
    "78k0",
    DBG_FLAG_CAN_CONT_BPT
    | DBG_FLAG_SAFE
    | DBG_FLAG_FAKE_ATTACH
    | DBG_FLAG_NOHOST
    | DBG_FLAG_NOPARAMETERS
    | DBG_FLAG_NOPASSWORD
    | DBG_FLAG_NOSTARTDIR
    | DBG_FLAG_SMALLBLKS
    | DBG_FLAG_ANYSIZE_HWBPT
    | DBG_FLAG_FAST_STEP
    | DBG_HAS_GET_PROCESSES
    | DBG_HAS_ATTACH_PROCESS
    | DBG_HAS_DETACH_PROCESS
    | DBG_HAS_REQUEST_PAUSE
    | DBG_HAS_THREAD_SUSPEND
    | DBG_HAS_THREAD_CONTINUE
    | DBG_HAS_SET_RESUME_MODE
    | DBG_HAS_CHECK_BPT
    | DBG_HAS_REXEC,
    const_cast<const char **>(kRegClasses),
    RC_GENERAL,
    const_cast<register_info_t *>(kRegisters),
    static_cast<int>(qnumber(kRegisters)),
    0x100,
    kSoftBptBytes,
    sizeof(kSoftBptBytes),
    0,
    DBG_RESMOD_STEP_INTO,
};

void k0dbg_plugmod_t::InstallHooks() {
    if (!hooks_installed) {
        hook_event_listener(HT_IDD, &idd_listener);
        hook_event_listener(HT_IDP, &idp_listener);
        hook_event_listener(HT_UI,  &ui_listener);
        hooks_installed = true;
    }
}

void k0dbg_plugmod_t::UninstallHooks() {
    if (hooks_installed) {
        unhook_event_listener(HT_UI,  &ui_listener);
        unhook_event_listener(HT_IDP, &idp_listener);
        unhook_event_listener(HT_IDD, &idd_listener);
        hooks_installed = false;
    }
}

bool idaapi k0dbg_plugmod_t::run(size_t) {
    if (load_debugger("k0emu", false) || load_debugger("k0dbg.dll", false)) {
        msg("[k0emu] Selected NEC 78K0 emulator debugger backend.\n");
    } else {
        warning("Failed to activate k0emu debugger backend.");
    }
    return true;
}

void k0dbg_plugmod_t::DetectLayoutFromIdb(MachineProfile *profile_out,
                                          uint16_t *rom_end_out,
                                          uint16_t *exp_start_out,
                                          uint16_t *exp_end_out,
                                          uint16_t *ram_start_out) const {
    MachineProfile profile = MachineProfile::Kx2;
    qstring devname;
    netnode k0_node("$ 78k0");
    if (k0_node.supstr(&devname, 0) > 0 && ContainsAsciiICase(devname.c_str(), "0831")) {
        profile = MachineProfile::Legacy0831;
    }

    uint16_t rom_end = kDefaultRomEnd;
    bool found_rom = false;
    uint16_t exp_start = kDefaultExpRamStart;
    uint16_t exp_end = kDefaultExpRamEnd;
    bool found_exp = false;
    uint16_t ram_start = K0Bus::kHighSpeedRamStart;
    bool found_ram = false;

    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea || seg->is_header_segm()) {
            continue;
        }
        qstring sname;
        get_segm_name(&sname, seg);
        if (sname == "ABS" || seg->type == SEG_XTRN) {
            continue;
        }
        if (seg->start_ea >= 0x10000ULL) {
            continue;
        }

        const uint32_t s_start = static_cast<uint32_t>(seg->start_ea);
        const uint32_t s_end = static_cast<uint32_t>(std::min<ea_t>(seg->end_ea, 0x10000ULL));

        if (s_start == 0 && s_end <= 0xF000u) {
            rom_end = static_cast<uint16_t>(s_end);
            found_rom = true;
            continue;
        }

        if (s_start >= 0xE000u && s_end <= 0xF800u) {
            if (!found_exp || ContainsAsciiICase(sname.c_str(), "EXP")) {
                exp_start = static_cast<uint16_t>(s_start);
                exp_end = static_cast<uint16_t>(s_end);
                found_exp = true;
            }
            continue;
        }

        if (s_start >= K0Bus::kHighSpeedRamStart && s_end <= K0Bus::kGprStart &&
            ContainsAsciiICase(sname.c_str(), "RAM")) {
            ram_start = static_cast<uint16_t>(s_start);
            found_ram = true;
            continue;
        }

        if (!found_rom && s_end <= 0xF000u && (seg->perm & SEGPERM_EXEC) != 0) {
            rom_end = static_cast<uint16_t>(s_end);
        }
    }

    if (!found_exp) {
        exp_start = 0xF800u;
        exp_end = 0xF800u;
    }
    if (!found_ram) {
        ram_start = K0Bus::kHighSpeedRamStart;
    }

    *profile_out = profile;
    *rom_end_out = rom_end;
    *exp_start_out = exp_start;
    *exp_end_out = exp_end;
    *ram_start_out = ram_start;
}

void k0dbg_plugmod_t::LoadSegmentsFromIdb() {
    const int qty = get_segm_qty();
    std::vector<uint8_t> buf;
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea || seg->is_header_segm()) {
            continue;
        }
        qstring sname;
        get_segm_name(&sname, seg);
        if (sname == "ABS" || seg->type == SEG_XTRN) {
            continue;
        }
        if (seg->start_ea >= K0Bus::kSfrStart) {
            continue;
        }

        const ea_t clamped_end = std::min<ea_t>(seg->end_ea, K0Bus::kSfrStart);
        if (clamped_end <= seg->start_ea) {
            continue;
        }
        const uint16_t start = static_cast<uint16_t>(seg->start_ea);
        const size_t seg_size = static_cast<size_t>(clamped_end - seg->start_ea);
        buf.resize(seg_size);

        const ssize_t got = get_bytes(buf.data(), seg_size, seg->start_ea, GMB_READALL);
        if (got <= 0) {
            continue;
        }

        for (size_t off = 0; off < seg_size; ) {
            if (!is_loaded(seg->start_ea + off)) {
                ++off;
                continue;
            }
            size_t run_end = off + 1;
            while (run_end < seg_size && is_loaded(seg->start_ea + run_end)) {
                ++run_end;
            }
            machine.bus.WriteDebug(
                static_cast<uint16_t>(start + off),
                run_end - off,
                buf.data() + off);
            off = run_end;
        }
    }
}

uint16_t k0dbg_plugmod_t::DetermineEntryPc(uint16_t rom_end) const {
    if (is_loaded(k0::kResetVectorAddress) && is_loaded(k0::kResetVectorAddress + 1u)) {
        const uint8_t lo = machine.bus.PeekByte(k0::kResetVectorAddress);
        const uint8_t hi = machine.bus.PeekByte(k0::kResetVectorAddress + 1u);
        const uint16_t vec = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        if (vec != 0x0000u && vec != 0xFFFFu && vec < rom_end) {
            return vec;
        }
    }

    const ea_t start_ip = inf_get_start_ip();
    if (start_ip != BADADDR && start_ip < 0x10000ULL) {
        return static_cast<uint16_t>(start_ip);
    }

    const ea_t main_ea = get_name_ea(BADADDR, "main");
    if (main_ea != BADADDR && main_ea < 0x10000ULL) {
        return static_cast<uint16_t>(main_ea);
    }

    const ea_t reset_ea = get_name_ea(BADADDR, "RESET");
    if (reset_ea != BADADDR && reset_ea < 0x10000ULL) {
        return static_cast<uint16_t>(reset_ea);
    }

    return 0;
}

std::string k0dbg_plugmod_t::PluginDirectory() const {
    return k0::GetModuleDirectoryForAddress(reinterpret_cast<const void *>(&g_debugger));
}

bool k0dbg_plugmod_t::LoadFlashAsset(bool is_prog_rom, const char *override_path, bool reset_to_default) {
    const char *default_name = is_prog_rom ? "78k0_programmer_fw.bin" : "EA.bin";
    const char *label = is_prog_rom ? "programmer ROM" : "Extra Area";
    std::string &custom_ref = is_prog_rom ? custom_prog_rom_path : custom_ea_path;

    if (reset_to_default) {
        custom_ref.clear();
    } else if (override_path && *override_path) {
        const bool ok = is_prog_rom ? machine.LoadProgrammerRomFile(override_path)
                                    : machine.LoadEaFile(override_path);
        if (!ok) {
            msg("[k0emu] Warning: failed to load %s image.\n", label);
            return false;
        }
        custom_ref = override_path;
        if (is_prog_rom) {
            invalidate_dbgmem_contents(K0Bus::kProgRomLowStart, K0Bus::kProgRomSize);
            invalidate_dbgmem_contents(K0Bus::kProgRomHighStart, K0Bus::kProgRomSize);
        }
        msg("[k0emu] Loaded %s (%u bytes).\n",
            label,
            static_cast<unsigned>(is_prog_rom ? K0Bus::kProgRomSize : k0::Kx2FlashCtrl::kEaSize));
        return true;
    }

    const std::string target = custom_ref.empty()
                                   ? k0::JoinPath(PluginDirectory(), default_name)
                                   : custom_ref;
    if (!k0::FileExists(target)) {
        if (!custom_ref.empty()) {
            msg("[k0emu] Warning: configured %s image is unavailable.\n", label);
        } else if (reset_to_default) {
            if (is_prog_rom) {
                machine.bus.ClearProgrammerRom();
                invalidate_dbgmem_contents(K0Bus::kProgRomLowStart, K0Bus::kProgRomSize);
                invalidate_dbgmem_contents(K0Bus::kProgRomHighStart, K0Bus::kProgRomSize);
            } else {
                machine.flash.ClearEa();
            }
        }
        return false;
    }

    const bool ok = is_prog_rom ? machine.LoadProgrammerRomFile(target.c_str())
                                : machine.LoadEaFile(target.c_str());
    if (!ok) {
        msg("[k0emu] Warning: failed to parse %s file: %s\n", label, default_name);
        return false;
    }
    if (is_prog_rom) {
        invalidate_dbgmem_contents(K0Bus::kProgRomLowStart, K0Bus::kProgRomSize);
        invalidate_dbgmem_contents(K0Bus::kProgRomHighStart, K0Bus::kProgRomSize);
    }
    msg("[k0emu] Loaded %s (%u bytes) from plugin directory: %s\n",
        label,
        static_cast<unsigned>(is_prog_rom ? K0Bus::kProgRomSize : k0::Kx2FlashCtrl::kEaSize),
        default_name);
    return true;
}

void k0dbg_plugmod_t::AutoLoadFlashImages() {
    LoadFlashAsset(true, nullptr, false);
    LoadFlashAsset(false, nullptr, false);
}

void k0dbg_plugmod_t::ResetSessionState() {
    MachineProfile profile = MachineProfile::Kx2;
    uint16_t rom_end = kDefaultRomEnd;
    uint16_t exp_start = kDefaultExpRamStart;
    uint16_t exp_end = kDefaultExpRamEnd;
    uint16_t ram_start = K0Bus::kHighSpeedRamStart;
    DetectLayoutFromIdb(&profile, &rom_end, &exp_start, &exp_end, &ram_start);

    machine.Configure(profile, rom_end, exp_start, exp_end, ram_start);
    machine.bus.ClearMemory();
    machine.cpu.ClearBreakpoints();
    machine.bus.ClearWatchpoints();

    LoadSegmentsFromIdb();
    AutoLoadFlashImages();
    entry_pc = DetermineEntryPc(rom_end);

    // Reset AFTER loading ROM so Option Byte (0x0080) and vector table are visible to peripherals.
    machine.Reset(static_cast<int32_t>(entry_pc));
}

void k0dbg_plugmod_t::QueueEvent(const debug_event_t &ev) {
    event_queue.push_back(ev);
}

void k0dbg_plugmod_t::QueueStopEvent(const k0::StopInfo &stop, bool from_single_step) {
    debug_event_t ev;
    ev.pid = kPid;
    ev.tid = kTid;
    ev.ea = stop.pc;
    ev.handled = true;

    switch (stop.reason) {
    case k0::StopReason::None:
        if (from_single_step) {
            ev.set_eid(STEP);
            ev.ea = machine.cpu.GetPC();
        } else {
            ev.set_eid(PROCESS_SUSPENDED);
        }
        break;

    case k0::StopReason::Breakpoint:
        {
            const ea_t bpt_ea = stop.pc;
            ev.ea = bpt_ea;
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = BADADDR;
            bpt.kea = BADADDR;
        }
        break;

    case k0::StopReason::Watchpoint:
        {
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = static_cast<ea_t>(stop.detail);
            bpt.kea = BADADDR;
        }
        break;

    case k0::StopReason::BreakInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "BRK instruction";
        }
        break;

    case k0::StopReason::Halt:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "CPU HALT instruction";
        }
        break;

    case k0::StopReason::Stop:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "CPU STOP instruction";
        }
        break;

    case k0::StopReason::UnmappedMemory:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 11;
            exc.can_cont = true;
            exc.ea = static_cast<ea_t>(stop.detail);
            exc.info.sprnt("Unmapped memory %s at 0x%04X",
                           stop.is_write ? "write" : "read",
                           static_cast<unsigned>(stop.detail));
        }
        break;

    case k0::StopReason::InvalidInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 4;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info.sprnt("Invalid opcode 0x%02X at 0x%04X",
                           static_cast<unsigned>(stop.detail),
                           static_cast<unsigned>(stop.pc));
        }
        break;

    case k0::StopReason::WdtReset:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "Watchdog timer overflow reset (RESF.WDTRF=1)";
        }
        break;
    }

    invalidate_dbgmem_contents(0, BADADDR);
    QueueEvent(ev);
}

uint64_t k0dbg_plugmod_t::ReadRegByIdx(size_t idx) const {
    if (idx >= qnumber(kRegBacking)) {
        return 0;
    }
    const RegBackingDesc &d = kRegBacking[idx];
    switch (d.kind) {
    case BACK_PC:      return machine.cpu.GetPC();
    case BACK_SP:      return machine.cpu.GetSP();
    case BACK_PSW:     return machine.cpu.GetPSW();
    case BACK_RP:      return machine.cpu.ReadRegPair(static_cast<uint8_t>(d.param0));
    case BACK_R8:      return machine.cpu.ReadReg(static_cast<uint8_t>(d.param0));
    case BACK_RB:      return machine.cpu.GetRB();
    case BACK_CY:      return machine.cpu.GetCY() ? 1u : 0u;
    case BACK_BANK_RP: return machine.cpu.ReadRegPairBank(static_cast<uint8_t>(d.param0), d.param1);
    case BACK_SFR8:    return machine.bus.PeekByte(d.param0);
    case BACK_SFR16: {
        const uint8_t lo = machine.bus.PeekByte(d.param0);
        const uint8_t hi = machine.bus.PeekByte(static_cast<uint16_t>(d.param0 + 1u));
        return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 8);
    }
    case BACK_CYCLES:  return machine.cpu.TotalCycles();
    }
    return 0;
}

void k0dbg_plugmod_t::WriteRegByIdx(size_t idx, uint64_t val) {
    if (idx >= qnumber(kRegBacking)) {
        return;
    }
    const RegBackingDesc &d = kRegBacking[idx];
    switch (d.kind) {
    case BACK_PC:
        machine.cpu.SetPC(static_cast<uint16_t>(val & 0xFFFFu));
        break;
    case BACK_SP:
        machine.cpu.SetSP(static_cast<uint16_t>(val & 0xFFFFu));
        break;
    case BACK_PSW:
        machine.cpu.SetPSW(static_cast<uint8_t>(val & 0xFFu));
        break;
    case BACK_RP:
        machine.cpu.WriteRegPair(static_cast<uint8_t>(d.param0), static_cast<uint16_t>(val & 0xFFFFu));
        break;
    case BACK_R8:
        machine.cpu.WriteReg(static_cast<uint8_t>(d.param0), static_cast<uint8_t>(val & 0xFFu));
        break;
    case BACK_RB:
        machine.cpu.SetRB(static_cast<uint8_t>(val & 3u));
        break;
    case BACK_CY:
        machine.cpu.SetCY((val & 1u) != 0);
        break;
    case BACK_BANK_RP:
        machine.cpu.WriteRegPairBank(static_cast<uint8_t>(d.param0), d.param1, static_cast<uint16_t>(val & 0xFFFFu));
        break;
    case BACK_SFR8:
        machine.bus.PokeByte(d.param0, static_cast<uint8_t>(val & 0xFFu));
        break;
    case BACK_SFR16:
        machine.bus.PokeByte(d.param0, static_cast<uint8_t>(val & 0xFFu));
        machine.bus.PokeByte(static_cast<uint16_t>(d.param0 + 1u), static_cast<uint8_t>((val >> 8) & 0xFFu));
        break;
    case BACK_CYCLES:
        break;
    }
}

void k0dbg_plugmod_t::InvalidateBusCacheOnChange(uint8_t prev_bank, uint8_t prev_ovl) const {
    if (machine.bus.GetActiveBank() != prev_bank) {
        invalidate_dbgmem_contents(K0Bus::kBankWindowStart, K0Bus::kBankSize);
    }
    if (machine.bus.GetProgOverlayMask() != prev_ovl) {
        invalidate_dbgmem_contents(K0Bus::kProgRomLowStart, K0Bus::kProgRomSize);
        invalidate_dbgmem_contents(K0Bus::kProgRomHighStart, K0Bus::kProgRomSize);
    }
}

void k0dbg_plugmod_t::WriteRegAndInvalidate(size_t idx, uint64_t val) {
    if (idx >= qnumber(kRegBacking)) {
        return;
    }
    const uint8_t prev_bank = machine.bus.GetActiveBank();
    const uint8_t prev_ovl = machine.bus.GetProgOverlayMask();
    WriteRegByIdx(idx, val);

    const RegBackingDesc &d = kRegBacking[idx];
    if (d.kind == BACK_CYCLES) {
        return;
    }

    int inv = DBGINV_REGS | DBGINV_MEMORY;
    if (d.kind == BACK_PC) {
        invalidate_dbg_state(DBGINV_REGS);
        return;
    }
    if (d.kind == BACK_BANK_RP || d.kind == BACK_RP || d.kind == BACK_R8) {
        invalidate_dbgmem_contents(K0Bus::kGprStart, 0x0120u);
    } else if (d.kind == BACK_SP) {
        invalidate_dbgmem_contents(k0::kSpAddress, 2u);
    } else if (d.kind == BACK_PSW || d.kind == BACK_RB || d.kind == BACK_CY) {
        invalidate_dbgmem_contents(k0::kPswAddress, 1u);
    } else if (d.kind == BACK_SFR8) {
        invalidate_dbgmem_contents(d.param0, 1u);
    } else if (d.kind == BACK_SFR16) {
        invalidate_dbgmem_contents(d.param0, 2u);
    }

    InvalidateBusCacheOnChange(prev_bank, prev_ovl);
    invalidate_dbg_state(inv);
}

ssize_t k0dbg_plugmod_t::HandleRexec(const char *cmdline) {
    std::string out;
    const char *cmd = (cmdline && *cmdline) ? cmdline : "help";
    machine.ExecuteCommand(cmd, out);
    if (!out.empty()) {
        msg("%s\n", out.c_str());
    }
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    return 0;
}

ssize_t k0dbg_plugmod_t::HandleIddEvent(ssize_t code, va_list va) {
    switch (code) {
    case debugger_t::ev_init_debugger:
        {
            va_arg(va, const char *);
            va_arg(va, int);
            va_arg(va, const char *);
            va_arg(va, qstring *);
            set_log_callback(IdaLogCallback);
            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_term_debugger:
        {
            set_log_callback(nullptr);
            event_queue.clear();
            ida_exec_bpts.clear();
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_get_processes:
        {
            procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
            va_arg(va, qstring *);
            if (procs) {
                process_info_t &pi = procs->push_back();
                pi.pid = kPid;
                pi.name = "NEC 78K0 Emulator";
            }
            return DRC_OK;
        }

    case debugger_t::ev_start_process:
        {
            const char *path = va_arg(va, const char *);
            va_arg(va, const char *);       // args
            va_arg(va, const char *);       // startdir
            va_arg(va, uint32);             // dbg_proc_flags
            const char *input_path = va_arg(va, const char *);
            va_arg(va, uint32);             // input_file_crc32
            va_arg(va, qstring *);          // errbuf
            va_arg(va, launch_env_t *);     // envs

            ResetSessionState();

            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = (input_path && *input_path) ? input_path : (path && *path ? path : "78k0.bin");
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);

            debug_event_t susp;
            susp.set_eid(PROCESS_SUSPENDED);
            susp.pid = kPid;
            susp.tid = kTid;
            susp.ea = entry_pc;
            susp.handled = true;
            QueueEvent(susp);
            return DRC_OK;
        }

    case debugger_t::ev_attach_process:
        {
            va_arg(va, pid_t);
            va_arg(va, int);
            va_arg(va, uint32);
            va_arg(va, qstring *);

            ResetSessionState();

            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = "78k0.bin";
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_detach_process:
    case debugger_t::ev_exit_process:
        {
            va_arg(va, qstring *);
            is_running = false;
            attached = false;
            debug_event_t ev;
            ev.set_exit_code(PROCESS_EXITED, 0);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = machine.cpu.GetPC();
            ev.handled = true;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_get_debapp_attrs:
        {
            debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
            if (out_pattrs) {
                out_pattrs->addrsize = 2;
                out_pattrs->platform = "gdb";
                out_pattrs->is_be = false;
            }
            return DRC_OK;
        }

    case debugger_t::ev_rebase_if_required_to:
        {
            va_arg(va, ea_t);
            return DRC_OK;
        }

    case debugger_t::ev_request_pause:
        {
            va_arg(va, qstring *);
            pause_requested.store(true);
            return DRC_OK;
        }

    case debugger_t::ev_set_resume_mode:
        {
            va_arg(va, thid_t);
            resmod = static_cast<resume_mode_t>(va_arg(va, int));
            va_arg(va, qstring *);
            return DRC_OK;
        }

    case debugger_t::ev_resume:
        {
            const debug_event_t *ev = va_arg(va, const debug_event_t *);
            if (attached) {
                pause_requested.store(false);
                if (ev && ev->eid() == PROCESS_STARTED && !event_queue.empty()) {
                    is_running = false;
                } else {
                    is_running = true;
                    ignore_bpt_once = true;
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_get_debug_event:
        {
            gdecode_t *out_code = va_arg(va, gdecode_t *);
            debug_event_t *event = va_arg(va, debug_event_t *);
            const int timeout_ms = va_arg(va, int);

            if (!out_code || !event) {
                return DRC_FAILED;
            }

            if (event_queue.empty() && is_running) {
                if (resmod == RESMOD_INTO) {
                    const k0::StopInfo stop = machine.Step(ignore_bpt_once);
                    ignore_bpt_once = false;
                    is_running = false;
                    resmod = RESMOD_NONE;
                    QueueStopEvent(stop, true);
                } else {
                    const k0::StopInfo stop = machine.RunSteps(100000ULL, ignore_bpt_once, &pause_requested);
                    ignore_bpt_once = false;
                    if (pause_requested.exchange(false)) {
                        is_running = false;
                        QueueStopEvent(k0::StopInfo{k0::StopReason::None, machine.cpu.GetPC(), 0, false}, false);
                    } else if (stop.reason != k0::StopReason::None) {
                        is_running = false;
                        QueueStopEvent(stop, false);
                    } else if (machine.cpu.GetRunState() != k0::RunState::Running && timeout_ms > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 25)));
                    }
                }
            }

            if (event_queue.empty()) {
                if (!is_running && timeout_ms > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 10)));
                }
                *out_code = GDE_NO_EVENT;
                return DRC_OK;
            }

            *event = event_queue.front();
            event_queue.pop_front();
            if (event->eid() == PROCESS_SUSPENDED) {
                is_running = false;
            }
            *out_code = event_queue.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
            return DRC_OK;
        }

    case debugger_t::ev_thread_suspend:
    case debugger_t::ev_thread_continue:
        {
            va_arg(va, thid_t);
            va_arg(va, qstring *);
            return DRC_OK;
        }

    case debugger_t::ev_read_registers:
        {
            va_arg(va, thid_t);
            const int clsmask = va_arg(va, int);
            regval_t *values = va_arg(va, regval_t *);
            va_arg(va, qstring *);
            if (!values) {
                return DRC_FAILED;
            }
            for (size_t i = 0; i < qnumber(kRegisters); ++i) {
                if (clsmask == 0 || (kRegisters[i].register_class_mask & clsmask) != 0) {
                    values[i].set_int(ReadRegByIdx(i));
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_write_register:
        {
            va_arg(va, thid_t);
            const int regidx = va_arg(va, int);
            const regval_t *value = va_arg(va, const regval_t *);
            va_arg(va, qstring *);
            if (!value || regidx < 0 || static_cast<size_t>(regidx) >= qnumber(kRegisters)) {
                return DRC_FAILED;
            }
            WriteRegAndInvalidate(static_cast<size_t>(regidx), value->ival);
            return DRC_OK;
        }

    case debugger_t::ev_get_memory_info:
        {
            meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
            va_arg(va, qstring *);
            if (!ranges) {
                return DRC_FAILED;
            }
            ranges->qclear();
            const auto regions = machine.bus.GetRegions();
            for (const auto &reg : regions) {
                memory_info_t &mi = ranges->push_back();
                mi.start_ea = reg.start;
                mi.end_ea = static_cast<ea_t>(reg.start) + static_cast<ea_t>(reg.size);
                mi.name = reg.name.c_str();
                mi.sclass = reg.is_device ? "DATA" : "CODE";
                mi.sbase = 0;
                mi.bitness = 0;
                mi.perm = ToIdaSegPerm(reg.perm);
            }
            return DRC_OK;
        }

    case debugger_t::ev_read_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            void *buffer = va_arg(va, void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) {
                return DRC_FAILED;
            }
            if (size == 0) {
                *nbytes = 0;
                return DRC_OK;
            }
            if (ea >= K0Bus::kAddressSpaceSize) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            const size_t avail = static_cast<size_t>(K0Bus::kAddressSpaceSize - ea);
            const size_t to_read = std::min(size, avail);
            if (!machine.bus.ReadDebug(static_cast<uint16_t>(ea), to_read, buffer)) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            *nbytes = to_read;
            return DRC_OK;
        }

    case debugger_t::ev_write_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            const void *buffer = va_arg(va, const void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) {
                return DRC_FAILED;
            }
            if (size == 0) {
                *nbytes = 0;
                return DRC_OK;
            }
            if (ea >= K0Bus::kAddressSpaceSize) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            const size_t avail = static_cast<size_t>(K0Bus::kAddressSpaceSize - ea);
            const size_t to_write = std::min(size, avail);
            const uint8_t prev_bank = machine.bus.GetActiveBank();
            const uint8_t prev_ovl = machine.bus.GetProgOverlayMask();
            if (!machine.bus.WriteDebug(static_cast<uint16_t>(ea), to_write, buffer)) {
                *nbytes = 0;
                return DRC_FAILED;
            }
            if (ea + to_write > K0Bus::kGprStart) {
                invalidate_dbg_state(DBGINV_REGS);
            }
            InvalidateBusCacheOnChange(prev_bank, prev_ovl);
            *nbytes = to_write;
            return DRC_OK;
        }

    case debugger_t::ev_check_bpt:
        {
            int *bptvc = va_arg(va, int *);
            const bpttype_t type = va_arg(va, bpttype_t);
            const ea_t ea = va_arg(va, ea_t);
            va_arg(va, int);
            if (bptvc) {
                if (ea >= K0Bus::kAddressSpaceSize) {
                    *bptvc = BPT_BAD_ADDR;
                } else {
                    switch (type) {
                    case BPT_SOFT:
                    case BPT_EXEC:
                    case BPT_DEFAULT:
                    case BPT_WRITE:
                    case BPT_READ:
                    case BPT_RDWR:
                        *bptvc = BPT_OK;
                        break;
                    default:
                        *bptvc = BPT_BAD_TYPE;
                        break;
                    }
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_update_bpts:
        {
            int *nbpts = va_arg(va, int *);
            update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
            const int nadd = va_arg(va, int);
            const int ndel = va_arg(va, int);
            va_arg(va, qstring *);
            int count = 0;
            for (int i = 0; i < nadd + ndel; ++i) {
                update_bpt_info_t &b = bpts[i];
                if (b.code == BPT_SKIP) {
                    continue;
                }
                if (b.ea >= K0Bus::kAddressSpaceSize) {
                    b.code = BPT_BAD_ADDR;
                    continue;
                }
                const bool is_add = i < nadd;
                const uint16_t ea = static_cast<uint16_t>(b.ea);
                if (b.type == BPT_SOFT || b.type == BPT_EXEC || b.type == BPT_DEFAULT) {
                    if (is_add) {
                        if (b.type == BPT_SOFT || b.type == BPT_DEFAULT) {
                            b.orgbytes.resize(1);
                            b.orgbytes[0] = machine.bus.PeekByte(ea);
                        }
                        machine.cpu.AddBreakpoint(ea);
                        ida_exec_bpts.insert(ea);
                    } else {
                        machine.cpu.RemoveBreakpoint(ea);
                        ida_exec_bpts.erase(ea);
                    }
                    b.code = BPT_OK;
                    ++count;
                } else {
                    const int wt = WatchTypeFromBpt(b.type);
                    const uint16_t wsize = b.size > 0 ? static_cast<uint16_t>(b.size) : 1u;
                    if (wt != 0) {
                        if (is_add) {
                            machine.bus.AddWatchpoint(ea, wsize, wt);
                        } else {
                            machine.bus.RemoveWatchpoint(ea, wsize, wt);
                        }
                        b.code = BPT_OK;
                        ++count;
                    } else {
                        b.code = BPT_BAD_TYPE;
                    }
                }
            }
            if (nbpts) {
                *nbpts = count;
            }
            return DRC_OK;
        }

    case debugger_t::ev_rexec:
        {
            const char *cmdline = va_arg(va, const char *);
            return HandleRexec(cmdline);
        }

    default:
        break;
    }

    return DRC_NONE;
}

ssize_t idaapi idd_listener_t::on_event(ssize_t code, va_list va) {
    return pm ? pm->HandleIddEvent(code, va) : DRC_NONE;
}

ssize_t idaapi idp_k0_listener_t::on_event(ssize_t code, va_list va) {
    if (PH.id != PLFM_NEC_78K0) {
        return 0;
    }

    switch (code) {
    case processor_t::ev_get_reg_info:
        {
            const char **main_regname = va_arg(va, const char **);
            bitrange_t *bitrange = va_arg(va, bitrange_t *);
            const char *regname = va_arg(va, const char *);
            if (ResolveRegInfo(regname, main_regname, bitrange)) {
                return 1;
            }
            return -1;
        }

    case processor_t::ev_is_call_insn:
        {
            const insn_t *insn = va_arg(va, const insn_t *);
            if (!insn || insn->ea == BADADDR) {
                return 0;
            }
            qstring mnem;
            if (!print_insn_mnem(&mnem, insn->ea)) {
                return 0;
            }
            if (strieq(mnem.c_str(), "call") ||
                strieq(mnem.c_str(), "callf") ||
                strieq(mnem.c_str(), "callt")) {
                return 1;
            }
            return -1;
        }

    case processor_t::ev_calc_step_over:
        {
            ea_t *target = va_arg(va, ea_t *);
            const ea_t ip = va_arg(va, ea_t);
            if (!target || ip == BADADDR) {
                return 0;
            }
            insn_t ins;
            if (decode_insn(&ins, ip) <= 0) {
                return 0;
            }
            qstring mnem;
            print_insn_mnem(&mnem, ip);
            if (strieq(mnem.c_str(), "call") ||
                strieq(mnem.c_str(), "callf") ||
                strieq(mnem.c_str(), "callt") ||
                strieq(mnem.c_str(), "brk")) {
                *target = ip + ins.size;
                return 1;
            }
            *target = BADADDR;
            return 1;
        }

    default:
        break;
    }

    return 0;
}

ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list) {
    if (PH.id == PLFM_NEC_78K0 &&
        (code == ui_database_inited || code == ui_ready_to_run) &&
        !debugger_selected) {
        if (load_debugger("k0emu", false) || load_debugger("k0dbg.dll", false)) {
            debugger_selected = true;
        }
    }
    return 0;
}

// ============================================================================
// IDC helpers (k0dbg_*)
// ============================================================================

error_t idaapi idc_k0dbg_start(idc_value_t *, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    pm->ResetSessionState();
    pm->event_queue.clear();
    pm->ida_exec_bpts.clear();
    pm->pause_requested.store(false);
    pm->is_running = false;
    pm->attached = true;
    pm->resmod = RESMOD_NONE;
    pm->ignore_bpt_once = false;
    r->set_long(static_cast<sval_t>(pm->entry_pc));
    return eOk;
}

error_t idaapi idc_k0dbg_stop(idc_value_t *, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->is_running = false;
    pm->attached = false;
    pm->event_queue.clear();
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_step(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint64_t count = argv[0].num > 0 ? static_cast<uint64_t>(argv[0].num) : 1ULL;
    if (count == 1) {
        pm->machine.Step(true);
    } else {
        pm->machine.RunSteps(count, true, &pm->pause_requested);
    }
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_k0dbg_run_to(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint16_t target = static_cast<uint16_t>(argv[0].num & 0xFFFF);
    const uint64_t max_steps = argv[1].num > 0 ? static_cast<uint64_t>(argv[1].num) : 1000000ULL;
    for (uint64_t i = 0; i < max_steps; ++i) {
        const k0::StopInfo stop = pm->machine.Step(i == 0);
        const uint16_t cur_pc = pm->machine.cpu.GetPC();
        if (cur_pc == target || stop.reason != k0::StopReason::None) {
            break;
        }
    }
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_k0dbg_get_reg(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) {
        r->set_long(-1);
        return eOk;
    }
    const uint64_t val = pm->ReadRegByIdx(static_cast<size_t>(idx));
    r->set_long(static_cast<sval_t>(val));
    return eOk;
}

error_t idaapi idc_k0dbg_set_reg(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) {
        r->set_long(0);
        return eOk;
    }
    pm->WriteRegAndInvalidate(static_cast<size_t>(idx), static_cast<uint64_t>(argv[1].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_read_u8(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint16_t addr = static_cast<uint16_t>(argv[0].num & 0xFFFF);
    r->set_long(static_cast<sval_t>(pm->machine.bus.PeekByte(addr)));
    return eOk;
}

error_t idaapi idc_k0dbg_write_u8(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const uint16_t addr = static_cast<uint16_t>(argv[0].num & 0xFFFF);
    const uint8_t val = static_cast<uint8_t>(argv[1].num & 0xFF);
    const uint8_t prev_bank = pm->machine.bus.GetActiveBank();
    const uint8_t prev_ovl = pm->machine.bus.GetProgOverlayMask();
    pm->machine.bus.PokeByte(addr, val);
    invalidate_dbgmem_contents(addr, 1);
    pm->InvalidateBusCacheOnChange(prev_bank, prev_ovl);
    if (addr >= K0Bus::kGprStart) {
        invalidate_dbg_state(DBGINV_REGS);
    }
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_read_u16(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint16_t addr = static_cast<uint16_t>(argv[0].num & 0xFFFF);
    uint8_t buf[2] = {};
    if (!pm->machine.bus.ReadDebug(addr, 2, buf)) {
        r->set_long(-1);
        return eOk;
    }
    const uint16_t val = static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
    r->set_long(static_cast<sval_t>(val));
    return eOk;
}

error_t idaapi idc_k0dbg_write_u16(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const uint16_t addr = static_cast<uint16_t>(argv[0].num & 0xFFFF);
    const uint16_t val = static_cast<uint16_t>(argv[1].num & 0xFFFF);
    const uint8_t prev_bank = pm->machine.bus.GetActiveBank();
    const uint8_t prev_ovl = pm->machine.bus.GetProgOverlayMask();
    const uint8_t buf[2] = {
        static_cast<uint8_t>(val & 0xFFu),
        static_cast<uint8_t>((val >> 8) & 0xFFu),
    };
    if (!pm->machine.bus.WriteDebug(addr, 2, buf)) {
        r->set_long(0);
        return eOk;
    }
    invalidate_dbgmem_contents(addr, 2);
    pm->InvalidateBusCacheOnChange(prev_bank, prev_ovl);
    if (addr + 2u > K0Bus::kGprStart) {
        invalidate_dbg_state(DBGINV_REGS);
    }
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_add_bpt(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->machine.cpu.AddBreakpoint(static_cast<uint16_t>(argv[0].num & 0xFFFF));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_del_bpt(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->machine.cpu.RemoveBreakpoint(static_cast<uint16_t>(argv[0].num & 0xFFFF));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_k0dbg_exec(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_string("ERROR: k0dbg plugmod not active");
        return eOk;
    }
    std::string out;
    pm->machine.ExecuteCommand(argv[0].c_str(), out);
    invalidate_dbgmem_contents(0, BADADDR);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_string(out.c_str());
    return eOk;
}

error_t idaapi idc_k0dbg_load_prog_rom(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const char *path = argv[0].c_str();
    const bool empty = (!path || !*path);
    const bool ok = pm->LoadFlashAsset(true, path, empty);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_k0dbg_load_ea(idc_value_t *argv, idc_value_t *r) {
    k0dbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const char *path = argv[0].c_str();
    const bool empty = (!path || !*path);
    const bool ok = pm->LoadFlashAsset(false, path, empty);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_long(ok ? 1 : 0);
    return eOk;
}

const char kArgsNone[] = { 0 };
const char kArgsLong[] = { VT_LONG, 0 };
const char kArgsStr[] = { VT_STR, 0 };
const char kArgsStrLong[] = { VT_STR, VT_LONG, 0 };
const char kArgsLongLong[] = { VT_LONG, VT_LONG, 0 };

const ext_idcfunc_t kIdcFuncs[] = {
    { "k0dbg_start",         idc_k0dbg_start,         kArgsNone,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_stop",          idc_k0dbg_stop,          kArgsNone,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_step",          idc_k0dbg_step,          kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_run_to",        idc_k0dbg_run_to,        kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "k0dbg_get_reg",       idc_k0dbg_get_reg,       kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "k0dbg_set_reg",       idc_k0dbg_set_reg,       kArgsStrLong,  nullptr, 0, EXTFUN_BASE },
    { "k0dbg_read_u8",       idc_k0dbg_read_u8,       kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_write_u8",      idc_k0dbg_write_u8,      kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "k0dbg_read_u16",      idc_k0dbg_read_u16,      kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_write_u16",     idc_k0dbg_write_u16,     kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "k0dbg_add_bpt",       idc_k0dbg_add_bpt,       kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_del_bpt",       idc_k0dbg_del_bpt,       kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "k0dbg_exec",          idc_k0dbg_exec,          kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "k0dbg_load_prog_rom", idc_k0dbg_load_prog_rom, kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "k0dbg_load_ea",       idc_k0dbg_load_ea,       kArgsStr,      nullptr, 0, EXTFUN_BASE },
};

void k0dbg_plugmod_t::RegisterIdcFunctions() {
    if (!idc_registered) {
        for (const auto &fn : kIdcFuncs) {
            add_idc_func(fn);
        }
        idc_registered = true;
    }
}

void k0dbg_plugmod_t::UnregisterIdcFunctions() {
    if (idc_registered) {
        for (const auto &fn : kIdcFuncs) {
            del_idc_func(fn.name);
        }
        idc_registered = false;
    }
}

plugmod_t *idaapi init(void) {
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
    const bool is_78k0 = (PH.id == PLFM_NEC_78K0) || (proc0 != nullptr && strieq(proc0, "78k0"));
    if (!is_78k0) {
        return PLUGIN_SKIP;
    }

    if (proc0 != nullptr) {
        g_debugger.processor = proc0;
    }
    dbg = &g_debugger;
    return new k0dbg_plugmod_t();
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Integrated NEC 78K0 / Kx2 Emulator Debugger",
    "In-process NEC 78K0 / 78K0/Kx2 emulator debugger powered by k0emu.",
    "78K0 k0emu",
    ""
};
