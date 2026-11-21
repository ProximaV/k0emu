#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "debugger.h"
#include "disasm.h"
#include "machine.h"

namespace {

void PrintUsage(const char *prog) {
    std::printf(
        "Usage: %s [options]\n"
        "Options:\n"
        "  --rom <path>           ROM binary to load at 0x0000\n"
        "  --prog-rom <path>      Programmer mask ROM binary (8 KB or 64 KB dump)\n"
        "  --ea <path>            Extra Area flash data binary (0x800 bytes)\n"
        "  --flmd0 <1|0|p23>      FLMD0 pin mode for FLPMC bit 2 (default: 1)\n"
        "  --product <hex>        Override product ID register 0xFFF5 (default: auto)\n"
        "  --profile <kx2|0831y>  Hardware profile (default: kx2)\n"
        "  --pc <addr>            Override initial PC (default: reset vector [0x0000])\n"
        "  --sp <addr>            Override initial SP (default: 0x0000)\n"
        "  --trace                Print instruction trace during headless run\n"
        "  --max-steps <n>        Maximum instructions in headless mode (0 = unlimited)\n"
        "  --map                  Print memory map and exit\n"
        "  --gdb, -g              Start GDB RSP server\n"
        "  --gdb-port <port>      GDB RSP TCP port (default: 23946, implies --gdb)\n"
        "  --headless             Run headless (default)\n"
        "  --help, -h             Show this help message\n",
        prog ? prog : "k0emu");
}

const char *StopReasonName(k0::StopReason r) {
    switch (r) {
    case k0::StopReason::None: return "None";
    case k0::StopReason::Breakpoint: return "Breakpoint";
    case k0::StopReason::Watchpoint: return "Watchpoint";
    case k0::StopReason::BreakInsn: return "BreakInsn";
    case k0::StopReason::Halt: return "Halt";
    case k0::StopReason::Stop: return "Stop";
    case k0::StopReason::UnmappedMemory: return "UnmappedMemory";
    case k0::StopReason::InvalidInsn: return "InvalidInsn";
    case k0::StopReason::WdtReset: return "WdtReset";
    }
    return "Unknown";
}

}  // namespace

int main(int argc, char *argv[]) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::string rom_path;
    std::string prog_rom_path;
    std::string ea_path;
    k0::Kx2FlashCtrl::Flmd0Mode flmd0_mode = k0::Kx2FlashCtrl::Flmd0Mode::High;
    int16_t product_override = -1;
    MachineProfile profile = MachineProfile::Kx2;
    int32_t pc_override = -1;
    int32_t sp_override = -1;
    bool trace = false;
    bool show_map = false;
    bool use_gdb = false;
    bool force_headless = false;
    int gdb_port = 23946;
    uint64_t max_steps = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (std::strcmp(arg, "--rom") == 0 && i + 1 < argc) {
            rom_path = argv[++i];
        } else if (std::strcmp(arg, "--prog-rom") == 0 && i + 1 < argc) {
            prog_rom_path = argv[++i];
        } else if (std::strcmp(arg, "--ea") == 0 && i + 1 < argc) {
            ea_path = argv[++i];
        } else if (std::strcmp(arg, "--flmd0") == 0 && i + 1 < argc) {
            if (!k0::K0Machine::ParseFlmd0Mode(argv[++i], &flmd0_mode)) {
                std::fprintf(stderr, "Invalid --flmd0 mode (expected 1|0|p23)\n");
                return 1;
            }
        } else if (std::strcmp(arg, "--product") == 0 && i + 1 < argc) {
            const char *pv = argv[++i];
            if (std::strcmp(pv, "auto") == 0) {
                product_override = -1;
            } else {
                product_override = static_cast<int16_t>(std::strtoul(pv, nullptr, 0) & 0xFFu);
            }
        } else if (std::strcmp(arg, "--profile") == 0 && i + 1 < argc) {
            const char *p = argv[++i];
            if (std::strcmp(p, "0831y") == 0 || std::strcmp(p, "0831") == 0) {
                profile = MachineProfile::Legacy0831;
            } else {
                profile = MachineProfile::Kx2;
            }
        } else if (std::strcmp(arg, "--pc") == 0 && i + 1 < argc) {
            pc_override = static_cast<int32_t>(std::strtoul(argv[++i], nullptr, 0) & 0xFFFFu);
        } else if (std::strcmp(arg, "--sp") == 0 && i + 1 < argc) {
            sp_override = static_cast<int32_t>(std::strtoul(argv[++i], nullptr, 0) & 0xFFFFu);
        } else if (std::strcmp(arg, "--trace") == 0) {
            trace = true;
        } else if (std::strcmp(arg, "--map") == 0) {
            show_map = true;
        } else if (std::strcmp(arg, "--max-steps") == 0 && i + 1 < argc) {
            max_steps = std::strtoull(argv[++i], nullptr, 0);
        } else if (std::strcmp(arg, "--gdb") == 0 || std::strcmp(arg, "-g") == 0) {
            use_gdb = true;
        } else if (std::strcmp(arg, "--gdb-port") == 0 && i + 1 < argc) {
            gdb_port = std::atoi(argv[++i]);
            use_gdb = true;
        } else if (std::strcmp(arg, "--headless") == 0) {
            force_headless = true;
            use_gdb = false;
        } else {
            std::fprintf(stderr, "Unknown or incomplete option: %s\n", arg);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    k0::K0Machine machine;
    if (profile == MachineProfile::Legacy0831) {
        machine.Configure(MachineProfile::Legacy0831, 0xF000u, 0xF000u, 0xF800u);
    } else {
        machine.Configure(MachineProfile::Kx2, 0xC000u, 0xF400u, 0xF800u);
    }

    if (show_map) {
        std::printf("%s", machine.FormatMemoryMap().c_str());
        return 0;
    }

    if (!rom_path.empty()) {
        if (!machine.LoadRomFile(rom_path.c_str(), 0)) {
            std::fprintf(stderr, "Failed to load ROM image: %s\n", rom_path.c_str());
            return 1;
        }
    } else if (!use_gdb) {
        std::fprintf(stderr, "No ROM specified. Use --rom <path> or --gdb.\n");
        PrintUsage(argv[0]);
        return 1;
    }

    if (!prog_rom_path.empty() && !machine.LoadProgrammerRomFile(prog_rom_path.c_str())) {
        std::fprintf(stderr, "Failed to load programmer ROM image: %s\n", prog_rom_path.c_str());
        return 1;
    }
    if (!ea_path.empty() && !machine.LoadEaFile(ea_path.c_str())) {
        std::fprintf(stderr, "Failed to load Extra Area image: %s\n", ea_path.c_str());
        return 1;
    }
    machine.flash.SetFlmd0Mode(flmd0_mode);
    machine.flash.SetProductOverride(product_override);

    machine.Reset(pc_override);
    if (sp_override >= 0) {
        machine.cpu.SetSP(static_cast<uint16_t>(sp_override));
    }

    if (use_gdb && !force_headless) {
        k0::Debugger dbg(&machine, gdb_port);
        if (!dbg.WaitForConnection()) {
            std::fprintf(stderr, "GDB server failed on port %d\n", gdb_port);
            return 1;
        }
        return 0;
    }

    k0::StopInfo stop{};
    if (trace) {
        uint64_t step = 0;
        while (max_steps == 0 || step < max_steps) {
            const uint16_t pc_before = machine.cpu.GetPC();
            const k0::DecodedInsn di = k0::DisassembleAt(machine.bus, pc_before);
            stop = machine.Step(false);
            const uint8_t psw = machine.cpu.GetPSW();
            std::printf("%-42s AX=%04X BC=%04X DE=%04X HL=%04X SP=%04X [IE:%d RB:%d ISP:%d Z:%d AC:%d CY:%d] T=%llu\n",
                        di.FormatWithBytes().c_str(),
                        machine.cpu.ReadRegPair(k0::RP_AX),
                        machine.cpu.ReadRegPair(k0::RP_BC),
                        machine.cpu.ReadRegPair(k0::RP_DE),
                        machine.cpu.ReadRegPair(k0::RP_HL),
                        machine.cpu.GetSP(),
                        (psw & k0::PSW_IE) ? 1 : 0,
                        machine.cpu.GetRB(),
                        (psw & k0::PSW_ISP) ? 1 : 0,
                        (psw & k0::PSW_Z) ? 1 : 0,
                        (psw & k0::PSW_AC) ? 1 : 0,
                        (psw & k0::PSW_CY) ? 1 : 0,
                        static_cast<unsigned long long>(machine.cpu.TotalCycles()));
            ++step;
            if (stop.reason != k0::StopReason::None) {
                break;
            }
        }
    } else {
        stop = machine.RunSteps(max_steps);
    }

    std::printf("Stopped: %s at PC=0x%04X (detail=0x%04X)\n%s\n",
                StopReasonName(stop.reason), stop.pc, stop.detail,
                machine.FormatStatus().c_str());
    return 0;
}
