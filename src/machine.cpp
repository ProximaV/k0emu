#include "machine.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>

namespace k0 {

namespace {

std::string Trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(start, end - start);
}

std::vector<std::string> SplitArgs(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        out.push_back(tok);
    }
    return out;
}

const char *RunStateName(RunState st) {
    switch (st) {
    case RunState::Running: return "RUNNING";
    case RunState::Halted:  return "HALTED";
    case RunState::Stopped: return "STOPPED";
    }
    return "?";
}

bool EqIgnoreCase(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) !=
            std::tolower(static_cast<unsigned char>(*b))) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

const char *Flmd0ModeName(Kx2FlashCtrl::Flmd0Mode mode) {
    switch (mode) {
    case Kx2FlashCtrl::Flmd0Mode::High:   return "high";
    case Kx2FlashCtrl::Flmd0Mode::Low:    return "low";
    case Kx2FlashCtrl::Flmd0Mode::PinP23: return "p23";
    }
    return "?";
}

std::string ExtractTrailingArg(const std::string &trimmed, size_t cmd_len) {
    if (trimmed.size() <= cmd_len) {
        return std::string();
    }
    std::string arg = Trim(trimmed.substr(cmd_len));
    if (arg.size() >= 2 &&
        ((arg.front() == '"' && arg.back() == '"') ||
         (arg.front() == '\'' && arg.back() == '\''))) {
        arg = arg.substr(1, arg.size() - 2);
    }
    return arg;
}

bool ReadBinaryFile(const char *path, std::vector<uint8_t> *out) {
    if (!path || !*path || !out) return false;
    std::FILE *fp = std::fopen(path, "rb");
    if (!fp) return false;
    std::fseek(fp, 0, SEEK_END);
    const long fsz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (fsz < 0) {
        std::fclose(fp);
        return false;
    }
    out->resize(static_cast<size_t>(fsz));
    if (fsz > 0) {
        const size_t nread = std::fread(out->data(), 1, out->size(), fp);
        if (nread != out->size()) {
            std::fclose(fp);
            out->clear();
            return false;
        }
    }
    std::fclose(fp);
    return true;
}

}  // namespace

K0Machine::K0Machine()
    : intc(MachineProfile::Kx2),
      sysctrl(&bus),
      wdt(&bus, &cpu, &sysctrl, &clock, &intc),
      ports(&intc),
      tm00(0, &intc, 14, 15),
      tm01(1, &intc, 26, 27),
      tm50(0, &intc, 13),
      tm51(1, &intc, 19),
      tmh0(0, &intc, 12),
      tmh1(1, &intc, 11),
      wtm(MachineProfile::Kx2, &intc, 18, 21),
      adc(MachineProfile::Kx2, &intc, 16),
      uart6(&intc, 8, 9, 7),
      uart0(&intc, 17, 10),
      csi10(0, MachineProfile::Kx2, &intc, 10),
      csi11(1, MachineProfile::Kx2, &intc, 25),
      iic0(MachineProfile::Kx2, &intc, 24),
      muldiv(&intc, 24),
      flash(&bus, &ports) {
    Configure(MachineProfile::Kx2, 0xC000u, 0xF400u, 0xF800u, K0Bus::kHighSpeedRamStart);
}

void K0Machine::Configure(MachineProfile profile,
                          uint16_t rom_end,
                          uint16_t exp_ram_start,
                          uint16_t exp_ram_end,
                          uint16_t ram_start) {
    profile_ = profile;
    bus.ClearAllDevices();
    bus.ConfigureLayout(profile, rom_end, exp_ram_start, exp_ram_end, ram_start);
    WirePeripherals();
}

void K0Machine::WirePeripherals() {
    cpu.AttachBus(&bus);  // maps 0xFF1C..0xFF1E
    cpu.AttachIntc(&intc);
    cpu.AttachClock(&clock);

    intc.SetProfile(profile_);
    bus.MapSfrRange(0xFFE0u, 0xFFEBu, &intc);

    if (profile_ == MachineProfile::Legacy0831) {
        wtm.SetProfile(MachineProfile::Legacy0831, 16, 23);
        adc.SetProfile(MachineProfile::Legacy0831, 21);
        csi10.SetProfile(MachineProfile::Legacy0831, 12);
        csi11.SetProfile(MachineProfile::Legacy0831, 13);
        iic0.SetProfile(MachineProfile::Legacy0831, 14);

        bus.MapSfr(0xFF41u, &wtm);
        bus.MapSfr(0xFF42u, &wdt);
        bus.MapSfr(0xFFF9u, &wdt);
        bus.MapSfr(0xFF17u, &adc);
        bus.MapSfrRange(0xFF80u, 0xFF81u, &adc);
        bus.MapSfr(0xFF1Au, &csi10);
        bus.MapSfr(0xFFB0u, &csi10);
        bus.MapSfr(0xFF1Bu, &csi11);
        bus.MapSfr(0xFFB8u, &csi11);
        bus.MapSfr(0xFF1Fu, &iic0);
        bus.MapSfrRange(0xFFA8u, 0xFFAAu, &iic0);
        bus.MapSfrRange(0xFF00u, 0xFF09u, &ports);
        bus.MapSfrRange(0xFF20u, 0xFF29u, &ports);
        return;
    }

    // 78K0/Kx2 peripheral map per 78K0KX2.pdf Table 3-8
    wtm.SetProfile(MachineProfile::Kx2, 18, 21);
    adc.SetProfile(MachineProfile::Kx2, 16);
    csi10.SetProfile(MachineProfile::Kx2, 10);
    csi11.SetProfile(MachineProfile::Kx2, 25);
    iic0.SetProfile(MachineProfile::Kx2, 24);

    // Ports & external interrupt edges
    bus.MapSfrRange(0xFF00u, 0xFF07u, &ports);
    bus.MapSfrRange(0xFF0Cu, 0xFF0Eu, &ports);
    bus.MapSfrRange(0xFF20u, 0xFF27u, &ports);
    bus.MapSfr(0xFF2Cu, &ports);
    bus.MapSfrRange(0xFF2Eu, 0xFF37u, &ports);
    bus.MapSfr(0xFF3Cu, &ports);
    bus.MapSfr(0xFF3Eu, &ports);
    bus.MapSfrRange(0xFF48u, 0xFF49u, &ports);
    bus.MapSfr(0xFF4Fu, &ports);
    bus.MapSfr(0xFF6Eu, &ports);

    // ADC
    bus.MapSfrRange(0xFF08u, 0xFF09u, &adc);
    bus.MapSfrRange(0xFF28u, 0xFF29u, &adc);

    // UART6 & UART0
    bus.MapSfrRange(0xFF0Au, 0xFF0Bu, &uart6);
    bus.MapSfr(0xFF50u, &uart6);
    bus.MapSfr(0xFF53u, &uart6);
    bus.MapSfrRange(0xFF55u, 0xFF58u, &uart6);
    bus.MapSfrRange(0xFF70u, 0xFF74u, &uart0);

    // CSI10 & CSI11
    bus.MapSfr(0xFF0Fu, &csi10);
    bus.MapSfrRange(0xFF80u, 0xFF81u, &csi10);
    bus.MapSfr(0xFF84u, &csi10);
    bus.MapSfr(0xFF4Au, &csi11);
    bus.MapSfr(0xFF4Cu, &csi11);
    bus.MapSfrRange(0xFF88u, 0xFF89u, &csi11);

    // 16-bit Timers 00 & 01
    bus.MapSfrRange(0xFF10u, 0xFF15u, &tm00);
    bus.MapSfrRange(0xFFBAu, 0xFFBDu, &tm00);
    bus.MapSfrRange(0xFFB0u, 0xFFB9u, &tm01);

    // 8-bit Timers 50 & 51
    bus.MapSfrRange(0xFF16u, 0xFF17u, &tm50);
    bus.MapSfrRange(0xFF6Au, 0xFF6Bu, &tm50);
    bus.MapSfr(0xFF1Fu, &tm51);
    bus.MapSfr(0xFF41u, &tm51);
    bus.MapSfr(0xFF43u, &tm51);
    bus.MapSfr(0xFF8Cu, &tm51);

    // 8-bit Timers H0 & H1
    bus.MapSfrRange(0xFF18u, 0xFF19u, &tmh0);
    bus.MapSfr(0xFF69u, &tmh0);
    bus.MapSfrRange(0xFF1Au, 0xFF1Bu, &tmh1);
    bus.MapSfrRange(0xFF6Cu, 0xFF6Du, &tmh1);

    // Multiplier / Divider
    bus.MapSfrRange(0xFF60u, 0xFF68u, &muldiv);

    // Watch Timer & Watchdog
    bus.MapSfr(0xFF6Fu, &wtm);
    bus.MapSfr(0xFF99u, &wdt);

    // Clock Generator
    bus.MapSfrRange(0xFF9Fu, 0xFFA4u, &clock);
    bus.MapSfr(0xFFFBu, &clock);

    // IIC0
    bus.MapSfrRange(0xFFA5u, 0xFFABu, &iic0);

    // System Control / Memory Bank / Reset / LVI
    bus.MapSfr(0xFFACu, &sysctrl);
    bus.MapSfrRange(0xFFBEu, 0xFFBFu, &sysctrl);
    bus.MapSfr(0xFFF0u, &sysctrl);
    bus.MapSfr(0xFFF3u, &sysctrl);
    bus.MapSfr(0xFFF4u, &sysctrl);

    // Internal Flash & Programmer ROM Controller
    bus.MapSfrRange(0xFFC0u, 0xFFCFu, &flash);
    bus.MapSfr(0xFFF5u, &flash);
    bus.MapFlashBuf(&flash);
}

void K0Machine::Reset(int32_t entry_override) {
    sysctrl.ClearResetFlags();
    bus.ResetDevices();
    if (entry_override >= 0) {
        cpu.ResetTo(static_cast<uint16_t>(entry_override & 0xFFFF));
    } else {
        cpu.Reset();
    }
}

bool K0Machine::LoadRomBytes(const uint8_t *data, size_t size, uint16_t base_addr) {
    return bus.LoadRom(data, size, base_addr);
}

bool K0Machine::LoadRomFile(const char *path, uint16_t base_addr) {
    std::vector<uint8_t> buf;
    if (!ReadBinaryFile(path, &buf)) return false;
    return bus.LoadRom(buf.data(), buf.size(), base_addr);
}

bool K0Machine::LoadProgrammerRomBytes(const uint8_t *data, size_t size) {
    return bus.LoadProgrammerRom(data, size);
}

bool K0Machine::LoadProgrammerRomFile(const char *path) {
    std::vector<uint8_t> buf;
    if (!ReadBinaryFile(path, &buf) || buf.empty()) return false;
    return bus.LoadProgrammerRom(buf.data(), buf.size());
}

bool K0Machine::LoadEaBytes(const uint8_t *data, size_t size) {
    return flash.LoadEaBytes(data, size);
}

bool K0Machine::LoadEaFile(const char *path) {
    std::vector<uint8_t> buf;
    if (!ReadBinaryFile(path, &buf)) return false;
    return flash.LoadEaBytes(buf.data(), buf.size());
}

bool K0Machine::ParseFlmd0Mode(const char *arg, Kx2FlashCtrl::Flmd0Mode *out) {
    if (!arg || !out) return false;
    if (EqIgnoreCase(arg, "1") || EqIgnoreCase(arg, "high") || EqIgnoreCase(arg, "true")) {
        *out = Kx2FlashCtrl::Flmd0Mode::High;
        return true;
    }
    if (EqIgnoreCase(arg, "0") || EqIgnoreCase(arg, "low") || EqIgnoreCase(arg, "false")) {
        *out = Kx2FlashCtrl::Flmd0Mode::Low;
        return true;
    }
    if (EqIgnoreCase(arg, "p23") || EqIgnoreCase(arg, "p2.3") || EqIgnoreCase(arg, "auto")) {
        *out = Kx2FlashCtrl::Flmd0Mode::PinP23;
        return true;
    }
    return false;
}

StopInfo K0Machine::Step(bool ignore_bpt_at_pc) {
    return cpu.Step(ignore_bpt_at_pc);
}

StopInfo K0Machine::RunSteps(uint64_t max_steps,
                             bool ignore_bpt_at_first_pc,
                             const std::atomic<bool> *cancel) {
    uint64_t count = 0;
    while (max_steps == 0 || count < max_steps) {
        if (cancel && cancel->load()) {
            return StopInfo{StopReason::None, cpu.GetPC(), 0, false};
        }
        const bool ignore = (count == 0) && ignore_bpt_at_first_pc;
        const StopInfo stop = cpu.Step(ignore);
        ++count;
        if (stop.reason != StopReason::None) {
            return stop;
        }
    }
    return StopInfo{StopReason::None, cpu.GetPC(), 0, false};
}

std::string K0Machine::FormatStatus() const {
    const uint8_t psw = cpu.GetPSW();
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "PC=%04X SP=%04X PSW=%02X [IE:%d Z:%d RBS:%d AC:%d ISP:%d CY:%d] %s\n"
        "AX=%04X BC=%04X DE=%04X HL=%04X | BANK=%u IMS=%02X IXS=%02X PCC=%02X | Cycles=%llu Insns=%llu",
        cpu.GetPC(), cpu.GetSP(), psw,
        (psw & PSW_IE) ? 1 : 0,
        (psw & PSW_Z) ? 1 : 0,
        cpu.GetRB(),
        (psw & PSW_AC) ? 1 : 0,
        (psw & PSW_ISP) ? 1 : 0,
        (psw & PSW_CY) ? 1 : 0,
        RunStateName(cpu.GetRunState()),
        cpu.ReadRegPair(RP_AX),
        cpu.ReadRegPair(RP_BC),
        cpu.ReadRegPair(RP_DE),
        cpu.ReadRegPair(RP_HL),
        bus.GetActiveBank(),
        sysctrl.GetIms(),
        sysctrl.GetIxs(),
        clock.GetPcc(),
        static_cast<unsigned long long>(cpu.TotalCycles()),
        static_cast<unsigned long long>(cpu.InstructionCount()));
    return buf;
}

std::string K0Machine::FormatIntc() const {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "PSW=%02X (IE=%d ISP=%d)\n"
        "IF0L=%02X IF0H=%02X IF1L=%02X IF1H=%02X\n"
        "MK0L=%02X MK0H=%02X MK1L=%02X MK1H=%02X\n"
        "PR0L=%02X PR0H=%02X PR1L=%02X PR1H=%02X",
        cpu.GetPSW(),
        (cpu.GetPSW() & PSW_IE) ? 1 : 0,
        (cpu.GetPSW() & PSW_ISP) ? 1 : 0,
        intc.Peek(0xFFE0u), intc.Peek(0xFFE1u), intc.Peek(0xFFE2u), intc.Peek(0xFFE3u),
        intc.Peek(0xFFE4u), intc.Peek(0xFFE5u), intc.Peek(0xFFE6u), intc.Peek(0xFFE7u),
        intc.Peek(0xFFE8u), intc.Peek(0xFFE9u), intc.Peek(0xFFEAu), intc.Peek(0xFFEBu));
    return buf;
}

std::string K0Machine::FormatClock() const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "PCC=%02X (CLS=%d CSS=%d div=%u) RCM=%02X (RSTS=%d LSRSTOP=%d RSTOP=%d)\n"
        "MCM=%02X (MCS=%d) MOC=%02X OSCCTL=%02X OSTC=%02X OSTS=%02X\n"
        "WDT: opt=%02X enabled=%d cnt=%u/%u RESF=%02X",
        clock.GetPcc(), (clock.GetPcc() >> 5) & 1, (clock.GetPcc() >> 4) & 1, clock.GetPcc() & 7,
        clock.GetRcm(), (clock.GetRcm() >> 7) & 1, (clock.GetRcm() >> 1) & 1, clock.GetRcm() & 1,
        clock.GetMcm(), (clock.GetMcm() >> 1) & 1,
        clock.GetMoc(), clock.GetOscctl(), clock.GetOstc(), clock.GetOsts(),
        wdt.GetOptionByte(), wdt.IsEnabled() ? 1 : 0,
        wdt.GetCounter(), wdt.GetOverflowPeriod(), sysctrl.GetResf());
    return buf;
}

std::string K0Machine::FormatTimers() const {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "TM00=%04X CR000=%04X CR010=%04X TMC00=%02X PRM00=%02X\n"
        "TM01=%04X CR001=%04X CR011=%04X TMC01=%02X PRM01=%02X\n"
        "TM50=%02X CR50=%02X TMC50=%02X | TM51=%02X CR51=%02X TMC51=%02X\n"
        "TMH0: CMP00=%02X CMP10=%02X MD0=%02X | TMH1: CMP01=%02X CMP11=%02X MD1=%02X\n"
        "WTM=%02X (prescaler=%u)",
        tm00.GetCounter(), tm00.GetCr0(), tm00.GetCr1(), tm00.GetTmc(), tm00.GetPrm(),
        tm01.GetCounter(), tm01.GetCr0(), tm01.GetCr1(), tm01.GetTmc(), tm01.GetPrm(),
        tm50.GetCounter(), tm50.GetCompare(), tm50.GetTmc(),
        tm51.GetCounter(), tm51.GetCompare(), tm51.GetTmc(),
        tmh0.GetCmp0(), tmh0.GetCmp1(), tmh0.GetMode(),
        tmh1.GetCmp0(), tmh1.GetCmp1(), tmh1.GetMode(),
        wtm.GetWtm(), wtm.GetPrescalerCounter());
    return buf;
}

std::string K0Machine::FormatPorts() const {
    static const uint8_t kPortNums[] = { 0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14 };
    std::string out;
    char buf[96];
    for (uint8_t p : kPortNums) {
        std::snprintf(buf, sizeof(buf), "P%-2u: pin=%02X latch=%02X PM=%02X ext=%02X\n",
                      p, ports.GetPinState(p), ports.GetLatch(p), ports.GetMode(p), ports.GetExternalInput(p));
        out += buf;
    }
    return out;
}

std::string K0Machine::FormatFlash() const {
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "ProgROM=%s overlay=%s (8000:%d 0000:%d) | EA=%s (0x%04zX bytes)\n"
        "PROD(FFF5)=%02X (flash=%uB%s) FLMD0=%d (mode=%s)\n"
        "PFCMD=%02X FLM0=%02X FLPMC=%02X FLCTL=%02X FLSTS=%02X FLREG=%02X\n"
        "FLADR=%06X DataBuf[F8F4..F5,F2..F3]=%02X %02X %02X %02X (reads=%llu last=%s@%06X)",
        bus.IsProgrammerRomLoaded() ? "loaded" : "none",
        bus.GetProgOverlayMask() ? "ON" : "off",
        bus.IsProgOverlayHigh() ? 1 : 0,
        bus.IsProgOverlayLow() ? 1 : 0,
        flash.IsEaLoaded() ? "loaded" : "default(0xFF)",
        Kx2FlashCtrl::kEaSize,
        flash.GetProductId(),
        bus.TotalFlashSize(),
        (flash.GetProductOverride() >= 0) ? ", override" : ", auto",
        flash.IsFlmd0High() ? 1 : 0,
        Flmd0ModeName(flash.GetFlmd0Mode()),
        flash.Peek(0xFFC0u), flash.Peek(0xFFC1u), flash.Peek(0xFFC4u),
        flash.Peek(0xFFC5u), flash.Peek(0xFFC7u), flash.Peek(0xFFCAu),
        flash.GetCurrentAddressReg(),
        flash.Peek(0xF8F4u), flash.Peek(0xF8F5u), flash.Peek(0xF8F2u), flash.Peek(0xF8F3u),
        static_cast<unsigned long long>(flash.GetReadCount()),
        flash.LastReadWasEa() ? "EA" : "MAIN",
        flash.GetLastReadAddr());
    return buf;
}

std::string K0Machine::FormatMemoryMap() const {
    std::string out;
    char buf[128];
    for (const auto &r : bus.GetRegions()) {
        std::snprintf(buf, sizeof(buf), "  %04X-%04X  %5u  %-10s %s%s%s\n",
                      r.start, static_cast<uint32_t>(r.start) + r.size - 1u, r.size,
                      r.name.c_str(),
                      (r.perm & MEM_PERM_READ) ? "R" : "-",
                      (r.perm & MEM_PERM_WRITE) ? "W" : "-",
                      (r.perm & MEM_PERM_EXEC) ? "X" : "-");
        out += buf;
    }
    return out;
}

bool K0Machine::ExecuteCommand(const std::string &cmdline, std::string &out) {
    out.clear();
    const std::string trimmed = Trim(cmdline);
    if (trimmed.empty()) return true;
    const auto args = SplitArgs(trimmed);
    const std::string &cmd = args[0];

    char buf[512];
    if (cmd == "help" || cmd == "?") {
        out =
            "[k0emu] Commands:\n"
            "  status                - Print CPU, PSW, GPRs, bank, and cycle count\n"
            "  banks                 - Print all 4 GPR register banks (RB0..RB3)\n"
            "  intc                  - Print IF/MK/PR interrupt registers\n"
            "  irq <name|idx>        - Raise interrupt request (e.g. irq INTP0, irq 1)\n"
            "  clock                 - Print clock generator & WDT state\n"
            "  timers                - Print TM00/01, TM50/51, TMH0/1, WTM state\n"
            "  ports                 - Print GPIO port pin states, latches, and PMn\n"
            "  pin <port> <bit> <0|1>- Set external input pin level (triggers EGP/EGN/KRM)\n"
            "  adc <ch> <val10>      - Set ADC analog channel value (0..1023)\n"
            "  uart6rx <hex|ascii>   - Inject RX byte into UART6\n"
            "  uart6tx               - Dump UART6 TX log\n"
            "  bank <n>              - Switch active flash memory bank (0..5)\n"
            "  flash                 - Print programmer ROM overlay & EA flash controller state\n"
            "  load_prog <path>      - Load 78k0_programmer_fw.bin (8 KB or 64 KB)\n"
            "  load_ea <path>        - Load EA.bin (0x800 bytes)\n"
            "  flmd0 <1|0|p23>       - Configure FLMD0 pin state (FLPMC.2)\n"
            "  product <hex|auto>    - Set or auto-derive product ID register (0xFFF5)\n"
            "  disasm [addr] [count] - Disassemble instructions (default PC, 10)\n"
            "  map                   - Print memory map\n"
            "  step [n]              - Execute n instructions (default 1)\n";
        return true;
    }
    if (cmd == "status") {
        out = FormatStatus();
        return true;
    }
    if (cmd == "banks") {
        for (uint8_t b = 0; b < 4; ++b) {
            std::snprintf(buf, sizeof(buf), "RB%u%s: AX=%04X BC=%04X DE=%04X HL=%04X\n",
                          b, (b == cpu.GetRB()) ? "*" : " ",
                          cpu.ReadRegPairBank(RP_AX, b),
                          cpu.ReadRegPairBank(RP_BC, b),
                          cpu.ReadRegPairBank(RP_DE, b),
                          cpu.ReadRegPairBank(RP_HL, b));
            out += buf;
        }
        return true;
    }
    if (cmd == "intc") {
        out = FormatIntc();
        return true;
    }
    if (cmd == "irq" && args.size() >= 2) {
        const int idx = intc.FindIrqByName(args[1].c_str());
        if (idx < 0) {
            out = "[k0emu] Unknown IRQ: " + args[1];
            return false;
        }
        intc.RaiseIrq(static_cast<uint8_t>(idx));
        std::snprintf(buf, sizeof(buf), "[k0emu] Raised IRQ %d (%s)",
                      idx, intc.Sources()[static_cast<size_t>(idx)].name);
        out = buf;
        return true;
    }
    if (cmd == "clock") {
        out = FormatClock();
        return true;
    }
    if (cmd == "timers") {
        out = FormatTimers();
        return true;
    }
    if (cmd == "ports") {
        out = FormatPorts();
        return true;
    }
    if (cmd == "pin" && args.size() >= 4) {
        const uint8_t port = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0));
        const uint8_t bit = static_cast<uint8_t>(std::strtoul(args[2].c_str(), nullptr, 0));
        const bool high = std::strtoul(args[3].c_str(), nullptr, 0) != 0;
        ports.SetExternalInput(port, bit, high);
        std::snprintf(buf, sizeof(buf), "[k0emu] P%u.%u <- %d (P%u=%02X)",
                      port, bit & 7u, high ? 1 : 0, port, ports.GetPinState(port));
        out = buf;
        return true;
    }
    if (cmd == "adc" && args.size() >= 3) {
        const uint8_t ch = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0)) & 7u;
        const uint16_t val = static_cast<uint16_t>(std::strtoul(args[2].c_str(), nullptr, 0)) & 0x3FFu;
        adc.SetChannelValue(ch, val);
        std::snprintf(buf, sizeof(buf), "[k0emu] ANI%u = 0x%03X (%u)", ch, val, val);
        out = buf;
        return true;
    }
    if (cmd == "uart6rx" && args.size() >= 2) {
        const uint8_t byte = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0));
        uart6.InjectRxByte(byte);
        std::snprintf(buf, sizeof(buf), "[k0emu] Injected UART6 RX 0x%02X", byte);
        out = buf;
        return true;
    }
    if (cmd == "uart6tx") {
        const auto &tx = uart6.TxLog();
        std::snprintf(buf, sizeof(buf), "[k0emu] UART6 TX (%zu bytes): ", tx.size());
        out = buf;
        for (uint8_t b : tx) {
            std::snprintf(buf, sizeof(buf), "%02X ", b);
            out += buf;
        }
        return true;
    }
    if (cmd == "bank" && args.size() >= 2) {
        const uint8_t b = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0)) & 7u;
        sysctrl.Poke(0xFFF3u, b);
        std::snprintf(buf, sizeof(buf), "[k0emu] Active ROM bank = %u", bus.GetActiveBank());
        out = buf;
        return true;
    }
    if (cmd == "flash") {
        out = FormatFlash();
        return true;
    }
    if (cmd == "load_prog") {
        const std::string path = ExtractTrailingArg(trimmed, cmd.size());
        if (path.empty() || !LoadProgrammerRomFile(path.c_str())) {
            out = "[k0emu] Failed to load programmer ROM image.";
            return false;
        }
        out = "[k0emu] Loaded programmer ROM (8192 bytes).";
        return true;
    }
    if (cmd == "load_ea") {
        const std::string path = ExtractTrailingArg(trimmed, cmd.size());
        if (path.empty() || !LoadEaFile(path.c_str())) {
            out = "[k0emu] Failed to load Extra Area image.";
            return false;
        }
        std::snprintf(buf, sizeof(buf), "[k0emu] Loaded Extra Area (%zu bytes).", Kx2FlashCtrl::kEaSize);
        out = buf;
        return true;
    }
    if (cmd == "flmd0" && args.size() >= 2) {
        Kx2FlashCtrl::Flmd0Mode mode = Kx2FlashCtrl::Flmd0Mode::High;
        if (!ParseFlmd0Mode(args[1].c_str(), &mode)) {
            out = "[k0emu] Invalid flmd0 mode (use 1|high, 0|low, or p23).";
            return false;
        }
        flash.SetFlmd0Mode(mode);
        std::snprintf(buf, sizeof(buf), "[k0emu] FLMD0 mode = %s (bit2=%d)",
                      Flmd0ModeName(mode), flash.IsFlmd0High() ? 1 : 0);
        out = buf;
        return true;
    }
    if (cmd == "product" && args.size() >= 2) {
        if (EqIgnoreCase(args[1].c_str(), "auto")) {
            flash.SetProductOverride(-1);
        } else {
            const uint8_t val = static_cast<uint8_t>(std::strtoul(args[1].c_str(), nullptr, 0) & 0xFFu);
            flash.SetProductOverride(val);
        }
        std::snprintf(buf, sizeof(buf), "[k0emu] PROD (0xFFF5) = 0x%02X", flash.GetProductId());
        out = buf;
        return true;
    }
    if (cmd == "disasm") {
        uint16_t addr = cpu.GetPC();
        int count = 10;
        if (args.size() >= 2) {
            addr = static_cast<uint16_t>(std::strtoul(args[1].c_str(), nullptr, 16));
        }
        if (args.size() >= 3) {
            count = std::max(1, std::min(64, std::atoi(args[2].c_str())));
        }
        for (int i = 0; i < count; ++i) {
            const DecodedInsn di = DisassembleAt(bus, addr);
            out += (addr == cpu.GetPC() ? "> " : "  ") + di.FormatWithBytes() + "\n";
            addr = static_cast<uint16_t>(addr + (di.length ? di.length : 1u));
        }
        return true;
    }
    if (cmd == "map") {
        out = FormatMemoryMap();
        return true;
    }
    if (cmd == "step") {
        uint64_t count = 1;
        if (args.size() >= 2) {
            count = std::strtoull(args[1].c_str(), nullptr, 0);
            if (count == 0) count = 1;
        }
        const StopInfo stop = RunSteps(count, true, nullptr);
        std::snprintf(buf, sizeof(buf), "[k0emu] Stepped -> PC=%04X (reason=%d)\n%s",
                      stop.pc, static_cast<int>(stop.reason), FormatStatus().c_str());
        out = buf;
        return true;
    }

    out = "[k0emu] Unknown command '" + cmd + "'. Type 'help' for commands.";
    return false;
}

}  // namespace k0
