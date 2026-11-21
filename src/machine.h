#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cpu.h"
#include "disasm.h"
#include "kx2_peripherals.h"
#include "memory.h"

namespace k0 {

class K0Machine {
public:
    K0Machine();

    void Configure(MachineProfile profile,
                   uint16_t rom_end = 0xC000u,
                   uint16_t exp_ram_start = 0xF400u,
                   uint16_t exp_ram_end = 0xF800u,
                   uint16_t ram_start = K0Bus::kHighSpeedRamStart);

    // Reset peripherals and CPU (reads reset vector from 0x0000 unless entry_override != -1).
    void Reset(int32_t entry_override = -1);

    // Load ROM file or raw bytes. If base_addr == 0 and size <= 0xF000, adjusts rom_end if larger.
    bool LoadRomBytes(const uint8_t *data, size_t size, uint16_t base_addr = 0);
    bool LoadRomFile(const char *path, uint16_t base_addr = 0);

    // Load 8 KB programmer mask ROM (78k0_programmer_fw.bin) and 0x800-byte Extra Area (EA.bin).
    bool LoadProgrammerRomBytes(const uint8_t *data, size_t size);
    bool LoadProgrammerRomFile(const char *path);
    bool LoadEaBytes(const uint8_t *data, size_t size);
    bool LoadEaFile(const char *path);

    static bool ParseFlmd0Mode(const char *arg, Kx2FlashCtrl::Flmd0Mode *out);

    StopInfo Step(bool ignore_bpt_at_pc = false);
    StopInfo RunSteps(uint64_t max_steps,
                      bool ignore_bpt_at_first_pc = false,
                      const std::atomic<bool> *cancel = nullptr);

    // Diagnostics & CLI command processor (shared by GDB qRcmd and IDA ev_rexec).
    std::string FormatStatus() const;
    std::string FormatIntc() const;
    std::string FormatClock() const;
    std::string FormatTimers() const;
    std::string FormatPorts() const;
    std::string FormatFlash() const;
    std::string FormatMemoryMap() const;
    bool ExecuteCommand(const std::string &cmdline, std::string &out);

    MachineProfile Profile() const { return profile_; }

    K0Bus bus;
    K0Cpu cpu;

    Kx2Intc intc;
    Kx2Clock clock;
    Kx2SystemCtrl sysctrl;
    Kx2Wdt wdt;
    Kx2Ports ports;
    Kx2Timer16 tm00;
    Kx2Timer16 tm01;
    Kx2Timer8 tm50;
    Kx2Timer8 tm51;
    Kx2TimerH tmh0;
    Kx2TimerH tmh1;
    Kx2WatchTimer wtm;
    Kx2Adc adc;
    Kx2Uart6 uart6;
    Kx2Uart0 uart0;
    Kx2Csi csi10;
    Kx2Csi csi11;
    Kx2Iic0 iic0;
    Kx2MulDiv muldiv;
    Kx2FlashCtrl flash;

private:
    void WirePeripherals();

    MachineProfile profile_ = MachineProfile::Kx2;
};

}  // namespace k0
