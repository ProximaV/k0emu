#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class MachineProfile {
    Kx2 = 0,
    Legacy0831 = 1,
};

enum MemPerm : uint8_t {
    MEM_PERM_READ  = 1,
    MEM_PERM_WRITE = 2,
    MEM_PERM_EXEC  = 4,
    MEM_PERM_RW    = MEM_PERM_READ | MEM_PERM_WRITE,
    MEM_PERM_RX    = MEM_PERM_READ | MEM_PERM_EXEC,
    MEM_PERM_RWX   = MEM_PERM_READ | MEM_PERM_WRITE | MEM_PERM_EXEC,
};

struct MemoryRegion {
    uint16_t start = 0;
    uint32_t size = 0;
    std::string name;
    bool is_device = false;
    uint8_t perm = MEM_PERM_RWX;
};

struct Watchpoint {
    uint16_t addr = 0;
    uint16_t size = 1;
    int type = 0;  // bit 0 (1) = write, bit 1 (2) = read, 3 = read/write
};

class PeripheralDevice {
public:
    virtual ~PeripheralDevice() = default;

    // CPU-initiated access (may trigger hardware side effects).
    virtual uint8_t Read(uint16_t addr) = 0;
    virtual void Write(uint16_t addr, uint8_t value) = 0;

    // Debugger / inspection access (side-effect-free).
    virtual uint8_t Peek(uint16_t addr) const = 0;
    virtual void Poke(uint16_t addr, uint8_t value) { Write(addr, value); }

    virtual void Reset() {}
    virtual void Tick(uint32_t cpu_cycles,
                      uint32_t prs_cycles,
                      uint32_t sub_cycles,
                      uint32_t rl_cycles,
                      bool in_halt,
                      bool in_stop) {
        (void)cpu_cycles;
        (void)prs_cycles;
        (void)sub_cycles;
        (void)rl_cycles;
        (void)in_halt;
        (void)in_stop;
    }
};

class K0Bus {
public:
    static constexpr uint32_t kAddressSpaceSize = 0x10000u;
    static constexpr uint16_t kHighSpeedRamStart = 0xFB00u;
    static constexpr uint16_t kHighSpeedRamEnd   = 0xFEDFu;
    static constexpr uint16_t kGprStart          = 0xFEE0u;
    static constexpr uint16_t kGprEnd            = 0xFEFFu;
    static constexpr uint16_t kSfrStart          = 0xFF00u;
    static constexpr uint16_t kSfrEnd            = 0xFFFFu;
    static constexpr uint16_t kBankWindowStart   = 0x8000u;
    static constexpr uint16_t kBankWindowEnd     = 0xBFFFu;
    static constexpr uint32_t kBankSize          = 0x4000u;
    static constexpr uint8_t  kMaxBanks          = 6u;
    static constexpr uint16_t kProgRomSize       = 0x2000u;
    static constexpr uint16_t kProgRomLowStart   = 0x0000u;
    static constexpr uint16_t kProgRomHighStart  = 0x8000u;
    static constexpr uint16_t kFlashBufStart     = 0xF8F0u;
    static constexpr uint16_t kFlashBufEnd       = 0xF8FFu;

    K0Bus();

    void ConfigureLayout(MachineProfile profile,
                         uint16_t rom_end,
                         uint16_t exp_ram_start,
                         uint16_t exp_ram_end,
                         uint16_t ram_start = kHighSpeedRamStart);

    void ClearMemory();
    void ClearAllDevices();
    void ResetDevices();

    void RegisterDevice(PeripheralDevice *dev);
    void MapSfr(uint16_t addr, PeripheralDevice *dev);
    void MapSfrRange(uint16_t start_addr, uint16_t end_addr, PeripheralDevice *dev);
    void MapFlashBuf(PeripheralDevice *dev);

    // Load flat firmware image into ROM (supports <= 60 KB unbanked or 96/128 KB banked images).
    bool LoadRom(const uint8_t *data, size_t size, uint16_t base_addr = 0);

    // Load 8 KB internal programmer mask ROM (accepts 8 KB or full 64 KB dump).
    bool LoadProgrammerRom(const uint8_t *data, size_t size);
    void ClearProgrammerRom();
    void SetProgrammerOverlay(bool overlay_high_8000, bool overlay_low_0000);
    bool IsProgrammerRomLoaded() const { return prog_rom_loaded_; }
    bool IsProgOverlayHigh() const { return prog_overlay_high_; }
    bool IsProgOverlayLow() const { return prog_overlay_low_; }
    uint8_t GetProgOverlayMask() const {
        return static_cast<uint8_t>((prog_overlay_high_ ? 1u : 0u) | (prog_overlay_low_ ? 2u : 0u));
    }

    // Read user flash array directly, bypassing programmer ROM overlays (supports up to 128 KB).
    uint8_t ReadMainFlashByte(uint32_t addr) const;
    uint32_t TotalFlashSize() const;

    // High-speed internal RAM rule: 0xFB00..0xFEFF (1 bus clock vs 2 clocks elsewhere).
    bool IsHighSpeed(uint16_t addr) const {
        return addr >= ram_start_ && addr <= kGprEnd;
    }

    // Active memory bank register (0xFFF3) for 96/128 KB flash devices.
    void SetActiveBank(uint8_t bank);
    uint8_t GetActiveBank() const { return active_bank_; }
    uint8_t GetBankCount() const { return bank_count_; }

    // CPU-side bus operations.
    uint8_t FetchByte(uint16_t pc);
    uint8_t ReadCpu(uint16_t addr);
    void WriteCpu(uint16_t addr, uint8_t value);

    // Side-effect-free debugger memory operations.
    uint8_t PeekByte(uint16_t addr) const;
    void PokeByte(uint16_t addr, uint8_t value);
    bool ReadDebug(uint16_t addr, size_t size, void *dest) const;
    bool WriteDebug(uint16_t addr, size_t size, const void *src);

    // Watchpoints.
    void AddWatchpoint(uint16_t addr, uint16_t size, int type);
    void RemoveWatchpoint(uint16_t addr, uint16_t size, int type);
    void ClearWatchpoints();

    void ClearFaults() {
        unmapped_fault = false;
        fault_addr = 0;
        fault_is_write = false;
        watchpoint_hit = false;
        watchpoint_addr = 0;
        watchpoint_is_write = false;
    }

    void TickDevices(uint32_t cpu_cycles,
                     uint32_t prs_cycles,
                     uint32_t sub_cycles,
                     uint32_t rl_cycles,
                     bool in_halt,
                     bool in_stop);

    std::vector<MemoryRegion> GetRegions() const;

    MachineProfile Profile() const { return profile_; }
    uint16_t RomEnd() const { return rom_end_; }
    uint16_t ExpRamStart() const { return exp_ram_start_; }
    uint16_t ExpRamEnd() const { return exp_ram_end_; }
    uint16_t RamStart() const { return ram_start_; }

    bool stop_on_unmapped = false;
    bool rom_writable = false;

    bool unmapped_fault = false;
    uint16_t fault_addr = 0;
    bool fault_is_write = false;

    bool watchpoint_hit = false;
    uint16_t watchpoint_addr = 0;
    bool watchpoint_is_write = false;

private:
    bool IsRomAddr(uint16_t addr) const { return addr < rom_end_; }
    bool IsProgRomOverlaid(uint16_t addr) const {
        return prog_rom_loaded_ &&
               ((prog_overlay_high_ && addr >= kProgRomHighStart &&
                 addr < static_cast<uint16_t>(kProgRomHighStart + kProgRomSize)) ||
                (prog_overlay_low_ && addr < kProgRomSize));
    }
    uint8_t ReadProgRomByte(uint16_t addr) const { return prog_rom_[addr & 0x1FFFu]; }
    bool IsExpRamAddr(uint16_t addr) const { return exp_ram_end_ > exp_ram_start_ && addr >= exp_ram_start_ && addr < exp_ram_end_; }
    bool IsFlashBufAddr(uint16_t addr) const { return flash_buf_dev_ != nullptr && addr >= kFlashBufStart && addr <= kFlashBufEnd; }
    bool IsHighSpeedRamAddr(uint16_t addr) const { return addr >= ram_start_ && addr <= kHighSpeedRamEnd; }
    bool IsGprAddr(uint16_t addr) const { return addr >= kGprStart && addr <= kGprEnd; }
    bool IsSfrAddr(uint16_t addr) const { return addr >= kSfrStart; }
    bool IsMappedAddr(uint16_t addr) const;

    uint8_t ReadRomByte(uint16_t addr) const;
    void WriteRomByte(uint16_t addr, uint8_t value);
    void CheckWatchpoints(uint16_t addr, bool is_write);

    MachineProfile profile_ = MachineProfile::Kx2;
    uint16_t rom_end_ = 0xC000u;
    uint16_t exp_ram_start_ = 0xF400u;
    uint16_t exp_ram_end_ = 0xF800u;
    uint16_t ram_start_ = kHighSpeedRamStart;
    uint8_t reserved_fill_ = 0xFFu;

    std::array<uint8_t, 0xF000u> rom_common_{};
    std::array<std::array<uint8_t, kBankSize>, kMaxBanks> rom_banks_{};
    std::array<uint8_t, kProgRomSize> prog_rom_{};
    bool prog_rom_loaded_ = false;
    bool prog_overlay_high_ = false;
    bool prog_overlay_low_ = false;
    uint8_t active_bank_ = 0;
    uint8_t bank_count_ = 0;  // 0 = unbanked, >0 = number of 16KB banks active at 0x8000..0xBFFF

    std::array<uint8_t, 0x1800u> exp_ram_{};  // 0xE000..0xF7FF max 6KB
    std::array<uint8_t, 0x03E0u> high_speed_ram_{};
    std::array<uint8_t, 0x0020u> gpr_ram_{};
    std::array<uint8_t, 0x0100u> sfr_ram_{};

    PeripheralDevice *flash_buf_dev_ = nullptr;
    std::array<PeripheralDevice *, 256> sfr_devs_{};
    std::vector<PeripheralDevice *> devices_;
    std::vector<Watchpoint> watchpoints_;
};
