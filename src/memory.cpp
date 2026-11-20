#include "memory.h"

#include <algorithm>
#include <cstring>

K0Bus::K0Bus() {
    ConfigureLayout(MachineProfile::Kx2, 0xC000u, 0xF400u, 0xF800u, kHighSpeedRamStart);
    ClearMemory();
}

void K0Bus::ConfigureLayout(MachineProfile profile,
                            uint16_t rom_end,
                            uint16_t exp_ram_start,
                            uint16_t exp_ram_end,
                            uint16_t ram_start) {
    profile_ = profile;
    rom_end_ = (rom_end <= 0xF000u) ? rom_end : 0xF000u;
    if (exp_ram_end > exp_ram_start && exp_ram_start >= 0xE000u && exp_ram_end <= 0xF800u) {
        exp_ram_start_ = exp_ram_start;
        exp_ram_end_ = exp_ram_end;
    } else {
        exp_ram_start_ = 0xF800u;
        exp_ram_end_ = 0xF800u;
    }
    ram_start_ = (ram_start >= kHighSpeedRamStart && ram_start <= kHighSpeedRamEnd)
                     ? ram_start
                     : kHighSpeedRamStart;
    reserved_fill_ = (profile_ == MachineProfile::Legacy0831) ? 0x08u : 0xFFu;
}

void K0Bus::ClearMemory() {
    rom_common_.fill(0xFFu);
    for (auto &b : rom_banks_) {
        b.fill(0xFFu);
    }
    active_bank_ = 0;
    bank_count_ = 0;
    exp_ram_.fill(0);
    high_speed_ram_.fill(0);
    gpr_ram_.fill(0);
    sfr_ram_.fill(0);
    ClearFaults();
}

void K0Bus::ClearAllDevices() {
    sfr_devs_.fill(nullptr);
    devices_.clear();
}

void K0Bus::ResetDevices() {
    active_bank_ = 0;
    sfr_ram_.fill(0);
    for (PeripheralDevice *dev : devices_) {
        if (dev) {
            dev->Reset();
        }
    }
}

void K0Bus::RegisterDevice(PeripheralDevice *dev) {
    if (!dev) {
        return;
    }
    if (std::find(devices_.begin(), devices_.end(), dev) == devices_.end()) {
        devices_.push_back(dev);
    }
}

void K0Bus::MapSfr(uint16_t addr, PeripheralDevice *dev) {
    if (addr < kSfrStart) {
        return;
    }
    RegisterDevice(dev);
    sfr_devs_[addr - kSfrStart] = dev;
}

void K0Bus::MapSfrRange(uint16_t start_addr, uint16_t end_addr, PeripheralDevice *dev) {
    if (start_addr < kSfrStart || end_addr < start_addr) {
        return;
    }
    RegisterDevice(dev);
    for (uint32_t a = start_addr; a <= end_addr; ++a) {
        sfr_devs_[a - kSfrStart] = dev;
    }
}

bool K0Bus::LoadRom(const uint8_t *data, size_t size, uint16_t base_addr) {
    if (!data && size > 0) {
        return false;
    }
    if (size == 0) {
        return true;
    }

    // Banked 96KB / 128KB Kx2 ROM images (> 60KB starting at 0x0000):
    // 0x0000..0x7FFF = common area; 0x8000..0xBFFF = bank 0, followed by banks 1..N.
    if (base_addr == 0 && size > 0xF000u) {
        const size_t common_copy = std::min<size_t>(size, 0xC000u);
        std::memcpy(rom_common_.data(), data, common_copy);
        if (rom_end_ < 0xC000u) {
            rom_end_ = 0xC000u;
        }
        // Bank 0 mirrors 0x8000..0xBFFF
        std::memcpy(rom_banks_[0].data(), data + kBankWindowStart, kBankSize);
        size_t offset = 0xC000u;
        uint8_t bank = 1;
        while (offset < size && bank < kMaxBanks) {
            const size_t chunk = std::min<size_t>(size - offset, kBankSize);
            rom_banks_[bank].fill(0xFFu);
            std::memcpy(rom_banks_[bank].data(), data + offset, chunk);
            offset += chunk;
            ++bank;
        }
        bank_count_ = bank;
        active_bank_ = 0;
        return true;
    }

    if (static_cast<uint32_t>(base_addr) + size > 0xF000u) {
        return false;
    }
    std::memcpy(rom_common_.data() + base_addr, data, size);
    const uint16_t end_addr = static_cast<uint16_t>(base_addr + size);
    if (end_addr > rom_end_) {
        rom_end_ = end_addr;
    }
    bank_count_ = 0;
    active_bank_ = 0;
    return true;
}

void K0Bus::SetActiveBank(uint8_t bank) {
    if (bank_count_ > 0 && bank < bank_count_) {
        active_bank_ = bank;
    } else {
        active_bank_ = bank & 0x07u;
    }
}

uint8_t K0Bus::ReadRomByte(uint16_t addr) const {
    if (bank_count_ > 0 && addr >= kBankWindowStart && addr <= kBankWindowEnd) {
        const uint8_t b = (active_bank_ < bank_count_) ? active_bank_ : 0u;
        return rom_banks_[b][addr - kBankWindowStart];
    }
    return rom_common_[addr];
}

void K0Bus::WriteRomByte(uint16_t addr, uint8_t value) {
    if (bank_count_ > 0 && addr >= kBankWindowStart && addr <= kBankWindowEnd) {
        const uint8_t b = (active_bank_ < bank_count_) ? active_bank_ : 0u;
        rom_banks_[b][addr - kBankWindowStart] = value;
        return;
    }
    rom_common_[addr] = value;
}

bool K0Bus::IsMappedAddr(uint16_t addr) const {
    return IsRomAddr(addr) || IsExpRamAddr(addr) || IsHighSpeedRamAddr(addr) || IsGprAddr(addr) || IsSfrAddr(addr);
}

void K0Bus::CheckWatchpoints(uint16_t addr, bool is_write) {
    if (watchpoints_.empty()) {
        return;
    }
    for (const auto &wp : watchpoints_) {
        const uint32_t wp_end = static_cast<uint32_t>(wp.addr) + (wp.size ? wp.size : 1u);
        if (addr >= wp.addr && addr < wp_end) {
            const bool match = is_write ? ((wp.type & 1) != 0) : ((wp.type & 2) != 0);
            if (match && !watchpoint_hit) {
                watchpoint_hit = true;
                watchpoint_addr = addr;
                watchpoint_is_write = is_write;
            }
        }
    }
}

uint8_t K0Bus::FetchByte(uint16_t pc) {
    if (IsRomAddr(pc)) {
        return ReadRomByte(pc);
    }
    if (IsExpRamAddr(pc)) {
        return exp_ram_[pc - 0xE000u];
    }
    if (IsHighSpeedRamAddr(pc)) {
        return high_speed_ram_[pc - kHighSpeedRamStart];
    }
    if (IsGprAddr(pc)) {
        return gpr_ram_[pc - kGprStart];
    }
    if (stop_on_unmapped && !IsMappedAddr(pc)) {
        unmapped_fault = true;
        fault_addr = pc;
        fault_is_write = false;
    }
    return PeekByte(pc);
}

uint8_t K0Bus::ReadCpu(uint16_t addr) {
    CheckWatchpoints(addr, false);
    if (IsRomAddr(addr)) {
        return ReadRomByte(addr);
    }
    if (IsExpRamAddr(addr)) {
        return exp_ram_[addr - 0xE000u];
    }
    if (IsHighSpeedRamAddr(addr)) {
        return high_speed_ram_[addr - kHighSpeedRamStart];
    }
    if (IsGprAddr(addr)) {
        return gpr_ram_[addr - kGprStart];
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            return dev->Read(addr);
        }
        return sfr_ram_[addr - kSfrStart];
    }
    if (stop_on_unmapped) {
        unmapped_fault = true;
        fault_addr = addr;
        fault_is_write = false;
    }
    return reserved_fill_;
}

void K0Bus::WriteCpu(uint16_t addr, uint8_t value) {
    CheckWatchpoints(addr, true);
    if (IsRomAddr(addr)) {
        if (rom_writable) {
            WriteRomByte(addr, value);
        }
        return;
    }
    if (IsExpRamAddr(addr)) {
        exp_ram_[addr - 0xE000u] = value;
        return;
    }
    if (IsHighSpeedRamAddr(addr)) {
        high_speed_ram_[addr - kHighSpeedRamStart] = value;
        return;
    }
    if (IsGprAddr(addr)) {
        gpr_ram_[addr - kGprStart] = value;
        return;
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            dev->Write(addr, value);
        } else {
            sfr_ram_[addr - kSfrStart] = value;
        }
        return;
    }
    if (stop_on_unmapped) {
        unmapped_fault = true;
        fault_addr = addr;
        fault_is_write = true;
    }
}

uint8_t K0Bus::PeekByte(uint16_t addr) const {
    if (IsRomAddr(addr)) {
        return ReadRomByte(addr);
    }
    if (IsExpRamAddr(addr)) {
        return exp_ram_[addr - 0xE000u];
    }
    if (IsHighSpeedRamAddr(addr)) {
        return high_speed_ram_[addr - kHighSpeedRamStart];
    }
    if (IsGprAddr(addr)) {
        return gpr_ram_[addr - kGprStart];
    }
    if (IsSfrAddr(addr)) {
        const PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            return dev->Peek(addr);
        }
        return sfr_ram_[addr - kSfrStart];
    }
    return reserved_fill_;
}

void K0Bus::PokeByte(uint16_t addr, uint8_t value) {
    if (IsRomAddr(addr)) {
        WriteRomByte(addr, value);
        return;
    }
    if (IsExpRamAddr(addr)) {
        exp_ram_[addr - 0xE000u] = value;
        return;
    }
    if (IsHighSpeedRamAddr(addr)) {
        high_speed_ram_[addr - kHighSpeedRamStart] = value;
        return;
    }
    if (IsGprAddr(addr)) {
        gpr_ram_[addr - kGprStart] = value;
        return;
    }
    if (IsSfrAddr(addr)) {
        PeripheralDevice *dev = sfr_devs_[addr - kSfrStart];
        if (dev) {
            dev->Poke(addr, value);
        } else {
            sfr_ram_[addr - kSfrStart] = value;
        }
    }
}

bool K0Bus::ReadDebug(uint16_t addr, size_t size, void *dest) const {
    if (!dest && size > 0) {
        return false;
    }
    uint8_t *out = static_cast<uint8_t *>(dest);
    for (size_t i = 0; i < size; ++i) {
        if (static_cast<uint32_t>(addr) + i >= kAddressSpaceSize) {
            return false;
        }
        out[i] = PeekByte(static_cast<uint16_t>(addr + i));
    }
    return true;
}

bool K0Bus::WriteDebug(uint16_t addr, size_t size, const void *src) {
    if (!src && size > 0) {
        return false;
    }
    const uint8_t *in = static_cast<const uint8_t *>(src);
    for (size_t i = 0; i < size; ++i) {
        if (static_cast<uint32_t>(addr) + i >= kAddressSpaceSize) {
            return false;
        }
        PokeByte(static_cast<uint16_t>(addr + i), in[i]);
    }
    return true;
}

void K0Bus::AddWatchpoint(uint16_t addr, uint16_t size, int type) {
    const uint16_t sz = size ? size : 1u;
    for (auto &wp : watchpoints_) {
        if (wp.addr == addr && wp.size == sz) {
            wp.type |= type;
            return;
        }
    }
    watchpoints_.push_back(Watchpoint{addr, sz, type});
}

void K0Bus::RemoveWatchpoint(uint16_t addr, uint16_t size, int type) {
    const uint16_t sz = size ? size : 1u;
    for (auto it = watchpoints_.begin(); it != watchpoints_.end();) {
        if (it->addr == addr && it->size == sz) {
            it->type &= ~type;
            if (it->type == 0) {
                it = watchpoints_.erase(it);
                continue;
            }
        }
        ++it;
    }
}

void K0Bus::ClearWatchpoints() {
    watchpoints_.clear();
}

void K0Bus::TickDevices(uint32_t cpu_cycles,
                        uint32_t prs_cycles,
                        uint32_t sub_cycles,
                        uint32_t rl_cycles,
                        bool in_halt,
                        bool in_stop) {
    for (PeripheralDevice *dev : devices_) {
        if (dev) {
            dev->Tick(cpu_cycles, prs_cycles, sub_cycles, rl_cycles, in_halt, in_stop);
        }
    }
}

std::vector<MemoryRegion> K0Bus::GetRegions() const {
    std::vector<MemoryRegion> regions;
    if (rom_end_ > 0) {
        regions.push_back(MemoryRegion{0x0000u, rom_end_, "ROM", false, MEM_PERM_RX});
    }
    if (exp_ram_end_ > exp_ram_start_) {
        regions.push_back(MemoryRegion{
            exp_ram_start_,
            static_cast<uint32_t>(exp_ram_end_ - exp_ram_start_),
            "EXP_RAM",
            false,
            MEM_PERM_RWX,
        });
    }
    if (ram_start_ <= kHighSpeedRamEnd) {
        regions.push_back(MemoryRegion{
            ram_start_,
            static_cast<uint32_t>(kHighSpeedRamEnd - ram_start_ + 1u),
            "RAM",
            false,
            MEM_PERM_RWX,
        });
    }
    regions.push_back(MemoryRegion{kGprStart, 0x0020u, "GPR", false, MEM_PERM_RW});
    regions.push_back(MemoryRegion{kSfrStart, 0x0100u, "SFR", true, MEM_PERM_RW});
    return regions;
}
