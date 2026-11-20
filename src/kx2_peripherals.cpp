#include "kx2_peripherals.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace k0 {

namespace {

// 78K0/Kx2 Table 20-1 (pp. 631-632)
const IrqSourceDef kKx2Sources[] = {
    {  0, 0, 0x01u, 0x0004u, "INTLVI" },
    {  1, 0, 0x02u, 0x0006u, "INTP0" },
    {  2, 0, 0x04u, 0x0008u, "INTP1" },
    {  3, 0, 0x08u, 0x000Au, "INTP2" },
    {  4, 0, 0x10u, 0x000Cu, "INTP3" },
    {  5, 0, 0x20u, 0x000Eu, "INTP4" },
    {  6, 0, 0x40u, 0x0010u, "INTP5" },
    {  7, 0, 0x80u, 0x0012u, "INTSRE6" },
    {  8, 1, 0x01u, 0x0014u, "INTSR6" },
    {  9, 1, 0x02u, 0x0016u, "INTST6" },
    { 10, 1, 0x04u, 0x0018u, "INTCSI10" },  // shared with INTST0
    { 11, 1, 0x08u, 0x001Au, "INTTMH1" },
    { 12, 1, 0x10u, 0x001Cu, "INTTMH0" },
    { 13, 1, 0x20u, 0x001Eu, "INTTM50" },
    { 14, 1, 0x40u, 0x0020u, "INTTM000" },
    { 15, 1, 0x80u, 0x0022u, "INTTM010" },
    { 16, 2, 0x01u, 0x0024u, "INTAD" },
    { 17, 2, 0x02u, 0x0026u, "INTSR0" },
    { 18, 2, 0x04u, 0x0028u, "INTWTI" },
    { 19, 2, 0x08u, 0x002Au, "INTTM51" },
    { 20, 2, 0x10u, 0x002Cu, "INTKR" },
    { 21, 2, 0x20u, 0x002Eu, "INTWT" },
    { 22, 2, 0x40u, 0x0030u, "INTP6" },
    { 23, 2, 0x80u, 0x0032u, "INTP7" },
    { 24, 3, 0x01u, 0x0034u, "INTIIC0" },   // shared with INTDMU
    { 25, 3, 0x02u, 0x0036u, "INTCSI11" },
    { 26, 3, 0x04u, 0x0038u, "INTTM001" },
    { 27, 3, 0x08u, 0x003Au, "INTTM011" },
    { 28, 3, 0x10u, 0x003Cu, "INTACSI" },
};

// uPD78F0831Y / 0833Y table matching Python k0emu/devices.py
const IrqSourceDef k0831Sources[] = {
    {  0, 0, 0x01u, 0x0004u, "INTWDT" },
    {  1, 0, 0x02u, 0x0006u, "INTP0" },
    {  2, 0, 0x04u, 0x0008u, "INTP1" },
    {  3, 0, 0x08u, 0x000Au, "INTP2" },
    {  4, 0, 0x10u, 0x000Cu, "INTP3" },
    {  5, 0, 0x20u, 0x000Eu, "INTP4" },
    {  6, 0, 0x40u, 0x0010u, "INTP5" },
    {  7, 0, 0x80u, 0x0012u, "INTP6" },
    {  8, 1, 0x01u, 0x0014u, "INTP7" },
    {  9, 1, 0x02u, 0x0016u, "INTSER0" },
    { 10, 1, 0x04u, 0x0018u, "INTSR0" },
    { 11, 1, 0x08u, 0x001Au, "INTST0" },
    { 12, 1, 0x10u, 0x001Cu, "INTCSI30" },
    { 13, 1, 0x20u, 0x001Eu, "INTCSI31" },
    { 14, 1, 0x40u, 0x0020u, "INTIIC0" },
    { 15, 1, 0x80u, 0x0022u, "INTC2" },
    { 16, 2, 0x01u, 0x0024u, "INTWTNI0" },
    { 17, 2, 0x02u, 0x0026u, "INTTM000" },
    { 18, 2, 0x04u, 0x0028u, "INTTM010" },
    { 19, 2, 0x08u, 0x002Au, "INTTM001" },
    { 20, 2, 0x10u, 0x002Cu, "INTTM011" },
    { 21, 2, 0x20u, 0x002Eu, "INTAD00" },
    { 22, 2, 0x40u, 0x0030u, "INTAD01" },
    { 23, 3, 0x01u, 0x0034u, "INTWTN0" },
    { 24, 3, 0x02u, 0x0036u, "INTKR" },
    { 25, 3, 0x04u, 0x0038u, "INTTM50" },
    { 26, 3, 0x08u, 0x003Au, "INTTM51" },
    { 27, 3, 0x10u, 0x003Cu, "INTTM52" },
};

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

}  // namespace

// ============================================================================
// Kx2Intc
// ============================================================================

Kx2Intc::Kx2Intc(MachineProfile profile) {
    SetProfile(profile);
    Reset();
}

void Kx2Intc::SetProfile(MachineProfile profile) {
    profile_ = profile;
    if (profile_ == MachineProfile::Legacy0831) {
        sources_.assign(std::begin(k0831Sources), std::end(k0831Sources));
    } else {
        sources_.assign(std::begin(kKx2Sources), std::end(kKx2Sources));
    }
}

void Kx2Intc::Reset() {
    for (size_t i = 0; i < 4; ++i) regs_[i] = 0x00u;
    for (size_t i = 4; i < 12; ++i) regs_[i] = 0xFFu;
}

uint8_t Kx2Intc::Read(uint16_t addr) {
    return Peek(addr);
}

void Kx2Intc::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

uint8_t Kx2Intc::Peek(uint16_t addr) const {
    if (addr < 0xFFE0u || addr > 0xFFEBu) return 0;
    return regs_[addr - 0xFFE0u];
}

void Kx2Intc::Poke(uint16_t addr, uint8_t value) {
    if (addr < 0xFFE0u || addr > 0xFFEBu) return;
    regs_[addr - 0xFFE0u] = value;
}

PendingInterrupt Kx2Intc::EvaluatePending() const {
    PendingInterrupt best;
    for (const auto &s : sources_) {
        const uint8_t ifv = regs_[s.reg_offset];
        const uint8_t mkv = regs_[s.reg_offset + 4u];
        const uint8_t prv = regs_[s.reg_offset + 8u];
        if ((ifv & s.bit_mask) == 0) continue;
        if ((mkv & s.bit_mask) != 0) continue;

        const bool is_high = (prv & s.bit_mask) == 0;  // PR bit 0 = high priority
        if (is_high) {
            best.pending = true;
            best.source_index = s.index;
            best.high_priority = true;
            best.vector_address = s.vector_addr;
            return best;
        }
        if (!best.pending) {
            best.pending = true;
            best.source_index = s.index;
            best.high_priority = false;
            best.vector_address = s.vector_addr;
        }
    }
    return best;
}

bool Kx2Intc::HasUnmaskedPending() const {
    for (const auto &s : sources_) {
        const uint8_t ifv = regs_[s.reg_offset];
        const uint8_t mkv = regs_[s.reg_offset + 4u];
        if ((ifv & ~mkv & s.bit_mask) != 0) {
            return true;
        }
    }
    return false;
}

void Kx2Intc::Acknowledge(uint8_t source_index) {
    if (source_index < sources_.size()) {
        const auto &s = sources_[source_index];
        regs_[s.reg_offset] &= static_cast<uint8_t>(~s.bit_mask);
    }
}

void Kx2Intc::RaiseIrq(uint8_t source_index) {
    if (source_index < sources_.size()) {
        const auto &s = sources_[source_index];
        regs_[s.reg_offset] |= s.bit_mask;
    }
}

void Kx2Intc::ClearIrq(uint8_t source_index) {
    Acknowledge(source_index);
}

int Kx2Intc::FindIrqByName(const char *name) const {
    if (!name || !*name) return -1;
    if (profile_ == MachineProfile::Kx2) {
        if (EqIgnoreCase(name, "INTST0")) return 10;
        if (EqIgnoreCase(name, "INTDMU")) return 24;
    }
    for (const auto &s : sources_) {
        if (EqIgnoreCase(name, s.name)) {
            return s.index;
        }
    }
    char *end = nullptr;
    const unsigned long idx = std::strtoul(name, &end, 0);
    if (end != name && *end == '\0' && idx < sources_.size()) {
        return static_cast<int>(idx);
    }
    return -1;
}

// ============================================================================
// Kx2Clock
// ============================================================================

void Kx2Clock::Reset() {
    oscctl_ = 0x00u;
    rcm_ = 0x80u;  // RSTS=1 (internal high-speed osc stabilized)
    mcm_ = 0x00u;
    moc_ = 0x80u;  // MSTOP=1 (X1 osc stopped)
    ostc_ = 0x00u;
    osts_ = 0x05u;
    pcc_ = 0x01u;  // fXP / 2 default
    sub_acc_ = 0;
    rl_acc_ = 0;
    ostc_timer_ = 0;
}

uint8_t Kx2Clock::GetRcm() const {
    const bool rsts = (rcm_ & 0x01u) == 0;  // stabilized whenever RSTOP=0
    return static_cast<uint8_t>((rcm_ & 0x03u) | (rsts ? 0x80u : 0x00u));
}

uint8_t Kx2Clock::GetMcm() const {
    const bool xsel = (mcm_ & 0x04u) != 0;
    const bool mcm0 = (mcm_ & 0x01u) != 0;
    const bool mcs = xsel && mcm0;
    return static_cast<uint8_t>((mcm_ & 0x05u) | (mcs ? 0x02u : 0x00u));
}

uint8_t Kx2Clock::GetPcc() const {
    const bool css = (pcc_ & 0x10u) != 0;
    return static_cast<uint8_t>((pcc_ & 0x57u) | (css ? 0x20u : 0x00u));
}

void Kx2Clock::UpdateOstc() {
    if ((moc_ & 0x80u) != 0) {
        ostc_ = 0x00u;
        ostc_timer_ = 0;
        return;
    }
    uint8_t max_mask = 0x1Fu;
    switch (osts_ & 0x07u) {
    case 1: max_mask = 0x10u; break;
    case 2: max_mask = 0x18u; break;
    case 3: max_mask = 0x1Cu; break;
    case 4: max_mask = 0x1Eu; break;
    case 5:
    default: max_mask = 0x1Fu; break;
    }
    ostc_ = max_mask;
}

uint8_t Kx2Clock::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Clock::Peek(uint16_t addr) const {
    switch (addr) {
    case 0xFF9Fu: return oscctl_;
    case 0xFFA0u: return GetRcm();
    case 0xFFA1u: return GetMcm();
    case 0xFFA2u: return moc_;
    case 0xFFA3u: return ostc_;
    case 0xFFA4u: return osts_;
    case 0xFFFBu: return GetPcc();
    default: return 0;
    }
}

void Kx2Clock::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2Clock::Poke(uint16_t addr, uint8_t value) {
    switch (addr) {
    case 0xFF9Fu: oscctl_ = value & 0xF1u; break;
    case 0xFFA0u: rcm_ = (rcm_ & 0x80u) | (value & 0x03u); break;
    case 0xFFA1u: mcm_ = value & 0x05u; break;
    case 0xFFA2u:
        moc_ = value & 0x80u;
        UpdateOstc();
        break;
    case 0xFFA3u: break;  // OSTC is read-only
    case 0xFFA4u: osts_ = value & 0x07u; break;
    case 0xFFFBu: pcc_ = value & 0x57u; break;
    default: break;
    }
}

void Kx2Clock::Tick(uint32_t, uint32_t, uint32_t, uint32_t, bool, bool in_stop) {
    if (!in_stop && (moc_ & 0x80u) == 0 && ostc_ == 0) {
        UpdateOstc();
    }
}

void Kx2Clock::OnEnterStop() {
    ostc_ = 0x00u;
}

void Kx2Clock::OnExitStop() {
    UpdateOstc();
}

void Kx2Clock::ComputeSubClocks(uint32_t cpu_cycles,
                                bool,
                                bool in_stop,
                                uint32_t *prs_cycles_out,
                                uint32_t *sub_cycles_out,
                                uint32_t *rl_cycles_out) {
    uint32_t prs = 0;
    uint32_t sub = 0;
    uint32_t rl = 0;

    if (in_stop) {
        prs = 0;
        // During STOP, subsystem and low-speed oscillators keep ticking
        sub = 1u;
        rl = ((rcm_ & 0x02u) == 0) ? 8u : 0u;
    } else {
        if ((pcc_ & 0x10u) != 0) {
            // CPU running on fSUB/2 (~16 kHz); main fPRS (~8 MHz) runs ~512x faster if active
            const bool main_active = ((mcm_ & 0x05u) == 0x05u) ? ((moc_ & 0x80u) == 0) : ((rcm_ & 0x01u) == 0);
            prs = main_active ? (cpu_cycles * 256u) : 0u;
            sub = cpu_cycles * 2u;
            rl = ((rcm_ & 0x02u) == 0) ? (cpu_cycles * 15u) : 0u;
        } else {
            const uint8_t div = std::min<uint8_t>(pcc_ & 0x07u, 4u);
            prs = cpu_cycles << div;
            sub_acc_ += prs;
            while (sub_acc_ >= 244u) {
                sub_acc_ -= 244u;
                ++sub;
            }
            if ((rcm_ & 0x02u) == 0) {
                rl_acc_ += prs;
                while (rl_acc_ >= 32u) {
                    rl_acc_ -= 32u;
                    ++rl;
                }
            }
        }
    }

    if (prs_cycles_out) *prs_cycles_out = prs;
    if (sub_cycles_out) *sub_cycles_out = sub;
    if (rl_cycles_out) *rl_cycles_out = rl;
}

// ============================================================================
// Kx2SystemCtrl
// ============================================================================

void Kx2SystemCtrl::Reset() {
    ims_ = 0xCFu;
    bank_ = 0x00u;
    ixs_ = 0x0Cu;
    lvim_ = 0x00u;
    lvis_ = 0x00u;
    pfcmd_ = 0x00u;
    flpmc_ = 0x00u;
    if (bus_) {
        bus_->SetActiveBank(0);
    }
}

uint8_t Kx2SystemCtrl::Read(uint16_t addr) {
    if (addr == 0xFFACu) {
        const uint8_t v = resf_;
        resf_ = 0;  // Hardware clears RESF upon CPU read (78K0KX2.pdf p. 691)
        return v;
    }
    return Peek(addr);
}

uint8_t Kx2SystemCtrl::Peek(uint16_t addr) const {
    switch (addr) {
    case 0xFFACu: return resf_;
    case 0xFFBEu: return lvim_;
    case 0xFFBFu: return lvis_;
    case 0xFFC0u: return pfcmd_;
    case 0xFFC4u: return flpmc_;
    case 0xFFF0u: return ims_;
    case 0xFFF3u: return bank_;
    case 0xFFF4u: return ixs_;
    default: return 0;
    }
}

void Kx2SystemCtrl::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2SystemCtrl::Poke(uint16_t addr, uint8_t value) {
    switch (addr) {
    case 0xFFACu: break;  // RESF is read-only
    case 0xFFBEu: lvim_ = (lvim_ & 0x01u) | (value & 0x86u); break;
    case 0xFFBFu: lvis_ = value & 0x0Fu; break;
    case 0xFFC0u: pfcmd_ = value; break;
    case 0xFFC4u: flpmc_ = value; break;
    case 0xFFF0u: ims_ = value; break;
    case 0xFFF3u:
        bank_ = value & 0x07u;
        if (bus_) {
            bus_->SetActiveBank(bank_);
        }
        break;
    case 0xFFF4u: ixs_ = value & 0x0Fu; break;
    default: break;
    }
}

// ============================================================================
// Kx2Wdt
// ============================================================================

void Kx2Wdt::Reset() {
    option_byte_ = bus_ ? bus_->PeekByte(0x0080u) : 0x00u;
    // Valid option byte has bit 7 == 0 (unprogrammed flash 0xFF disables WDT).
    if ((option_byte_ & 0x80u) == 0) {
        wdton_ = (option_byte_ & 0x10u) != 0;
        wdcs_ = (option_byte_ >> 1) & 0x07u;
        window_ = (option_byte_ >> 5) & 0x03u;
        lsrosc_ = (option_byte_ & 0x01u) != 0;
    } else {
        wdton_ = false;
        wdcs_ = 7u;
        window_ = 3u;
        lsrosc_ = false;
    }
    overflow_period_ = 1u << (10u + wdcs_);
    counter_ = 0;
    kicked_once_ = false;

    legacy_wdcs_ = 0;
    legacy_wdtm_ = 0;
}

uint8_t Kx2Wdt::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Wdt::Peek(uint16_t addr) const {
    if (addr == 0xFF99u) {
        return wdton_ ? 0x9Au : 0x1Au;
    }
    if (addr == 0xFF42u) {
        return 0x00u;  // WDCS write-only on 0831Y
    }
    if (addr == 0xFFF9u) {
        return legacy_wdtm_;
    }
    return 0;
}

void Kx2Wdt::TriggerReset() {
    if (sys_) {
        sys_->SetResetFlag(0x10u);  // WDTRF
    }
    if (cpu_) {
        if (halt_on_reset) {
            cpu_->RequestWdtReset();
        } else {
            bus_->ResetDevices();
            cpu_->Reset();
        }
    }
}

void Kx2Wdt::Write(uint16_t addr, uint8_t value) {
    if (addr == 0xFF99u) {
        if (!wdton_) {
            return;
        }
        if (value == 0xACu) {
            counter_ = 0;
            kicked_once_ = true;
        } else {
            TriggerReset();
        }
        return;
    }
    if (addr == 0xFF42u) {
        legacy_wdcs_ = value & 0x07u;
        return;
    }
    if (addr == 0xFFF9u) {
        legacy_wdtm_ |= (value & 0x98u);
        if (value & 0x80u) {
            counter_ = 0;
        }
    }
}

void Kx2Wdt::Poke(uint16_t addr, uint8_t value) {
    if (addr == 0xFF99u) {
        if (value == 0xACu) {
            counter_ = 0;
        }
        return;
    }
    Write(addr, value);
}

void Kx2Wdt::Tick(uint32_t cpu_cycles, uint32_t, uint32_t, uint32_t rl_cycles, bool in_halt, bool in_stop) {
    if (bus_ && bus_->Profile() == MachineProfile::Legacy0831) {
        if ((legacy_wdtm_ & 0x80u) == 0) return;
        static const uint32_t kLegacyIntervals[8] = {
            1u << 12, 1u << 13, 1u << 14, 1u << 15,
            1u << 16, 1u << 17, 1u << 18, 1u << 20
        };
        counter_ += cpu_cycles;
        const uint32_t limit = kLegacyIntervals[legacy_wdcs_ & 7u];
        if (counter_ >= limit) {
            counter_ = 0;
            if ((legacy_wdtm_ & 0x10u) == 0) {
                if (intc_) intc_->RaiseIrq(0);  // INTWDT
            } else if ((legacy_wdtm_ & 0x08u) != 0) {
                TriggerReset();
            }
        }
        return;
    }

    if (!wdton_) {
        return;
    }
    // 78K0KX2.pdf p. 400 Caution 4: stops in HALT/STOP if LSROSC=0
    if ((in_halt || in_stop) && !lsrosc_) {
        return;
    }
    if (clk_ && clk_->IsLsrStopped() && !lsrosc_) {
        return;
    }
    counter_ += rl_cycles;
    if (counter_ >= overflow_period_) {
        counter_ = 0;
        TriggerReset();
    }
}

// ============================================================================
// Kx2Ports
// ============================================================================

void Kx2Ports::Reset() {
    latch_.fill(0x00u);
    mode_.fill(0xFFu);
    pullup_.fill(0x00u);
    ext_in_.fill(0xFFu);
    adpc_ = 0x00u;
    egp_ = 0x00u;
    egn_ = 0x00u;
    isc_ = 0x00u;
    krm_ = 0x00u;
}

uint8_t Kx2Ports::GetPinState(uint8_t port) const {
    if (port >= 15u) return 0;
    if (port == 13u) return latch_[13] & 0x01u;
    return static_cast<uint8_t>((latch_[port] & ~mode_[port]) | (ext_in_[port] & mode_[port]));
}

void Kx2Ports::CheckEdgeIntp(uint8_t port, uint8_t pin, bool old_high, bool new_high) {
    if (!intc_ || old_high == new_high) return;

    // 78K0KX2.pdf Table 20-3 (p. 654):
    // INTP0: P12.0, INTP1..4: P3.0..3, INTP5: P1.6, INTP6..7: P14.0..1
    int intp_idx = -1;
    if (port == 12u && pin == 0u) intp_idx = 0;
    else if (port == 3u && pin <= 3u) intp_idx = pin + 1;
    else if (port == 1u && pin == 6u) intp_idx = 5;
    else if (port == 14u && pin <= 1u) intp_idx = 6 + pin;

    if (intp_idx >= 0) {
        const uint8_t mask = static_cast<uint8_t>(1u << intp_idx);
        const bool rising = !old_high && new_high;
        const bool falling = old_high && !new_high;
        if ((rising && (egp_ & mask)) || (falling && (egn_ & mask))) {
            static const uint8_t kIntpIrqs[8] = { 1, 2, 3, 4, 5, 6, 22, 23 };
            intc_->RaiseIrq(kIntpIrqs[intp_idx]);
        }
    }

    // Key Return interrupt on P7 falling edge
    if (port == 7u && old_high && !new_high && (krm_ & (1u << pin)) != 0) {
        intc_->RaiseIrq(20);  // INTKR
    }
}

void Kx2Ports::SetExternalInput(uint8_t port, uint8_t pin, bool high) {
    if (port >= 15u || pin >= 8u) return;
    const uint8_t mask = static_cast<uint8_t>(1u << pin);
    const bool old_pin = (GetPinState(port) & mask) != 0;
    if (high) ext_in_[port] |= mask;
    else ext_in_[port] &= static_cast<uint8_t>(~mask);
    const bool new_pin = (GetPinState(port) & mask) != 0;
    CheckEdgeIntp(port, pin, old_pin, new_pin);
}

void Kx2Ports::SetExternalPortByte(uint8_t port, uint8_t value) {
    if (port >= 15u) return;
    for (uint8_t pin = 0; pin < 8; ++pin) {
        SetExternalInput(port, pin, (value & (1u << pin)) != 0);
    }
}

uint8_t Kx2Ports::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Ports::Peek(uint16_t addr) const {
    if (addr <= 0xFF07u) return GetPinState(static_cast<uint8_t>(addr - 0xFF00u));
    if (addr >= 0xFF0Cu && addr <= 0xFF0Eu) return GetPinState(static_cast<uint8_t>(addr - 0xFF00u));
    if (addr >= 0xFF20u && addr <= 0xFF27u) return mode_[addr - 0xFF20u];
    if (addr == 0xFF2Cu) return mode_[12];
    if (addr == 0xFF2Eu) return mode_[14];
    if (addr == 0xFF2Fu) return adpc_;
    if (addr >= 0xFF30u && addr <= 0xFF37u) return pullup_[addr - 0xFF30u];
    if (addr == 0xFF3Cu) return pullup_[12];
    if (addr == 0xFF3Eu) return pullup_[14];
    if (addr == 0xFF48u) return egp_;
    if (addr == 0xFF49u) return egn_;
    if (addr == 0xFF4Fu) return isc_;
    if (addr == 0xFF6Eu) return krm_;
    return 0;
}

void Kx2Ports::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2Ports::Poke(uint16_t addr, uint8_t value) {
    if (addr <= 0xFF07u) {
        latch_[addr - 0xFF00u] = value;
        return;
    }
    if (addr >= 0xFF0Cu && addr <= 0xFF0Eu) {
        latch_[addr - 0xFF00u] = value;
        return;
    }
    if (addr >= 0xFF20u && addr <= 0xFF27u) { mode_[addr - 0xFF20u] = value; return; }
    if (addr == 0xFF2Cu) { mode_[12] = value; return; }
    if (addr == 0xFF2Eu) { mode_[14] = value; return; }
    if (addr == 0xFF2Fu) { adpc_ = value; return; }
    if (addr >= 0xFF30u && addr <= 0xFF37u) { pullup_[addr - 0xFF30u] = value; return; }
    if (addr == 0xFF3Cu) { pullup_[12] = value; return; }
    if (addr == 0xFF3Eu) { pullup_[14] = value; return; }
    if (addr == 0xFF48u) { egp_ = value; return; }
    if (addr == 0xFF49u) { egn_ = value; return; }
    if (addr == 0xFF4Fu) { isc_ = value; return; }
    if (addr == 0xFF6Eu) { krm_ = value; return; }
}

// ============================================================================
// Kx2Timer16 (TM00 / TM01)
// ============================================================================

void Kx2Timer16::Reset() {
    tm_ = 0;
    cr0_ = 0;
    cr1_ = 0;
    tmc_ = 0;
    prm_ = 0;
    crc_ = 0;
    toc_ = 0;
    prescaler_acc_ = 0;
}

uint32_t Kx2Timer16::PrescalerDivisor() const {
    if (ch_ == 0) {
        switch (prm_ & 0x03u) {
        case 0: return 1u;
        case 1: return 4u;
        case 2: return 256u;
        default: return 0u;  // external TI000
        }
    }
    switch (prm_ & 0x03u) {
    case 0: return 1u;
    case 1: return 16u;
    case 2: return 64u;
    default: return 0u;
    }
}

uint8_t Kx2Timer16::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Timer16::Peek(uint16_t addr) const {
    const uint16_t base_reg = (ch_ == 0) ? 0xFF10u : 0xFFB0u;
    if (addr == base_reg)     return static_cast<uint8_t>(tm_ & 0xFFu);
    if (addr == base_reg + 1) return static_cast<uint8_t>(tm_ >> 8);
    if (addr == base_reg + 2) return static_cast<uint8_t>(cr0_ & 0xFFu);
    if (addr == base_reg + 3) return static_cast<uint8_t>(cr0_ >> 8);
    if (addr == base_reg + 4) return static_cast<uint8_t>(cr1_ & 0xFFu);
    if (addr == base_reg + 5) return static_cast<uint8_t>(cr1_ >> 8);

    const uint16_t base_ctl = (ch_ == 0) ? 0xFFBAu : 0xFFB6u;
    if (addr == base_ctl)     return tmc_;
    if (addr == base_ctl + 1) return prm_;
    if (addr == base_ctl + 2) return crc_;
    if (addr == base_ctl + 3) return toc_;
    return 0;
}

void Kx2Timer16::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2Timer16::Poke(uint16_t addr, uint8_t value) {
    const uint16_t base_reg = (ch_ == 0) ? 0xFF10u : 0xFFB0u;
    if (addr == base_reg + 2) { cr0_ = static_cast<uint16_t>((cr0_ & 0xFF00u) | value); return; }
    if (addr == base_reg + 3) { cr0_ = static_cast<uint16_t>((cr0_ & 0x00FFu) | (uint16_t(value) << 8)); return; }
    if (addr == base_reg + 4) { cr1_ = static_cast<uint16_t>((cr1_ & 0xFF00u) | value); return; }
    if (addr == base_reg + 5) { cr1_ = static_cast<uint16_t>((cr1_ & 0x00FFu) | (uint16_t(value) << 8)); return; }

    const uint16_t base_ctl = (ch_ == 0) ? 0xFFBAu : 0xFFB6u;
    if (addr == base_ctl) {
        tmc_ = value & 0x0Fu;
        if ((tmc_ & 0x0Cu) == 0) {
            tm_ = 0;
            tmc_ &= ~0x01u;  // clear OVF0n when stopped
            prescaler_acc_ = 0;
        }
        return;
    }
    if (addr == base_ctl + 1) { prm_ = value & 0xF3u; return; }
    if (addr == base_ctl + 2) { crc_ = value & 0x07u; return; }
    if (addr == base_ctl + 3) { toc_ = value & 0x7Fu; return; }
}

void Kx2Timer16::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (in_stop) return;
    const uint8_t mode = (tmc_ >> 2) & 0x03u;
    if (mode == 0) return;

    const uint32_t div = PrescalerDivisor();
    if (div == 0 || prs_cycles == 0) return;

    prescaler_acc_ += prs_cycles;
    uint32_t ticks = prescaler_acc_ / div;
    prescaler_acc_ %= div;
    if (ticks == 0) return;

    // Fast-forward cleanly for multi-tick intervals
    while (ticks > 0) {
        const uint32_t step = std::min<uint32_t>(ticks, 64u);
        for (uint32_t i = 0; i < step; ++i) {
            const uint32_t next = static_cast<uint32_t>(tm_) + 1u;
            if (next > 0xFFFFu) {
                tm_ = 0;
                tmc_ |= 0x01u;  // OVF0n
            } else {
                tm_ = static_cast<uint16_t>(next);
            }
            if ((crc_ & 0x01u) == 0 && tm_ == cr0_) {
                if (intc_) intc_->RaiseIrq(irq_cmp0_);
                if (mode == 3u) {
                    tm_ = 0;
                }
            }
            if ((crc_ & 0x04u) == 0 && tm_ == cr1_) {
                if (intc_) intc_->RaiseIrq(irq_cmp1_);
            }
        }
        ticks -= step;
    }
}

// ============================================================================
// Kx2Timer8 (TM50 / TM51)
// ============================================================================

void Kx2Timer8::Reset() {
    tm_ = 0;
    cr_ = 0;
    tcl_ = 0;
    tmc_ = 0;
    prescaler_acc_ = 0;
}

uint32_t Kx2Timer8::PrescalerDivisor() const {
    if (ch_ == 0) {
        switch (tcl_ & 0x07u) {
        case 2: return 1u;
        case 3: return 2u;
        case 4: return 4u;
        case 5: return 64u;
        case 6: return 256u;
        case 7: return 8192u;
        default: return 0u;
        }
    }
    switch (tcl_ & 0x07u) {
    case 2: return 1u;
    case 3: return 2u;
    case 4: return 16u;
    case 5: return 64u;
    case 6: return 256u;
    case 7: return 4096u;
    default: return 0u;
    }
}

uint8_t Kx2Timer8::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Timer8::Peek(uint16_t addr) const {
    if (ch_ == 0) {
        if (addr == 0xFF16u) return tm_;
        if (addr == 0xFF17u) return cr_;
        if (addr == 0xFF6Au) return tcl_;
        if (addr == 0xFF6Bu) return tmc_ & 0xF3u;
    } else {
        if (addr == 0xFF1Fu) return tm_;
        if (addr == 0xFF41u) return cr_;
        if (addr == 0xFF8Cu) return tcl_;
        if (addr == 0xFF43u) return tmc_ & 0xF3u;
    }
    return 0;
}

void Kx2Timer8::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2Timer8::Poke(uint16_t addr, uint8_t value) {
    if (ch_ == 0) {
        if (addr == 0xFF17u) { cr_ = value; return; }
        if (addr == 0xFF6Au) { tcl_ = value & 0x07u; return; }
        if (addr == 0xFF6Bu) {
            tmc_ = value & 0xCFu;
            if ((tmc_ & 0x80u) == 0) {
                tm_ = 0;
                prescaler_acc_ = 0;
            }
            return;
        }
    } else {
        if (addr == 0xFF41u) { cr_ = value; return; }
        if (addr == 0xFF8Cu) { tcl_ = value & 0x07u; return; }
        if (addr == 0xFF43u) {
            tmc_ = value & 0xCFu;
            if ((tmc_ & 0x80u) == 0) {
                tm_ = 0;
                prescaler_acc_ = 0;
            }
            return;
        }
    }
}

void Kx2Timer8::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (in_stop || (tmc_ & 0x80u) == 0) return;
    const uint32_t div = PrescalerDivisor();
    if (div == 0 || prs_cycles == 0) return;

    prescaler_acc_ += prs_cycles;
    const uint32_t ticks = prescaler_acc_ / div;
    prescaler_acc_ %= div;
    if (ticks == 0) return;

    const bool pwm_mode = (tmc_ & 0x40u) != 0;
    for (uint32_t i = 0; i < ticks; ++i) {
        tm_ = static_cast<uint8_t>(tm_ + 1u);
        if (tm_ == cr_) {
            if (intc_) intc_->RaiseIrq(irq_match_);
            if (!pwm_mode) {
                tm_ = 0;
            }
        }
    }
}

// ============================================================================
// Kx2TimerH (TMH0 / TMH1)
// ============================================================================

void Kx2TimerH::Reset() {
    cnt_ = 0;
    cmp0_ = 0;
    cmp1_ = 0;
    tmhmd_ = 0;
    tmcyc1_ = 0;
    prescaler_acc_ = 0;
}

uint8_t Kx2TimerH::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2TimerH::Peek(uint16_t addr) const {
    if (ch_ == 0) {
        if (addr == 0xFF18u) return cmp0_;
        if (addr == 0xFF19u) return cmp1_;
        if (addr == 0xFF69u) return tmhmd_;
    } else {
        if (addr == 0xFF1Au) return cmp0_;
        if (addr == 0xFF1Bu) return cmp1_;
        if (addr == 0xFF6Cu) return tmhmd_;
        if (addr == 0xFF6Du) return tmcyc1_;
    }
    return 0;
}

void Kx2TimerH::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2TimerH::Poke(uint16_t addr, uint8_t value) {
    if (ch_ == 0) {
        if (addr == 0xFF18u) { cmp0_ = value; return; }
        if (addr == 0xFF19u) { cmp1_ = value; return; }
        if (addr == 0xFF69u) {
            tmhmd_ = value;
            if ((tmhmd_ & 0x80u) == 0) {
                cnt_ = 0;
                prescaler_acc_ = 0;
            }
            return;
        }
    } else {
        if (addr == 0xFF1Au) { cmp0_ = value; return; }
        if (addr == 0xFF1Bu) { cmp1_ = value; return; }
        if (addr == 0xFF6Cu) {
            tmhmd_ = value;
            if ((tmhmd_ & 0x80u) == 0) {
                cnt_ = 0;
                prescaler_acc_ = 0;
            }
            return;
        }
        if (addr == 0xFF6Du) { tmcyc1_ = value & 0x07u; return; }
    }
}

void Kx2TimerH::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t rl_cycles, bool, bool in_stop) {
    if ((tmhmd_ & 0x80u) == 0) return;

    const uint8_t cks = (tmhmd_ >> 4) & 0x07u;
    uint32_t src_clocks = 0;
    uint32_t div = 1u;

    if (ch_ == 0) {
        if (in_stop) return;
        static const uint32_t kDiv0[8] = { 1u, 2u, 4u, 64u, 1024u, 0u, 0u, 0u };
        div = kDiv0[cks];
        src_clocks = prs_cycles;
    } else {
        if (cks >= 5u) {
            // fRL / 2^7, fRL / 2^9, fRL (operates even in HALT/STOP!)
            static const uint32_t kRlDiv[3] = { 128u, 512u, 1u };
            div = kRlDiv[cks - 5u];
            src_clocks = rl_cycles;
        } else {
            if (in_stop) return;
            static const uint32_t kDiv1[5] = { 1u, 4u, 16u, 64u, 4096u };
            div = kDiv1[cks];
            src_clocks = prs_cycles;
        }
    }

    if (div == 0 || src_clocks == 0) return;
    prescaler_acc_ += src_clocks;
    const uint32_t ticks = prescaler_acc_ / div;
    prescaler_acc_ %= div;
    if (ticks == 0) return;

    const uint32_t period = static_cast<uint32_t>(cmp0_) + 1u;
    uint32_t total = static_cast<uint32_t>(cnt_) + ticks;
    if (total >= period) {
        cnt_ = static_cast<uint8_t>(total % period);
        if (intc_) intc_->RaiseIrq(irq_match_);
    } else {
        cnt_ = static_cast<uint8_t>(total);
    }
}

// ============================================================================
// Kx2WatchTimer (WTM at 0xFF6F; Legacy0831 WTNM0 at 0xFF41)
// ============================================================================

void Kx2WatchTimer::SetProfile(MachineProfile profile, uint8_t irq_wti, uint8_t irq_wt) {
    profile_ = profile;
    irq_wti_ = irq_wti;
    irq_wt_ = irq_wt;
}

void Kx2WatchTimer::Reset() {
    wtm_ = 0x00u;
    prescaler_counter_ = 0;
    watch_counter_ = 0;
}

uint8_t Kx2WatchTimer::Read(uint16_t) {
    return wtm_;
}

uint8_t Kx2WatchTimer::Peek(uint16_t) const {
    return wtm_;
}

void Kx2WatchTimer::Write(uint16_t, uint8_t value) {
    const uint8_t old = wtm_;
    wtm_ = value;
    if ((value & 0x01u) == 0) {
        prescaler_counter_ = 0;
        watch_counter_ = 0;
    } else if ((old & 0x01u) == 0) {
        prescaler_counter_ = 0;
        watch_counter_ = 0;
    }
    if ((value & 0x02u) == 0) {
        watch_counter_ = 0;
    }
}

void Kx2WatchTimer::Poke(uint16_t addr, uint8_t value) {
    Write(addr, value);
}

uint32_t Kx2WatchTimer::PrescalerIntervalPrs() const {
    const uint8_t exp = static_cast<uint8_t>(4u + ((wtm_ >> 4) & 0x07u));
    if (profile_ == MachineProfile::Legacy0831) {
        const uint32_t fw_div = (wtm_ & 0x80u) ? (1u << 6) : (1u << 7);
        return (1u << exp) * fw_div;
    }
    return (1u << exp) * ((wtm_ & 0x80u) ? 1u : 128u);
}

uint32_t Kx2WatchTimer::WatchIntervalPrs() const {
    static const uint8_t kWatchExp[4] = { 14u, 13u, 5u, 4u };
    const uint8_t exp = kWatchExp[(wtm_ >> 2) & 0x03u];
    if (profile_ == MachineProfile::Legacy0831) {
        const uint32_t fw_div = (wtm_ & 0x80u) ? (1u << 6) : (1u << 7);
        return (1u << exp) * fw_div;
    }
    return (1u << exp) * ((wtm_ & 0x80u) ? 1u : 128u);
}

void Kx2WatchTimer::Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
                         uint32_t, bool, bool in_stop) {
    if ((wtm_ & 0x01u) == 0) return;

    uint32_t clk_ticks = 0;
    if (profile_ == MachineProfile::Legacy0831) {
        clk_ticks = cpu_cycles;
    } else if ((wtm_ & 0x80u) != 0) {
        clk_ticks = sub_cycles;
    } else {
        if (in_stop) return;
        clk_ticks = prs_cycles;
    }
    if (clk_ticks == 0) return;

    const uint32_t p_int = PrescalerIntervalPrs();
    prescaler_counter_ += clk_ticks;
    if (prescaler_counter_ >= p_int) {
        prescaler_counter_ %= p_int;
        if (intc_) intc_->RaiseIrq(irq_wti_);
    }

    if ((wtm_ & 0x02u) == 0) return;
    const uint32_t w_int = WatchIntervalPrs();
    watch_counter_ += clk_ticks;
    if (watch_counter_ >= w_int) {
        watch_counter_ %= w_int;
        if (intc_) intc_->RaiseIrq(irq_wt_);
    }
}

// ============================================================================
// Kx2Adc
// ============================================================================

void Kx2Adc::SetProfile(MachineProfile profile, uint8_t irq_ad) {
    profile_ = profile;
    irq_ad_ = irq_ad;
}

void Kx2Adc::SetChannelValue(uint8_t ch, uint16_t val10) {
    channels_[ch & 7u] = val10 & 0x03FFu;
}

void Kx2Adc::Reset() {
    adcr_ = (profile_ == MachineProfile::Legacy0831) ? static_cast<uint16_t>(channels_[0] & 0xFFu) : 0x0000u;
    adm_ = 0x00u;
    ads_ = 0x00u;
    conv_ticks_ = 0;
    converting_ = false;
}

uint8_t Kx2Adc::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Adc::Peek(uint16_t addr) const {
    if (profile_ == MachineProfile::Legacy0831) {
        if (addr == 0xFF17u) return static_cast<uint8_t>(adcr_ & 0xFFu);
        if (addr == 0xFF80u) return adm_;
        if (addr == 0xFF81u) return ads_;
        return 0;
    }
    if (addr == 0xFF08u) return static_cast<uint8_t>(adcr_ & 0xFFu);
    if (addr == 0xFF09u) return static_cast<uint8_t>(adcr_ >> 8);
    if (addr == 0xFF28u) return adm_;
    if (addr == 0xFF29u) return ads_;
    return 0;
}

void Kx2Adc::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

void Kx2Adc::Poke(uint16_t addr, uint8_t value) {
    const uint16_t adm_addr = (profile_ == MachineProfile::Legacy0831) ? 0xFF80u : 0xFF28u;
    const uint16_t ads_addr = (profile_ == MachineProfile::Legacy0831) ? 0xFF81u : 0xFF29u;

    if (addr == adm_addr) {
        const uint8_t old = adm_;
        adm_ = value;
        if ((value & 0x80u) != 0 && (old & 0x80u) == 0) {
            if (profile_ == MachineProfile::Legacy0831) {
                adcr_ = static_cast<uint16_t>(channels_[ads_ & 7u] & 0xFFu);
                if (intc_) intc_->RaiseIrq(irq_ad_);
            } else {
                converting_ = true;
                conv_ticks_ = 0;
            }
        } else if ((value & 0x80u) == 0) {
            converting_ = false;
            conv_ticks_ = 0;
        }
        return;
    }
    if (addr == ads_addr) {
        ads_ = value & 0x07u;
    }
}

void Kx2Adc::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (profile_ == MachineProfile::Legacy0831 || in_stop || (adm_ & 0x80u) == 0) {
        return;
    }
    if (!converting_) {
        converting_ = true;
        conv_ticks_ = 0;
    }
    static const uint32_t kConvCycles[6] = { 264u, 176u, 132u, 88u, 66u, 44u };
    const uint8_t fr = (adm_ >> 3) & 0x07u;
    const uint32_t target = (fr < 6u) ? kConvCycles[fr] : 264u;
    conv_ticks_ += prs_cycles;
    if (conv_ticks_ >= target) {
        conv_ticks_ = 0;
        // 10-bit result left-aligned in ADCR (0xFF08..0xFF09): bits [15:6] = value, bits [5:0] = 0
        adcr_ = static_cast<uint16_t>((channels_[ads_ & 7u] & 0x03FFu) << 6);
        if (intc_) intc_->RaiseIrq(irq_ad_);
    }
}

// ============================================================================
// Kx2Uart6 & Kx2Uart0
// ============================================================================

void Kx2Uart6::Reset() {
    rxb_ = 0xFFu;
    txb_ = 0xFFu;
    asim_ = 0x01u;
    asis_ = 0x00u;
    asif_ = 0x00u;
    cksr_ = 0x00u;
    brgc_ = 0xFFu;
    asicl_ = 0x16u;
    rx_unread_ = false;
    tx_ticks_left_ = 0;
    tx_log_.clear();
}

uint8_t Kx2Uart6::Read(uint16_t addr) {
    const uint8_t v = Peek(addr);
    if (addr == 0xFF0Au) {
        rx_unread_ = false;
    } else if (addr == 0xFF53u) {
        asis_ = 0x00u;  // Cleared on CPU read (78K0KX2.pdf p. 462)
    }
    return v;
}

uint8_t Kx2Uart6::Peek(uint16_t addr) const {
    switch (addr) {
    case 0xFF0Au: return rxb_;
    case 0xFF0Bu: return txb_;
    case 0xFF50u: return asim_;
    case 0xFF53u: return asis_;
    case 0xFF55u: return asif_;
    case 0xFF56u: return cksr_;
    case 0xFF57u: return brgc_;
    case 0xFF58u: return asicl_;
    default: return 0;
    }
}

void Kx2Uart6::Write(uint16_t addr, uint8_t value) {
    if (addr == 0xFF0Bu) {
        txb_ = value;
        if ((asim_ & 0xC0u) == 0xC0u) {
            tx_log_.push_back(value);
            if (tx_cb_) tx_cb_(value);
            asif_ |= 0x03u;  // TXBF6 | TXSF6
            tx_ticks_left_ = 16u;
        }
        return;
    }
    Poke(addr, value);
}

void Kx2Uart6::Poke(uint16_t addr, uint8_t value) {
    switch (addr) {
    case 0xFF0Bu: txb_ = value; break;
    case 0xFF50u:
        asim_ = value;
        if ((asim_ & 0x80u) == 0 || (asim_ & 0x40u) == 0) {
            asif_ = 0x00u;
            tx_ticks_left_ = 0;
        }
        if ((asim_ & 0x80u) == 0 || (asim_ & 0x20u) == 0) {
            asis_ = 0x00u;
            rx_unread_ = false;
        }
        break;
    case 0xFF56u: cksr_ = value & 0x0Fu; break;
    case 0xFF57u: brgc_ = value; break;
    case 0xFF58u: asicl_ = (asicl_ & 0x80u) | (value & 0x7Fu); break;
    default: break;
    }
}

void Kx2Uart6::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (in_stop || tx_ticks_left_ == 0) return;
    if (prs_cycles >= tx_ticks_left_) {
        tx_ticks_left_ = 0;
        asif_ = 0x00u;
        if (intc_) intc_->RaiseIrq(irq_tx_);
    } else {
        tx_ticks_left_ -= prs_cycles;
    }
}

void Kx2Uart6::InjectRxByte(uint8_t byte) {
    if ((asim_ & 0xA0u) != 0xA0u) return;
    if (rx_unread_) {
        asis_ |= 0x01u;  // OVE6
        if (intc_) intc_->RaiseIrq((asim_ & 0x01u) ? irq_rx_ : irq_err_);
        return;
    }
    rxb_ = byte;
    rx_unread_ = true;
    if (intc_) intc_->RaiseIrq(irq_rx_);
}

void Kx2Uart0::Reset() {
    asim_ = 0x01u;
    brgc_ = 0x1Fu;
    rxb_ = 0xFFu;
    asis_ = 0x00u;
    txs_ = 0xFFu;
    tx_busy_ = false;
    tx_ticks_left_ = 0;
    tx_log_.clear();
}

uint8_t Kx2Uart0::Read(uint16_t addr) {
    const uint8_t v = Peek(addr);
    if (addr == 0xFF73u) {
        asis_ = 0x00u;
    }
    return v;
}

uint8_t Kx2Uart0::Peek(uint16_t addr) const {
    switch (addr) {
    case 0xFF70u: return asim_;
    case 0xFF71u: return brgc_;
    case 0xFF72u: return rxb_;
    case 0xFF73u: return asis_;
    case 0xFF74u: return txs_;
    default: return 0;
    }
}

void Kx2Uart0::Write(uint16_t addr, uint8_t value) {
    if (addr == 0xFF74u) {
        txs_ = value;
        if ((asim_ & 0xC0u) == 0xC0u) {
            tx_log_.push_back(value);
            tx_busy_ = true;
            tx_ticks_left_ = 16u;
        }
        return;
    }
    Poke(addr, value);
}

void Kx2Uart0::Poke(uint16_t addr, uint8_t value) {
    switch (addr) {
    case 0xFF70u: asim_ = value & 0xFCu; break;
    case 0xFF71u: brgc_ = value & 0xDFu; break;
    default: break;
    }
}

void Kx2Uart0::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (in_stop || !tx_busy_) return;
    if (prs_cycles >= tx_ticks_left_) {
        tx_busy_ = false;
        tx_ticks_left_ = 0;
        if (intc_) intc_->RaiseIrq(irq_tx_);
    } else {
        tx_ticks_left_ -= prs_cycles;
    }
}

void Kx2Uart0::InjectRxByte(uint8_t byte) {
    if ((asim_ & 0xA0u) != 0xA0u) return;
    rxb_ = byte;
    if (intc_) intc_->RaiseIrq(irq_rx_);
}

// ============================================================================
// Kx2Csi
// ============================================================================

void Kx2Csi::SetProfile(MachineProfile profile, uint8_t irq_xfer) {
    profile_ = profile;
    irq_xfer_ = irq_xfer;
}

void Kx2Csi::Reset() {
    sio_ = 0x00u;
    sotb_ = 0x00u;
    csim_ = 0x00u;
    csic_ = 0x00u;
}

void Kx2Csi::DoTransfer(uint8_t tx) {
    sio_ = spi_cb_ ? spi_cb_(tx) : 0xFFu;
    csim_ &= ~0x01u;  // CSOT1n = 0 (transfer complete)
    if (intc_) intc_->RaiseIrq(irq_xfer_);
}

uint8_t Kx2Csi::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Csi::Peek(uint16_t addr) const {
    if (profile_ == MachineProfile::Legacy0831) {
        if (addr == 0xFF1Au || addr == 0xFF1Bu) return sio_;
        if (addr == 0xFFB0u || addr == 0xFFB8u) return csim_;
        return 0;
    }
    if (ch_ == 0) {
        if (addr == 0xFF0Fu) return sio_;
        if (addr == 0xFF80u) return csim_;
        if (addr == 0xFF81u) return csic_;
        if (addr == 0xFF84u) return sotb_;
    } else {
        if (addr == 0xFF4Au) return sio_;
        if (addr == 0xFF88u) return csim_;
        if (addr == 0xFF89u) return csic_;
        if (addr == 0xFF4Cu) return sotb_;
    }
    return 0;
}

void Kx2Csi::Write(uint16_t addr, uint8_t value) {
    if (profile_ == MachineProfile::Legacy0831) {
        if (addr == 0xFFB0u || addr == 0xFFB8u) {
            csim_ = value;
            return;
        }
        if (addr == 0xFF1Au || addr == 0xFF1Bu) {
            DoTransfer(value);
            return;
        }
        return;
    }

    const uint16_t sotb_addr = (ch_ == 0) ? 0xFF84u : 0xFF4Cu;
    const uint16_t csim_addr = (ch_ == 0) ? 0xFF80u : 0xFF88u;
    const uint16_t csic_addr = (ch_ == 0) ? 0xFF81u : 0xFF89u;
    if (addr == csim_addr) { csim_ = value & 0xD0u; return; }
    if (addr == csic_addr) { csic_ = value & 0x1Fu; return; }
    if (addr == sotb_addr) {
        sotb_ = value;
        if ((csim_ & 0x80u) != 0) {
            DoTransfer(value);
        }
    }
}

void Kx2Csi::Poke(uint16_t addr, uint8_t value) {
    if (profile_ == MachineProfile::Legacy0831) {
        if (addr == 0xFF1Au || addr == 0xFF1Bu) sio_ = value;
        else if (addr == 0xFFB0u || addr == 0xFFB8u) csim_ = value;
        return;
    }
    const uint16_t sio_addr  = (ch_ == 0) ? 0xFF0Fu : 0xFF4Au;
    const uint16_t sotb_addr = (ch_ == 0) ? 0xFF84u : 0xFF4Cu;
    const uint16_t csim_addr = (ch_ == 0) ? 0xFF80u : 0xFF88u;
    const uint16_t csic_addr = (ch_ == 0) ? 0xFF81u : 0xFF89u;
    if (addr == sio_addr) sio_ = value;
    else if (addr == sotb_addr) sotb_ = value;
    else if (addr == csim_addr) csim_ = value;
    else if (addr == csic_addr) csic_ = value;
}

// ============================================================================
// Kx2Iic0
// ============================================================================

void Kx2Iic0::SetProfile(MachineProfile profile, uint8_t irq_iic) {
    profile_ = profile;
    irq_iic_ = irq_iic;
}

void Kx2Iic0::AddTarget(uint8_t addr7, I2cTargetDevice *target) {
    targets_[addr7 & 0x7Fu] = target;
}

void Kx2Iic0::Reset() {
    iic0_ = 0;
    iicc0_ = 0;
    sva0_ = 0;
    iiccl0_ = 0;
    iicx0_ = 0;
    iics0_ = 0;
    iicf0_ = 0;
    active_target_ = nullptr;
    is_read_ = false;
    waiting_ = false;
    start_pending_ = false;
}

uint8_t Kx2Iic0::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2Iic0::Peek(uint16_t addr) const {
    if (profile_ == MachineProfile::Legacy0831) {
        switch (addr) {
        case 0xFF1Fu: return iic0_;
        case 0xFFA8u: return iicc0_;
        case 0xFFA9u: return iics0_;
        case 0xFFAAu: return static_cast<uint8_t>(iiccl0_ | ((iicc0_ & 0x80u) ? 0x30u : 0x00u));
        default: return 0;
        }
    }
    switch (addr) {
    case 0xFFA5u: return iic0_;
    case 0xFFA6u: return iicc0_;
    case 0xFFA7u: return sva0_;
    case 0xFFA8u: return static_cast<uint8_t>(iiccl0_ | ((iicc0_ & 0x80u) ? 0x30u : 0x00u));
    case 0xFFA9u: return iicx0_;
    case 0xFFAAu: return iics0_;
    case 0xFFABu: return iicf0_;
    default: return 0;
    }
}

void Kx2Iic0::Write(uint16_t addr, uint8_t value) {
    const uint16_t reg_iic  = (profile_ == MachineProfile::Legacy0831) ? 0xFF1Fu : 0xFFA5u;
    const uint16_t reg_iicc = (profile_ == MachineProfile::Legacy0831) ? 0xFFA8u : 0xFFA6u;
    const uint16_t reg_iics = (profile_ == MachineProfile::Legacy0831) ? 0xFFA9u : 0xFFAAu;
    const uint16_t reg_cl   = (profile_ == MachineProfile::Legacy0831) ? 0xFFAAu : 0xFFA8u;

    if (addr == reg_iic) {
        iic0_ = value;
        if (start_pending_) {
            start_pending_ = false;
            DoStart();
        } else if (waiting_) {
            DoNextByte();
        }
        return;
    }
    if (addr == reg_iicc) {
        WriteIicc0(value);
        return;
    }
    if (addr == reg_iics) {
        iics0_ = value;
        return;
    }
    if (addr == reg_cl) {
        iiccl0_ = value & 0x0Fu;
        return;
    }
    if (profile_ == MachineProfile::Kx2) {
        if (addr == 0xFFA7u) sva0_ = value & 0xFEu;
        else if (addr == 0xFFA9u) iicx0_ = value & 0x01u;
        else if (addr == 0xFFABu) iicf0_ = (iicf0_ & 0xC0u) | (value & 0x03u);
    }
}

void Kx2Iic0::Poke(uint16_t addr, uint8_t value) {
    const uint16_t reg_iic  = (profile_ == MachineProfile::Legacy0831) ? 0xFF1Fu : 0xFFA5u;
    const uint16_t reg_iicc = (profile_ == MachineProfile::Legacy0831) ? 0xFFA8u : 0xFFA6u;
    const uint16_t reg_iics = (profile_ == MachineProfile::Legacy0831) ? 0xFFA9u : 0xFFAAu;
    const uint16_t reg_cl   = (profile_ == MachineProfile::Legacy0831) ? 0xFFAAu : 0xFFA8u;
    if (addr == reg_iic) iic0_ = value;
    else if (addr == reg_iicc) iicc0_ = value;
    else if (addr == reg_iics) iics0_ = value;
    else if (addr == reg_cl) iiccl0_ = value;
    else if (addr == 0xFFA7u) sva0_ = value;
    else if (addr == 0xFFA9u) iicx0_ = value;
    else if (addr == 0xFFABu) iicf0_ = value;
}

void Kx2Iic0::WriteIicc0(uint8_t val) {
    const uint8_t old = iicc0_;
    iicc0_ = val;

    if ((val & 0x80u) == 0) {
        iics0_ = 0x00u;
        iicf0_ &= ~0xC0u;
        active_target_ = nullptr;
        waiting_ = false;
        start_pending_ = false;
        return;
    }

    if ((val & 0x40u) != 0) {  // LREL0
        iicc0_ &= ~0x43u;
        iics0_ &= ~0xFFu;
        active_target_ = nullptr;
        waiting_ = false;
        start_pending_ = false;
        return;
    }

    if ((val & 0x02u) && !(old & 0x02u)) {  // STT0
        start_pending_ = true;
    }
    if ((val & 0x01u) && !(old & 0x01u)) {  // SPT0
        DoStop();
    }
    if ((val & 0x20u) && !(old & 0x20u)) {  // WREL0
        DoNextByte();
    }
}

void Kx2Iic0::DoStart() {
    const uint8_t addr7 = iic0_ >> 1;
    is_read_ = (iic0_ & 0x01u) != 0;

    // Kx2: MSTS0=0x80, TRC0=0x08, ACKD0=0x04, STD0=0x02, SPD0=0x01
    // 0831Y: MSTS0=0x80, TRC0=0x08, ACKD0=0x04, STD0=0x01
    const uint8_t std_bit = (profile_ == MachineProfile::Legacy0831) ? 0x00u : 0x02u;
    iics0_ = static_cast<uint8_t>(0x80u | 0x08u | std_bit);
    if (profile_ == MachineProfile::Kx2) {
        iicf0_ |= 0x40u;  // IICBSY
    }

    auto it = targets_.find(addr7);
    if (it != targets_.end() && it->second != nullptr) {
        active_target_ = it->second;
        active_target_->I2cStart(is_read_);
        iics0_ |= 0x04u;  // ACKD0
    } else {
        active_target_ = nullptr;
    }

    iicc0_ &= ~0x02u;  // clear STT0
    waiting_ = true;
    if (intc_) intc_->RaiseIrq(irq_iic_);
}

void Kx2Iic0::DoStop() {
    if (active_target_) {
        active_target_->I2cStop();
        active_target_ = nullptr;
    }
    waiting_ = false;
    start_pending_ = false;
    const uint8_t spd_bit = 0x01u;
    iics0_ = static_cast<uint8_t>((iics0_ & ~0x02u) | spd_bit);
    if (profile_ == MachineProfile::Kx2) {
        iicf0_ &= ~0x40u;  // IICBSY = 0
    }
    iicc0_ &= ~0x01u;  // clear SPT0
    if (intc_) intc_->RaiseIrq(irq_iic_);
}

void Kx2Iic0::DoNextByte() {
    iicc0_ &= ~0x20u;  // clear WREL0
    if (!active_target_) {
        iics0_ &= ~0x04u;  // ACKD0 = 0
        if (intc_) intc_->RaiseIrq(irq_iic_);
        return;
    }
    if (is_read_) {
        iic0_ = active_target_->I2cRead();
        iics0_ = static_cast<uint8_t>((iics0_ & ~0x08u) | 0x04u);
    } else {
        const bool ack = active_target_->I2cWrite(iic0_);
        iics0_ |= 0x08u;
        if (ack) iics0_ |= 0x04u;
        else iics0_ &= ~0x04u;
    }
    waiting_ = true;
    if (intc_) intc_->RaiseIrq(irq_iic_);
}

// ============================================================================
// Kx2MulDiv (0xFF60..0xFF68)
// ============================================================================

void Kx2MulDiv::Reset() {
    sdr0_ = 0;
    mda0_ = 0;
    mdb0_ = 0;
    dmuc0_ = 0;
    ticks_left_ = 0;
    running_ = false;
}

uint8_t Kx2MulDiv::Read(uint16_t addr) {
    return Peek(addr);
}

uint8_t Kx2MulDiv::Peek(uint16_t addr) const {
    switch (addr) {
    case 0xFF60u: return static_cast<uint8_t>(sdr0_ & 0xFFu);
    case 0xFF61u: return static_cast<uint8_t>(sdr0_ >> 8);
    case 0xFF62u: return static_cast<uint8_t>(mda0_ & 0xFFu);
    case 0xFF63u: return static_cast<uint8_t>((mda0_ >> 8) & 0xFFu);
    case 0xFF64u: return static_cast<uint8_t>((mda0_ >> 16) & 0xFFu);
    case 0xFF65u: return static_cast<uint8_t>((mda0_ >> 24) & 0xFFu);
    case 0xFF66u: return static_cast<uint8_t>(mdb0_ & 0xFFu);
    case 0xFF67u: return static_cast<uint8_t>(mdb0_ >> 8);
    case 0xFF68u: return dmuc0_;
    default: return 0;
    }
}

void Kx2MulDiv::Write(uint16_t addr, uint8_t value) {
    if (addr == 0xFF68u) {
        dmuc0_ = value & 0x81u;
        if (dmuc0_ & 0x80u) {
            running_ = true;
            ticks_left_ = (dmuc0_ & 0x01u) ? 16u : 32u;
        } else {
            running_ = false;
            ticks_left_ = 0;
        }
        return;
    }
    Poke(addr, value);
}

void Kx2MulDiv::Poke(uint16_t addr, uint8_t value) {
    switch (addr) {
    case 0xFF62u: mda0_ = (mda0_ & 0xFFFFFF00u) | value; break;
    case 0xFF63u: mda0_ = (mda0_ & 0xFFFF00FFu) | (uint32_t(value) << 8); break;
    case 0xFF64u: mda0_ = (mda0_ & 0xFF00FFFFu) | (uint32_t(value) << 16); break;
    case 0xFF65u: mda0_ = (mda0_ & 0x00FFFFFFu) | (uint32_t(value) << 24); break;
    case 0xFF66u: mdb0_ = static_cast<uint16_t>((mdb0_ & 0xFF00u) | value); break;
    case 0xFF67u: mdb0_ = static_cast<uint16_t>((mdb0_ & 0x00FFu) | (uint16_t(value) << 8)); break;
    case 0xFF68u: dmuc0_ = value & 0x81u; break;
    default: break;
    }
}

void Kx2MulDiv::CompleteOperation() {
    running_ = false;
    ticks_left_ = 0;
    if (dmuc0_ & 0x01u) {  // Multiplication: MDA0L * MDB0 -> MDA0
        const uint32_t a = mda0_ & 0xFFFFu;
        mda0_ = a * static_cast<uint32_t>(mdb0_);
    } else {  // Division: MDA0 / MDB0 -> MDA0, remainder -> SDR0
        if (mdb0_ == 0) {
            mda0_ = 0xFFFFFFFFu;
            sdr0_ = 0;
        } else {
            const uint32_t q = mda0_ / mdb0_;
            const uint16_t r = static_cast<uint16_t>(mda0_ % mdb0_);
            mda0_ = q;
            sdr0_ = r;
        }
    }
    dmuc0_ &= ~0x80u;
    if (intc_) intc_->RaiseIrq(irq_dmu_);
}

void Kx2MulDiv::Tick(uint32_t, uint32_t prs_cycles, uint32_t, uint32_t, bool, bool in_stop) {
    if (in_stop || !running_) return;
    if (prs_cycles >= ticks_left_) {
        CompleteOperation();
    } else {
        ticks_left_ -= prs_cycles;
    }
}

}  // namespace k0
