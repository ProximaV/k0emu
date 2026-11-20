#include "cpu.h"

#include "log.h"

namespace k0 {

namespace {

inline uint16_t MakeWord(uint8_t lo, uint8_t hi) {
    return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
}

inline uint16_t DecodeSaddr(uint8_t offset) {
    return static_cast<uint16_t>(offset < 0x20u ? (0xFF00u + offset) : (0xFE00u + offset));
}

inline uint16_t DecodeSfr(uint8_t offset) {
    return static_cast<uint16_t>(0xFF00u + offset);
}

}  // namespace

uint8_t K0Cpu::StatusSfrDevice::Read(uint16_t addr) {
    return Peek(addr);
}

void K0Cpu::StatusSfrDevice::Write(uint16_t addr, uint8_t value) {
    Poke(addr, value);
}

uint8_t K0Cpu::StatusSfrDevice::Peek(uint16_t addr) const {
    if (!cpu_) return 0;
    switch (addr) {
    case kSpAddress:     return static_cast<uint8_t>(cpu_->sp_ & 0xFFu);
    case kSpAddress + 1: return static_cast<uint8_t>((cpu_->sp_ >> 8) & 0xFFu);
    case kPswAddress:    return cpu_->GetPSW();
    default:             return 0;
    }
}

void K0Cpu::StatusSfrDevice::Poke(uint16_t addr, uint8_t value) {
    if (!cpu_) return;
    switch (addr) {
    case kSpAddress:
        cpu_->sp_ = static_cast<uint16_t>((cpu_->sp_ & 0xFF00u) | value);
        break;
    case kSpAddress + 1:
        cpu_->sp_ = static_cast<uint16_t>((cpu_->sp_ & 0x00FFu) | (static_cast<uint16_t>(value) << 8));
        break;
    case kPswAddress:
        cpu_->SetPSW(value);
        break;
    default:
        break;
    }
}

K0Cpu::K0Cpu() : status_dev_(this) {
    InitTables();
}

void K0Cpu::AttachBus(K0Bus *bus) {
    bus_ = bus;
    if (bus_) {
        bus_->MapSfrRange(kSpAddress, kPswAddress, &status_dev_);
    }
}

void K0Cpu::Reset() {
    uint16_t entry = 0;
    if (bus_) {
        const uint8_t lo = bus_->PeekByte(kResetVectorAddress);
        const uint8_t hi = bus_->PeekByte(kResetVectorAddress + 1u);
        entry = MakeWord(lo, hi);
    }
    ResetTo(entry);
}

void K0Cpu::ResetTo(uint16_t entry_pc) {
    SetPSW(PSW_ISP);
    SetSP(0x0000u);
    pc_ = entry_pc;
    run_state_ = RunState::Running;
    total_cycles_ = 0;
    inst_cycles_ = 0;
    insn_count_ = 0;
    interrupt_delayed_ = false;
    invalid_insn_ = false;
    brk_stopped_ = false;
    halt_entered_ = false;
    stop_entered_ = false;
    wdt_reset_pending_ = false;
    current_insn_pc_ = entry_pc;
    last_invalid_opcode_ = 0;
}

uint8_t K0Cpu::ReadRegBank(uint8_t reg, uint8_t bank) const {
    if (!bus_) return 0;
    return bus_->PeekByte(AddressOfReg(reg, bank));
}

void K0Cpu::WriteRegBank(uint8_t reg, uint8_t bank, uint8_t val) {
    if (!bus_) return;
    bus_->PokeByte(AddressOfReg(reg, bank), val);
}

uint16_t K0Cpu::ReadRegPairBank(uint8_t rp, uint8_t bank) const {
    const uint8_t lo = ReadRegBank(static_cast<uint8_t>((rp & 3u) << 1), bank);
    const uint8_t hi = ReadRegBank(static_cast<uint8_t>(((rp & 3u) << 1) + 1u), bank);
    return MakeWord(lo, hi);
}

void K0Cpu::WriteRegPairBank(uint8_t rp, uint8_t bank, uint16_t val) {
    WriteRegBank(static_cast<uint8_t>((rp & 3u) << 1), bank, static_cast<uint8_t>(val & 0xFFu));
    WriteRegBank(static_cast<uint8_t>(((rp & 3u) << 1) + 1u), bank, static_cast<uint8_t>((val >> 8) & 0xFFu));
}

void K0Cpu::AddBreakpoint(uint16_t addr) {
    breakpoints_.insert(addr);
}

void K0Cpu::RemoveBreakpoint(uint16_t addr) {
    breakpoints_.erase(addr);
}

void K0Cpu::ClearBreakpoints() {
    breakpoints_.clear();
}

bool K0Cpu::HasBreakpoint(uint16_t addr) const {
    return breakpoints_.find(addr) != breakpoints_.end();
}

void K0Cpu::CheckInterruptHold(uint16_t addr) {
    if (addr == kPswAddress || (addr >= 0xFFE0u && addr <= 0xFFEBu)) {
        interrupt_delayed_ = true;
    }
}

void K0Cpu::TickBus(uint32_t cycles, bool in_halt, bool in_stop) {
    if (!bus_ || cycles == 0) {
        return;
    }
    uint32_t prs = cycles;
    uint32_t sub = 0;
    uint32_t rl = 0;
    if (clock_) {
        clock_->ComputeSubClocks(cycles, in_halt, in_stop, &prs, &sub, &rl);
    }
    bus_->TickDevices(in_halt || in_stop ? 0u : cycles, prs, sub, rl, in_halt, in_stop);
}

void K0Cpu::DispatchInterruptIfReady() {
    if (!intc_) {
        return;
    }
    if (interrupt_delayed_) {
        interrupt_delayed_ = false;
        return;
    }
    uint8_t psw = GetPSW();
    if ((psw & PSW_IE) == 0) {
        return;
    }
    const PendingInterrupt pending = intc_->EvaluatePending();
    if (!pending.pending) {
        return;
    }
    if ((psw & PSW_ISP) == 0 && !pending.high_priority) {
        return;
    }

    intc_->Acknowledge(pending.source_index);
    PushByte(psw);
    psw &= ~PSW_IE;
    if (pending.high_priority) {
        psw &= ~PSW_ISP;
    } else {
        psw |= PSW_ISP;
    }
    SetPSW(psw);
    PushWord(pc_);
    const uint8_t lo = bus_->PeekByte(pending.vector_address);
    const uint8_t hi = bus_->PeekByte(static_cast<uint16_t>(pending.vector_address + 1u));
    pc_ = MakeWord(lo, hi);
}

StopInfo K0Cpu::Step(bool ignore_bpt_at_pc) {
    if (!bus_) {
        return StopInfo{StopReason::InvalidInsn, pc_, 0, false};
    }

    bus_->ClearFaults();
    invalid_insn_ = false;
    brk_stopped_ = false;
    halt_entered_ = false;
    stop_entered_ = false;
    wdt_reset_pending_ = false;
    current_insn_pc_ = pc_;

    if (!ignore_bpt_at_pc && HasBreakpoint(pc_)) {
        return StopInfo{StopReason::Breakpoint, pc_, 0, false};
    }

    // Standby states (HALT / STOP): clock peripherals until an unmasked interrupt releases standby.
    if (run_state_ == RunState::Halted || run_state_ == RunState::Stopped) {
        const bool was_stop = (run_state_ == RunState::Stopped);
        const uint32_t standby_cycles = 2u;
        inst_cycles_ = standby_cycles;
        total_cycles_ += standby_cycles;
        TickBus(standby_cycles, !was_stop, was_stop);

        if (wdt_reset_pending_) {
            wdt_reset_pending_ = false;
            return StopInfo{StopReason::WdtReset, pc_, 0, false};
        }

        if (intc_ && intc_->HasUnmaskedPending()) {
            if (was_stop && clock_) {
                clock_->OnExitStop();
            }
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    inst_cycles_ = 0;
    const uint8_t opcode = ConsumeByte();
    (this->*tbl_unprefixed_[opcode])(opcode);
    total_cycles_ += inst_cycles_;

    if (invalid_insn_) {
        pc_ = current_insn_pc_;
        return StopInfo{StopReason::InvalidInsn, current_insn_pc_, last_invalid_opcode_, false};
    }

    ++insn_count_;

    // Clock peripherals by the elapsed instruction cycles.
    TickBus(inst_cycles_, halt_entered_, stop_entered_);

    if (wdt_reset_pending_) {
        wdt_reset_pending_ = false;
        return StopInfo{StopReason::WdtReset, pc_, 0, false};
    }
    if (brk_stopped_) {
        return StopInfo{StopReason::BreakInsn, current_insn_pc_, 0, false};
    }
    if (bus_->unmapped_fault) {
        return StopInfo{StopReason::UnmappedMemory, current_insn_pc_, bus_->fault_addr, bus_->fault_is_write};
    }
    if (bus_->watchpoint_hit) {
        return StopInfo{StopReason::Watchpoint, current_insn_pc_, bus_->watchpoint_addr, bus_->watchpoint_is_write};
    }

    if (halt_entered_) {
        if (stop_on_halt) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::Halt, current_insn_pc_, 0, false};
        }
        if (intc_ && intc_->HasUnmaskedPending()) {
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        } else {
            run_state_ = RunState::Halted;
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    if (stop_entered_) {
        if (stop_on_stop) {
            run_state_ = RunState::Stopped;
            return StopInfo{StopReason::Stop, current_insn_pc_, 0, false};
        }
        if (intc_ && intc_->HasUnmaskedPending()) {
            if (clock_) {
                clock_->OnExitStop();
            }
            run_state_ = RunState::Running;
            DispatchInterruptIfReady();
        } else {
            run_state_ = RunState::Stopped;
        }
        return StopInfo{StopReason::None, pc_, 0, false};
    }

    DispatchInterruptIfReady();
    return StopInfo{StopReason::None, pc_, 0, false};
}

uint8_t K0Cpu::ConsumeByte() {
    ++inst_cycles_;
    const uint8_t v = bus_->FetchByte(pc_);
    pc_ = static_cast<uint16_t>(pc_ + 1u);
    return v;
}

uint16_t K0Cpu::ConsumeWord() {
    const uint8_t lo = ConsumeByte();
    const uint8_t hi = ConsumeByte();
    return MakeWord(lo, hi);
}

uint16_t K0Cpu::ConsumeSfr() {
    const uint16_t addr = DecodeSfr(ConsumeByte());
    CheckInterruptHold(addr);
    return addr;
}

uint16_t K0Cpu::ConsumeSfrP() {
    const uint16_t addr = DecodeSfr(ConsumeByte());
    if ((addr & 1u) != 0) {
        LOG_WARN("Odd sfrp address 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    CheckInterruptHold(addr);
    CheckInterruptHold(static_cast<uint16_t>(addr + 1u));
    return addr;
}

uint16_t K0Cpu::ConsumeSaddr() {
    const uint16_t addr = DecodeSaddr(ConsumeByte());
    CheckInterruptHold(addr);
    return addr;
}

uint16_t K0Cpu::ConsumeSaddrP() {
    const uint16_t addr = DecodeSaddr(ConsumeByte());
    if ((addr & 1u) != 0) {
        LOG_WARN("Odd saddrp address 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    CheckInterruptHold(addr);
    CheckInterruptHold(static_cast<uint16_t>(addr + 1u));
    return addr;
}

uint8_t K0Cpu::BusRead(uint16_t addr) {
    ++inst_cycles_;
    if (!bus_->IsHighSpeed(addr)) {
        ++inst_cycles_;
    }
    return bus_->ReadCpu(addr);
}

void K0Cpu::BusWrite(uint16_t addr, uint8_t value) {
    ++inst_cycles_;
    if (!bus_->IsHighSpeed(addr)) {
        ++inst_cycles_;
    }
    bus_->WriteCpu(addr, value);
}

void K0Cpu::PushByte(uint8_t value) {
    sp_ = static_cast<uint16_t>(sp_ - 1u);
    ++inst_cycles_;
    bus_->WriteCpu(sp_, value);
}

uint8_t K0Cpu::PopByte() {
    ++inst_cycles_;
    const uint8_t v = bus_->ReadCpu(sp_);
    sp_ = static_cast<uint16_t>(sp_ + 1u);
    return v;
}

void K0Cpu::PushWord(uint16_t value) {
    PushByte(static_cast<uint8_t>((value >> 8) & 0xFFu));
    PushByte(static_cast<uint8_t>(value & 0xFFu));
}

uint16_t K0Cpu::PopWord() {
    const uint8_t lo = PopByte();
    const uint8_t hi = PopByte();
    return MakeWord(lo, hi);
}

uint16_t K0Cpu::BasedHlImm(uint8_t imm) const {
    return static_cast<uint16_t>(ReadRegPair(RP_HL) + imm);
}

uint16_t K0Cpu::BasedHlB() const {
    return static_cast<uint16_t>(ReadRegPair(RP_HL) + ReadReg(REG_B));
}

uint16_t K0Cpu::BasedHlC() const {
    return static_cast<uint16_t>(ReadRegPair(RP_HL) + ReadReg(REG_C));
}

uint16_t K0Cpu::ResolveRel(uint16_t pc, uint8_t disp) {
    const int8_t sdisp = static_cast<int8_t>(disp);
    return static_cast<uint16_t>(static_cast<int32_t>(pc) + static_cast<int32_t>(sdisp));
}

void K0Cpu::UpdatePswZ(uint8_t value) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~PSW_Z);
    if (value == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
}

uint8_t K0Cpu::OpAdd(uint8_t a, uint8_t b) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    if (((a & 0x0Fu) + (b & 0x0Fu)) > 0x0Fu) {
        psw |= PSW_AC;
    }
    const uint16_t sum = static_cast<uint16_t>(a) + static_cast<uint16_t>(b);
    if (sum > 0xFFu) {
        psw |= PSW_CY;
    }
    const uint8_t res = static_cast<uint8_t>(sum & 0xFFu);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint8_t K0Cpu::OpAddc(uint8_t a, uint8_t b) {
    uint8_t psw = GetPSW();
    const uint8_t carry = (psw & PSW_CY) ? 1u : 0u;
    psw &= static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    if (((a & 0x0Fu) + (b & 0x0Fu) + carry) > 0x0Fu) {
        psw |= PSW_AC;
    }
    const uint16_t sum = static_cast<uint16_t>(a) + static_cast<uint16_t>(b) + carry;
    if (sum > 0xFFu) {
        psw |= PSW_CY;
    }
    const uint8_t res = static_cast<uint8_t>(sum & 0xFFu);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint8_t K0Cpu::OpSub(uint8_t a, uint8_t b) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    if (((a & 0x0Fu) < (b & 0x0Fu))) {
        psw |= PSW_AC;
    }
    const int32_t diff = static_cast<int32_t>(a) - static_cast<int32_t>(b);
    if (diff < 0) {
        psw |= PSW_CY;
    }
    const uint8_t res = static_cast<uint8_t>(diff & 0xFF);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint8_t K0Cpu::OpSubc(uint8_t a, uint8_t b) {
    uint8_t psw = GetPSW();
    const int32_t carry = (psw & PSW_CY) ? 1 : 0;
    psw &= static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    if (static_cast<int32_t>(a & 0x0Fu) - static_cast<int32_t>(b & 0x0Fu) - carry < 0) {
        psw |= PSW_AC;
    }
    const int32_t diff = static_cast<int32_t>(a) - static_cast<int32_t>(b) - carry;
    if (diff < 0) {
        psw |= PSW_CY;
    }
    const uint8_t res = static_cast<uint8_t>(diff & 0xFF);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

void K0Cpu::OpCmp(uint8_t a, uint8_t b) {
    (void)OpSub(a, b);
}

uint8_t K0Cpu::OpAnd(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a & b);
    UpdatePswZ(res);
    return res;
}

uint8_t K0Cpu::OpOr(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a | b);
    UpdatePswZ(res);
    return res;
}

uint8_t K0Cpu::OpXor(uint8_t a, uint8_t b) {
    const uint8_t res = static_cast<uint8_t>(a ^ b);
    UpdatePswZ(res);
    return res;
}

uint8_t K0Cpu::OpInc(uint8_t val) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC));
    if ((val & 0x0Fu) == 0x0Fu) {
        psw |= PSW_AC;
    }
    const uint8_t res = static_cast<uint8_t>(val + 1u);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint8_t K0Cpu::OpDec(uint8_t val) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC));
    if ((val & 0x0Fu) == 0u) {
        psw |= PSW_AC;
    }
    const uint8_t res = static_cast<uint8_t>(val - 1u);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint16_t K0Cpu::OpAddw(uint16_t a, uint16_t b) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    const uint32_t sum = static_cast<uint32_t>(a) + static_cast<uint32_t>(b);
    if (sum > 0xFFFFu) {
        psw |= PSW_CY;
    }
    const uint16_t res = static_cast<uint16_t>(sum & 0xFFFFu);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

uint16_t K0Cpu::OpSubw(uint16_t a, uint16_t b) {
    uint8_t psw = GetPSW() & static_cast<uint8_t>(~(PSW_Z | PSW_AC | PSW_CY));
    const int32_t diff = static_cast<int32_t>(a) - static_cast<int32_t>(b);
    if (diff < 0) {
        psw |= PSW_CY;
    }
    const uint16_t res = static_cast<uint16_t>(diff & 0xFFFF);
    if (res == 0) {
        psw |= PSW_Z;
    }
    SetPSW(psw);
    return res;
}

// =========================================================================
// Opcode Table Initialization
// =========================================================================

void K0Cpu::InitTables() {
    tbl_unprefixed_.fill(&K0Cpu::OpInvalid);
    tbl_prefix31_.fill(&K0Cpu::OpInvalid);
    tbl_prefix61_.fill(&K0Cpu::OpInvalid);
    tbl_prefix71_.fill(&K0Cpu::OpInvalid);

    auto &U = tbl_unprefixed_;
    U[0x00] = &K0Cpu::OpNop;
    U[0x01] = &K0Cpu::OpNot1Cy;
    U[0x02] = &K0Cpu::OpMovwAxAddr16;
    U[0x03] = &K0Cpu::OpMovwAddr16Ax;
    U[0x04] = &K0Cpu::OpDbnzSaddr;
    U[0x05] = &K0Cpu::OpXchADe;
    U[0x07] = &K0Cpu::OpXchAHl;
    U[0x08] = &K0Cpu::OpAddAAddr16;
    U[0x09] = &K0Cpu::OpAddAHlDisp;
    U[0x0D] = &K0Cpu::OpAddAImm;
    U[0x0E] = &K0Cpu::OpAddASaddr;
    U[0x0F] = &K0Cpu::OpAddAHl;
    U[0x11] = &K0Cpu::OpMovSaddrImm;
    U[0x13] = &K0Cpu::OpMovSfrImm;
    U[0x18] = &K0Cpu::OpSubAAddr16;
    U[0x19] = &K0Cpu::OpSubAHlDisp;
    U[0x1D] = &K0Cpu::OpSubAImm;
    U[0x1E] = &K0Cpu::OpSubASaddr;
    U[0x1F] = &K0Cpu::OpSubAHl;
    U[0x20] = &K0Cpu::OpSet1Cy;
    U[0x21] = &K0Cpu::OpClr1Cy;
    U[0x22] = &K0Cpu::OpPushPsw;
    U[0x23] = &K0Cpu::OpPopPsw;
    U[0x24] = &K0Cpu::OpRorA;
    U[0x25] = &K0Cpu::OpRorcA;
    U[0x26] = &K0Cpu::OpRolA;
    U[0x27] = &K0Cpu::OpRolcA;
    U[0x28] = &K0Cpu::OpAddcAAddr16;
    U[0x29] = &K0Cpu::OpAddcAHlDisp;
    U[0x2D] = &K0Cpu::OpAddcAImm;
    U[0x2E] = &K0Cpu::OpAddcASaddr;
    U[0x2F] = &K0Cpu::OpAddcAHl;
    U[0x31] = &K0Cpu::OpPrefix31;
    U[0x38] = &K0Cpu::OpSubcAAddr16;
    U[0x39] = &K0Cpu::OpSubcAHlDisp;
    U[0x3D] = &K0Cpu::OpSubcAImm;
    U[0x3E] = &K0Cpu::OpSubcASaddr;
    U[0x3F] = &K0Cpu::OpSubcAHl;
    U[0x48] = &K0Cpu::OpCmpAAddr16;
    U[0x49] = &K0Cpu::OpCmpAHlDisp;
    U[0x4D] = &K0Cpu::OpCmpAImm;
    U[0x4E] = &K0Cpu::OpCmpASaddr;
    U[0x4F] = &K0Cpu::OpCmpAHl;
    U[0x58] = &K0Cpu::OpAndAAddr16;
    U[0x59] = &K0Cpu::OpAndAHlDisp;
    U[0x5D] = &K0Cpu::OpAndAImm;
    U[0x5E] = &K0Cpu::OpAndASaddr;
    U[0x5F] = &K0Cpu::OpAndAHl;
    U[0x61] = &K0Cpu::OpPrefix61;
    U[0x68] = &K0Cpu::OpOrAAddr16;
    U[0x69] = &K0Cpu::OpOrAHlDisp;
    U[0x6D] = &K0Cpu::OpOrAImm;
    U[0x6E] = &K0Cpu::OpOrASaddr;
    U[0x6F] = &K0Cpu::OpOrAHl;
    U[0x71] = &K0Cpu::OpPrefix71;
    U[0x78] = &K0Cpu::OpXorAAddr16;
    U[0x79] = &K0Cpu::OpXorAHlDisp;
    U[0x7D] = &K0Cpu::OpXorAImm;
    U[0x7E] = &K0Cpu::OpXorASaddr;
    U[0x7F] = &K0Cpu::OpXorAHl;
    U[0x81] = &K0Cpu::OpIncSaddr;
    U[0x83] = &K0Cpu::OpXchASaddr;
    U[0x85] = &K0Cpu::OpMovADe;
    U[0x87] = &K0Cpu::OpMovAHl;
    U[0x88] = &K0Cpu::OpAddSaddrImm;
    U[0x89] = &K0Cpu::OpMovwAxSaddrp;
    U[0x8A] = &K0Cpu::OpDbnzC;
    U[0x8B] = &K0Cpu::OpDbnzB;
    U[0x8D] = &K0Cpu::OpBc;
    U[0x8E] = &K0Cpu::OpMovAAddr16;
    U[0x8F] = &K0Cpu::OpReti;
    U[0x91] = &K0Cpu::OpDecSaddr;
    U[0x93] = &K0Cpu::OpXchASfr;
    U[0x95] = &K0Cpu::OpMovDeA;
    U[0x97] = &K0Cpu::OpMovHlA;
    U[0x98] = &K0Cpu::OpSubSaddrImm;
    U[0x99] = &K0Cpu::OpMovwSaddrpAx;
    U[0x9A] = &K0Cpu::OpCallAddr16;
    U[0x9B] = &K0Cpu::OpBrAddr16;
    U[0x9D] = &K0Cpu::OpBnc;
    U[0x9E] = &K0Cpu::OpMovAddr16A;
    U[0x9F] = &K0Cpu::OpRetb;
    U[0xA8] = &K0Cpu::OpAddcSaddrImm;
    U[0xA9] = &K0Cpu::OpMovwAxSfrp;
    U[0xAA] = &K0Cpu::OpMovAHlC;
    U[0xAB] = &K0Cpu::OpMovAHlB;
    U[0xAD] = &K0Cpu::OpBz;
    U[0xAE] = &K0Cpu::OpMovAHlDisp;
    U[0xAF] = &K0Cpu::OpRet;
    U[0xB8] = &K0Cpu::OpSubcSaddrImm;
    U[0xB9] = &K0Cpu::OpMovwSfrpAx;
    U[0xBA] = &K0Cpu::OpMovHlCA;
    U[0xBB] = &K0Cpu::OpMovHlBA;
    U[0xBD] = &K0Cpu::OpBnz;
    U[0xBE] = &K0Cpu::OpMovHlDispA;
    U[0xBF] = &K0Cpu::OpBrk;
    U[0xC8] = &K0Cpu::OpCmpSaddrImm;
    U[0xCA] = &K0Cpu::OpAddwAxImm;
    U[0xCE] = &K0Cpu::OpXchAAddr16;
    U[0xD8] = &K0Cpu::OpAndSaddrImm;
    U[0xDA] = &K0Cpu::OpSubwAxImm;
    U[0xDE] = &K0Cpu::OpXchAHlDisp;
    U[0xE8] = &K0Cpu::OpOrSaddrImm;
    U[0xEA] = &K0Cpu::OpCmpwAxImm;
    U[0xEE] = &K0Cpu::OpMovwSaddrpImm;
    U[0xF0] = &K0Cpu::OpMovASaddr;
    U[0xF2] = &K0Cpu::OpMovSaddrA;
    U[0xF4] = &K0Cpu::OpMovASfr;
    U[0xF6] = &K0Cpu::OpMovSfrA;
    U[0xF8] = &K0Cpu::OpXorSaddrImm;
    U[0xFA] = &K0Cpu::OpBrRel;
    U[0xFE] = &K0Cpu::OpMovwSfrpImm;

    for (uint8_t r = 0; r < 8; ++r) {
        if (r != REG_A) {
            U[0x30u + r] = &K0Cpu::OpXchAReg;
            U[0x60u + r] = &K0Cpu::OpMovAReg;
            U[0x70u + r] = &K0Cpu::OpMovRegA;
        }
        U[0x40u + r] = &K0Cpu::OpIncReg;
        U[0x50u + r] = &K0Cpu::OpDecReg;
        U[0xA0u + r] = &K0Cpu::OpMovRegImm;
    }

    for (uint8_t b = 0; b < 8; ++b) {
        const uint8_t hi = static_cast<uint8_t>(b << 4);
        U[0x0Au | hi] = &K0Cpu::OpSet1Saddr;
        U[0x0Bu | hi] = &K0Cpu::OpClr1Saddr;
        U[0x0Cu | hi] = &K0Cpu::OpCallf;
        U[0x8Cu | hi] = &K0Cpu::OpBtSaddr;
    }

    for (uint8_t rp = 0; rp < 4; ++rp) {
        const uint8_t p = static_cast<uint8_t>(rp << 1);
        U[0x10u | p] = &K0Cpu::OpMovwRpImm;
        U[0x80u | p] = &K0Cpu::OpIncwRp;
        U[0x90u | p] = &K0Cpu::OpDecwRp;
        U[0xB0u | p] = &K0Cpu::OpPopRp;
        U[0xB1u | p] = &K0Cpu::OpPushRp;
        if (rp != 0) {
            U[0xC0u | p] = &K0Cpu::OpMovwAxRp;
            U[0xD0u | p] = &K0Cpu::OpMovwRpAx;
            U[0xE0u | p] = &K0Cpu::OpXchwAxRp;
        }
    }

    for (uint16_t op = 0xC1u; op <= 0xFFu; op += 2u) {
        U[op] = &K0Cpu::OpCallt;
    }

    // 0x31 table
    auto &P31 = tbl_prefix31_;
    for (uint8_t op = 0; op < 8; ++op) {
        P31[(op << 4) | 0x0Au] = &K0Cpu::Op31AluHlIdx;
        P31[(op << 4) | 0x0Bu] = &K0Cpu::Op31AluHlIdx;
    }
    P31[0x80] = &K0Cpu::Op31Rol4;
    P31[0x82] = &K0Cpu::Op31Divuw;
    P31[0x88] = &K0Cpu::Op31Mulu;
    P31[0x8A] = &K0Cpu::Op31XchHlIdx;
    P31[0x8B] = &K0Cpu::Op31XchHlIdx;
    P31[0x90] = &K0Cpu::Op31Ror4;
    P31[0x98] = &K0Cpu::Op31BrAx;
    for (uint8_t b = 0; b < 8; ++b) {
        const uint8_t hi = static_cast<uint8_t>(b << 4);
        P31[hi | 0x01u] = &K0Cpu::Op31BitBranchSaddr;
        P31[hi | 0x03u] = &K0Cpu::Op31BitBranchSaddr;
        P31[hi | 0x05u] = &K0Cpu::Op31BitBranchSfr;
        P31[hi | 0x06u] = &K0Cpu::Op31BitBranchSfr;
        P31[hi | 0x07u] = &K0Cpu::Op31BitBranchSfr;
        P31[hi | 0x0Du] = &K0Cpu::Op31BitBranchA;
        P31[hi | 0x0Eu] = &K0Cpu::Op31BitBranchA;
        P31[hi | 0x0Fu] = &K0Cpu::Op31BitBranchA;
        P31[0x80u | hi | 0x05u] = &K0Cpu::Op31BitBranchHl;
        P31[0x80u | hi | 0x06u] = &K0Cpu::Op31BitBranchHl;
        P31[0x80u | hi | 0x07u] = &K0Cpu::Op31BitBranchHl;
    }

    // 0x61 table
    auto &P61 = tbl_prefix61_;
    for (uint8_t alu = 0; alu < 8; ++alu) {
        const uint8_t base = static_cast<uint8_t>(alu << 4);
        for (uint8_t r = 0; r < 8; ++r) {
            P61[base | r] = &K0Cpu::Op61AluReg;
            if (r != REG_A) {
                P61[base | 0x08u | r] = &K0Cpu::Op61AluReg;
            }
        }
    }
    P61[0x80] = &K0Cpu::Op61Adjba;
    P61[0x90] = &K0Cpu::Op61Adjbs;
    P61[0xD0] = &K0Cpu::Op61SelRb;
    P61[0xD8] = &K0Cpu::Op61SelRb;
    P61[0xF0] = &K0Cpu::Op61SelRb;
    P61[0xF8] = &K0Cpu::Op61SelRb;
    for (uint8_t b = 0; b < 8; ++b) {
        const uint8_t hi = static_cast<uint8_t>(0x80u | (b << 4));
        for (uint8_t lo = 0x09u; lo <= 0x0Fu; ++lo) {
            P61[hi | lo] = &K0Cpu::Op61BitOpA;
        }
    }

    // 0x71 table
    auto &P71 = tbl_prefix71_;
    P71[0x00] = &K0Cpu::Op71Stop;
    P71[0x10] = &K0Cpu::Op71Halt;
    for (uint8_t b = 0; b < 8; ++b) {
        const uint8_t hi = static_cast<uint8_t>(b << 4);
        P71[hi | 0x01u] = &K0Cpu::Op71BitOpSaddr;
        P71[hi | 0x04u] = &K0Cpu::Op71BitOpSaddr;
        P71[hi | 0x05u] = &K0Cpu::Op71BitOpSaddr;
        P71[hi | 0x06u] = &K0Cpu::Op71BitOpSaddr;
        P71[hi | 0x07u] = &K0Cpu::Op71BitOpSaddr;

        P71[hi | 0x09u] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Au] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Bu] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Cu] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Du] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Eu] = &K0Cpu::Op71BitOpSfr;
        P71[hi | 0x0Fu] = &K0Cpu::Op71BitOpSfr;

        for (uint8_t lo = 0x01u; lo <= 0x07u; ++lo) {
            P71[0x80u | hi | lo] = &K0Cpu::Op71BitOpHl;
        }
    }
}

// =========================================================================
// Unprefixed Handlers
// =========================================================================

void K0Cpu::OpInvalid(uint8_t opcode) {
    last_invalid_opcode_ = opcode;
    invalid_insn_ = true;
}

void K0Cpu::OpPrefix31(uint8_t) {
    const uint8_t op2 = ConsumeByte();
    if (tbl_prefix31_[op2] == &K0Cpu::OpInvalid) {
        last_invalid_opcode_ = 0x3100u | op2;
        invalid_insn_ = true;
        return;
    }
    (this->*tbl_prefix31_[op2])(op2);
}

void K0Cpu::OpPrefix61(uint8_t) {
    const uint8_t op2 = ConsumeByte();
    if (tbl_prefix61_[op2] == &K0Cpu::OpInvalid) {
        last_invalid_opcode_ = 0x6100u | op2;
        invalid_insn_ = true;
        return;
    }
    (this->*tbl_prefix61_[op2])(op2);
}

void K0Cpu::OpPrefix71(uint8_t) {
    const uint8_t op2 = ConsumeByte();
    if (tbl_prefix71_[op2] == &K0Cpu::OpInvalid) {
        last_invalid_opcode_ = 0x7100u | op2;
        invalid_insn_ = true;
        return;
    }
    (this->*tbl_prefix71_[op2])(op2);
}

void K0Cpu::OpNop(uint8_t) {
    inst_cycles_ += 1;
}

void K0Cpu::OpNot1Cy(uint8_t) {
    SetCY(!GetCY());
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwAxAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    if ((addr & 1u) != 0) {
        LOG_WARN("Odd addr16p 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    const uint8_t lo = BusRead(addr);
    const uint8_t hi = BusRead(static_cast<uint16_t>(addr + 1u));
    WriteReg(REG_X, lo);
    WriteReg(REG_A, hi);
    inst_cycles_ += 5;
}

void K0Cpu::OpMovwAddr16Ax(uint8_t) {
    const uint16_t addr = ConsumeWord();
    if ((addr & 1u) != 0) {
        LOG_WARN("Odd addr16p 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    BusWrite(addr, ReadReg(REG_X));
    BusWrite(static_cast<uint16_t>(addr + 1u), ReadReg(REG_A));
    inst_cycles_ += 5;
}

void K0Cpu::OpDbnzSaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t disp = ConsumeByte();
    const uint8_t val = static_cast<uint8_t>(BusRead(addr) - 1u);
    BusWrite(addr, val);
    if (val != 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 3;
}

void K0Cpu::OpXchADe(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_DE);
    const uint8_t a = ReadReg(REG_A);
    const uint8_t m = BusRead(addr);
    WriteReg(REG_A, m);
    BusWrite(addr, a);
    inst_cycles_ += 1;
}

void K0Cpu::OpXchAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    const uint8_t a = ReadReg(REG_A);
    const uint8_t m = BusRead(addr);
    WriteReg(REG_A, m);
    BusWrite(addr, a);
    inst_cycles_ += 1;
}

void K0Cpu::OpAddAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpAdd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpAddAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpAdd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpSet1Saddr(uint8_t opcode) {
    const uint8_t bit = (opcode >> 4) & 7u;
    const uint16_t addr = ConsumeSaddr();
    const uint8_t v = BusRead(addr);
    BusWrite(addr, static_cast<uint8_t>(v | (1u << bit)));
}

void K0Cpu::OpClr1Saddr(uint8_t opcode) {
    const uint8_t bit = (opcode >> 4) & 7u;
    const uint16_t addr = ConsumeSaddr();
    const uint8_t v = BusRead(addr);
    BusWrite(addr, static_cast<uint8_t>(v & ~(1u << bit)));
}

void K0Cpu::OpCallf(uint8_t opcode) {
    const uint16_t base = static_cast<uint16_t>(0x0800u + ((opcode >> 4) << 8));
    const uint8_t lo = ConsumeByte();
    PushWord(pc_);
    pc_ = static_cast<uint16_t>(base + lo);
    inst_cycles_ += 1;
}

void K0Cpu::OpAddAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpAdd(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpAddASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpAdd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpAddAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpAdd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovwRpImm(uint8_t opcode) {
    const uint8_t rp = (opcode >> 1) & 3u;
    WriteRegPair(rp, ConsumeWord());
    inst_cycles_ += 3;
}

void K0Cpu::OpMovSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t val = ConsumeByte();
    BusWrite(addr, val);
    inst_cycles_ += 2;
}

void K0Cpu::OpMovSfrImm(uint8_t) {
    const uint16_t addr = ConsumeSfr();
    const uint8_t val = ConsumeByte();
    BusWrite(addr, val);
    inst_cycles_ += 2;
}

void K0Cpu::OpSubAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpSub(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpSubAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpSub(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpSubAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpSub(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpSubASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpSub(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpSubAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpSub(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpSet1Cy(uint8_t) {
    SetCY(true);
    inst_cycles_ += 1;
}

void K0Cpu::OpClr1Cy(uint8_t) {
    SetCY(false);
    inst_cycles_ += 1;
}

void K0Cpu::OpPushPsw(uint8_t) {
    PushByte(GetPSW());
    interrupt_delayed_ = true;
}

void K0Cpu::OpPopPsw(uint8_t) {
    SetPSW(PopByte());
    interrupt_delayed_ = true;
}

void K0Cpu::OpRorA(uint8_t) {
    const uint8_t a = ReadReg(REG_A);
    const bool bit0 = (a & 0x01u) != 0;
    const uint8_t res = static_cast<uint8_t>((a >> 1) | (bit0 ? 0x80u : 0x00u));
    SetCY(bit0);
    WriteReg(REG_A, res);
    inst_cycles_ += 1;
}

void K0Cpu::OpRorcA(uint8_t) {
    const uint8_t a = ReadReg(REG_A);
    const bool bit0 = (a & 0x01u) != 0;
    const bool old_cy = GetCY();
    const uint8_t res = static_cast<uint8_t>((a >> 1) | (old_cy ? 0x80u : 0x00u));
    SetCY(bit0);
    WriteReg(REG_A, res);
    inst_cycles_ += 1;
}

void K0Cpu::OpRolA(uint8_t) {
    const uint8_t a = ReadReg(REG_A);
    const bool bit7 = (a & 0x80u) != 0;
    const uint8_t res = static_cast<uint8_t>((a << 1) | (bit7 ? 0x01u : 0x00u));
    SetCY(bit7);
    WriteReg(REG_A, res);
    inst_cycles_ += 1;
}

void K0Cpu::OpRolcA(uint8_t) {
    const uint8_t a = ReadReg(REG_A);
    const bool bit7 = (a & 0x80u) != 0;
    const bool old_cy = GetCY();
    const uint8_t res = static_cast<uint8_t>((a << 1) | (old_cy ? 0x01u : 0x00u));
    SetCY(bit7);
    WriteReg(REG_A, res);
    inst_cycles_ += 1;
}

void K0Cpu::OpAddcAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpAddc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpAddcAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpAddc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpAddcAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpAddc(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpAddcASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpAddc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpAddcAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpAddc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpXchAReg(uint8_t opcode) {
    const uint8_t r = opcode & 7u;
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, ReadReg(r));
    WriteReg(r, a);
    inst_cycles_ += 1;
}

void K0Cpu::OpSubcAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpSubc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpSubcAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpSubc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpSubcAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpSubc(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpSubcASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpSubc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpSubcAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpSubc(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpIncReg(uint8_t opcode) {
    const uint8_t r = opcode & 7u;
    WriteReg(r, OpInc(ReadReg(r)));
    inst_cycles_ += 1;
}

void K0Cpu::OpCmpAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    OpCmp(ReadReg(REG_A), BusRead(addr));
    inst_cycles_ += 4;
}

void K0Cpu::OpCmpAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    OpCmp(ReadReg(REG_A), BusRead(addr));
    inst_cycles_ += 5;
}

void K0Cpu::OpCmpAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    OpCmp(ReadReg(REG_A), imm);
    inst_cycles_ += 2;
}

void K0Cpu::OpCmpASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    OpCmp(ReadReg(REG_A), BusRead(addr));
    inst_cycles_ += 1;
}

void K0Cpu::OpCmpAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    OpCmp(ReadReg(REG_A), BusRead(addr));
    inst_cycles_ += 2;
}

void K0Cpu::OpDecReg(uint8_t opcode) {
    const uint8_t r = opcode & 7u;
    WriteReg(r, OpDec(ReadReg(r)));
    inst_cycles_ += 1;
}

void K0Cpu::OpAndAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpAnd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpAndAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpAnd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpAndAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpAnd(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpAndASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpAnd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpAndAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpAnd(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovAReg(uint8_t opcode) {
    WriteReg(REG_A, ReadReg(opcode & 7u));
    inst_cycles_ += 1;
}

void K0Cpu::OpOrAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpOr(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpOrAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpOr(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpOrAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpOr(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpOrASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpOr(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpOrAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpOr(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovRegA(uint8_t opcode) {
    WriteReg(opcode & 7u, ReadReg(REG_A));
    inst_cycles_ += 1;
}

void K0Cpu::OpXorAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, OpXor(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 4;
}

void K0Cpu::OpXorAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, OpXor(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 5;
}

void K0Cpu::OpXorAImm(uint8_t) {
    const uint8_t imm = ConsumeByte();
    WriteReg(REG_A, OpXor(ReadReg(REG_A), imm));
    inst_cycles_ += 2;
}

void K0Cpu::OpXorASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    WriteReg(REG_A, OpXor(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 1;
}

void K0Cpu::OpXorAHl(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    WriteReg(REG_A, OpXor(ReadReg(REG_A), BusRead(addr)));
    inst_cycles_ += 2;
}

void K0Cpu::OpIncwRp(uint8_t opcode) {
    const uint8_t rp = (opcode >> 1) & 3u;
    WriteRegPair(rp, static_cast<uint16_t>(ReadRegPair(rp) + 1u));
    inst_cycles_ += 3;
}

void K0Cpu::OpIncSaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    BusWrite(addr, OpInc(BusRead(addr)));
}

void K0Cpu::OpXchASaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, BusRead(addr));
    BusWrite(addr, a);
}

void K0Cpu::OpMovADe(uint8_t) {
    WriteReg(REG_A, BusRead(ReadRegPair(RP_DE)));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovAHl(uint8_t) {
    WriteReg(REG_A, BusRead(ReadRegPair(RP_HL)));
    inst_cycles_ += 2;
}

void K0Cpu::OpAddSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpAdd(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwAxSaddrp(uint8_t) {
    const uint16_t addr = ConsumeSaddrP();
    const uint8_t lo = BusRead(addr);
    const uint8_t hi = BusRead(static_cast<uint16_t>(addr + 1u));
    WriteReg(REG_X, lo);
    WriteReg(REG_A, hi);
    inst_cycles_ += 2;
}

void K0Cpu::OpDbnzC(uint8_t) {
    const uint8_t disp = ConsumeByte();
    const uint8_t val = static_cast<uint8_t>(ReadReg(REG_C) - 1u);
    WriteReg(REG_C, val);
    if (val != 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpDbnzB(uint8_t) {
    const uint8_t disp = ConsumeByte();
    const uint8_t val = static_cast<uint8_t>(ReadReg(REG_B) - 1u);
    WriteReg(REG_B, val);
    if (val != 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpBtSaddr(uint8_t opcode) {
    const uint8_t bit = (opcode >> 4) & 7u;
    const uint16_t addr = ConsumeSaddr();
    const uint8_t disp = ConsumeByte();
    const uint8_t val = BusRead(addr);
    if ((val & (1u << bit)) != 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpBc(uint8_t) {
    const uint8_t disp = ConsumeByte();
    if (GetCY()) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpMovAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    WriteReg(REG_A, BusRead(addr));
    inst_cycles_ += 4;
}

void K0Cpu::OpReti(uint8_t) {
    pc_ = PopWord();
    SetPSW(PopByte());
    interrupt_delayed_ = true;
    inst_cycles_ += 2;
}

void K0Cpu::OpDecwRp(uint8_t opcode) {
    const uint8_t rp = (opcode >> 1) & 3u;
    WriteRegPair(rp, static_cast<uint16_t>(ReadRegPair(rp) - 1u));
    inst_cycles_ += 3;
}

void K0Cpu::OpDecSaddr(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    BusWrite(addr, OpDec(BusRead(addr)));
}

void K0Cpu::OpXchASfr(uint8_t) {
    const uint16_t addr = ConsumeSfr();
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, BusRead(addr));
    BusWrite(addr, a);
}

void K0Cpu::OpMovDeA(uint8_t) {
    BusWrite(ReadRegPair(RP_DE), ReadReg(REG_A));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovHlA(uint8_t) {
    BusWrite(ReadRegPair(RP_HL), ReadReg(REG_A));
    inst_cycles_ += 2;
}

void K0Cpu::OpSubSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpSub(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwSaddrpAx(uint8_t) {
    const uint16_t addr = ConsumeSaddrP();
    BusWrite(addr, ReadReg(REG_X));
    BusWrite(static_cast<uint16_t>(addr + 1u), ReadReg(REG_A));
    inst_cycles_ += 2;
}

void K0Cpu::OpCallAddr16(uint8_t) {
    const uint16_t target = ConsumeWord();
    PushWord(pc_);
    pc_ = target;
    inst_cycles_ += 2;
}

void K0Cpu::OpBrAddr16(uint8_t) {
    pc_ = ConsumeWord();
    inst_cycles_ += 3;
}

void K0Cpu::OpBnc(uint8_t) {
    const uint8_t disp = ConsumeByte();
    if (!GetCY()) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpMovAddr16A(uint8_t) {
    const uint16_t addr = ConsumeWord();
    BusWrite(addr, ReadReg(REG_A));
    inst_cycles_ += 4;
}

void K0Cpu::OpRetb(uint8_t) {
    pc_ = PopWord();
    SetPSW(PopByte());
    interrupt_delayed_ = true;
    inst_cycles_ += 2;
}

void K0Cpu::OpMovRegImm(uint8_t opcode) {
    WriteReg(opcode & 7u, ConsumeByte());
    inst_cycles_ += 2;
}

void K0Cpu::OpAddcSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpAddc(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwAxSfrp(uint8_t) {
    const uint16_t addr = ConsumeSfrP();
    const uint8_t lo = BusRead(addr);
    const uint8_t hi = BusRead(static_cast<uint16_t>(addr + 1u));
    WriteReg(REG_X, lo);
    WriteReg(REG_A, hi);
    inst_cycles_ += 2;
}

void K0Cpu::OpMovAHlC(uint8_t) {
    WriteReg(REG_A, BusRead(BasedHlC()));
    inst_cycles_ += 4;
}

void K0Cpu::OpMovAHlB(uint8_t) {
    WriteReg(REG_A, BusRead(BasedHlB()));
    inst_cycles_ += 4;
}

void K0Cpu::OpBz(uint8_t) {
    const uint8_t disp = ConsumeByte();
    if ((GetPSW() & PSW_Z) != 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpMovAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    WriteReg(REG_A, BusRead(addr));
    inst_cycles_ += 5;
}

void K0Cpu::OpRet(uint8_t) {
    pc_ = PopWord();
    inst_cycles_ += 3;
}

void K0Cpu::OpPopRp(uint8_t opcode) {
    WriteRegPair((opcode >> 1) & 3u, PopWord());
    inst_cycles_ += 1;
}

void K0Cpu::OpPushRp(uint8_t opcode) {
    PushWord(ReadRegPair((opcode >> 1) & 3u));
    inst_cycles_ += 1;
}

void K0Cpu::OpSubcSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpSubc(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwSfrpAx(uint8_t) {
    const uint16_t addr = ConsumeSfrP();
    BusWrite(addr, ReadReg(REG_X));
    BusWrite(static_cast<uint16_t>(addr + 1u), ReadReg(REG_A));
    inst_cycles_ += 2;
}

void K0Cpu::OpMovHlCA(uint8_t) {
    BusWrite(BasedHlC(), ReadReg(REG_A));
    inst_cycles_ += 4;
}

void K0Cpu::OpMovHlBA(uint8_t) {
    BusWrite(BasedHlB(), ReadReg(REG_A));
    inst_cycles_ += 4;
}

void K0Cpu::OpBnz(uint8_t) {
    const uint8_t disp = ConsumeByte();
    if ((GetPSW() & PSW_Z) == 0) {
        pc_ = ResolveRel(pc_, disp);
    }
    inst_cycles_ += 4;
}

void K0Cpu::OpMovHlDispA(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    BusWrite(addr, ReadReg(REG_A));
    inst_cycles_ += 5;
}

void K0Cpu::OpBrk(uint8_t) {
    const uint16_t vec = MakeWord(bus_->PeekByte(kBrkVectorAddress),
                                  bus_->PeekByte(kBrkVectorAddress + 1u));
    if (stop_on_brk || vec == 0x0000u || vec == 0xFFFFu) {
        inst_cycles_ += 5;
        brk_stopped_ = true;
        return;
    }
    const uint8_t psw = GetPSW();
    PushByte(psw);
    PushWord(pc_);
    SetPSW(static_cast<uint8_t>(psw & ~PSW_IE));
    ++inst_cycles_;
    const uint8_t lo = bus_->ReadCpu(kBrkVectorAddress);
    ++inst_cycles_;
    const uint8_t hi = bus_->ReadCpu(kBrkVectorAddress + 1u);
    pc_ = MakeWord(lo, hi);
}

void K0Cpu::OpMovwAxRp(uint8_t opcode) {
    WriteRegPair(RP_AX, ReadRegPair((opcode >> 1) & 3u));
    inst_cycles_ += 3;
}

void K0Cpu::OpCmpSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    OpCmp(BusRead(addr), imm);
    inst_cycles_ += 1;
}

void K0Cpu::OpAddwAxImm(uint8_t) {
    const uint16_t imm = ConsumeWord();
    WriteRegPair(RP_AX, OpAddw(ReadRegPair(RP_AX), imm));
    inst_cycles_ += 3;
}

void K0Cpu::OpXchAAddr16(uint8_t) {
    const uint16_t addr = ConsumeWord();
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, BusRead(addr));
    BusWrite(addr, a);
    inst_cycles_ += 3;
}

void K0Cpu::OpCallt(uint8_t opcode) {
    const uint16_t vec_addr = static_cast<uint16_t>(kCalltTableStart + (opcode & 0x3Eu));
    ++inst_cycles_;
    const uint8_t lo = bus_->ReadCpu(vec_addr);
    ++inst_cycles_;
    const uint8_t hi = bus_->ReadCpu(static_cast<uint16_t>(vec_addr + 1u));
    PushWord(pc_);
    pc_ = MakeWord(lo, hi);
    inst_cycles_ += 1;
}

void K0Cpu::OpMovwRpAx(uint8_t opcode) {
    WriteRegPair((opcode >> 1) & 3u, ReadRegPair(RP_AX));
    inst_cycles_ += 3;
}

void K0Cpu::OpAndSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpAnd(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpSubwAxImm(uint8_t) {
    const uint16_t imm = ConsumeWord();
    WriteRegPair(RP_AX, OpSubw(ReadRegPair(RP_AX), imm));
    inst_cycles_ += 3;
}

void K0Cpu::OpXchAHlDisp(uint8_t) {
    const uint16_t addr = BasedHlImm(ConsumeByte());
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, BusRead(addr));
    BusWrite(addr, a);
    inst_cycles_ += 4;
}

void K0Cpu::OpXchwAxRp(uint8_t opcode) {
    const uint8_t rp = (opcode >> 1) & 3u;
    const uint16_t ax = ReadRegPair(RP_AX);
    WriteRegPair(RP_AX, ReadRegPair(rp));
    WriteRegPair(rp, ax);
    inst_cycles_ += 3;
}

void K0Cpu::OpOrSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpOr(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpCmpwAxImm(uint8_t) {
    const uint16_t imm = ConsumeWord();
    (void)OpSubw(ReadRegPair(RP_AX), imm);
    inst_cycles_ += 3;
}

void K0Cpu::OpMovwSaddrpImm(uint8_t) {
    const uint16_t addr = ConsumeSaddrP();
    const uint8_t lo = ConsumeByte();
    BusWrite(addr, lo);
    const uint8_t hi = ConsumeByte();
    BusWrite(static_cast<uint16_t>(addr + 1u), hi);
    inst_cycles_ += 2;
}

void K0Cpu::OpMovASaddr(uint8_t) {
    WriteReg(REG_A, BusRead(ConsumeSaddr()));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovSaddrA(uint8_t) {
    BusWrite(ConsumeSaddr(), ReadReg(REG_A));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovASfr(uint8_t) {
    WriteReg(REG_A, BusRead(ConsumeSfr()));
    inst_cycles_ += 1;
}

void K0Cpu::OpMovSfrA(uint8_t) {
    BusWrite(ConsumeSfr(), ReadReg(REG_A));
    inst_cycles_ += 1;
}

void K0Cpu::OpXorSaddrImm(uint8_t) {
    const uint16_t addr = ConsumeSaddr();
    const uint8_t imm = ConsumeByte();
    BusWrite(addr, OpXor(BusRead(addr), imm));
    inst_cycles_ += 1;
}

void K0Cpu::OpBrRel(uint8_t) {
    const uint8_t disp = ConsumeByte();
    pc_ = ResolveRel(pc_, disp);
    inst_cycles_ += 4;
}

void K0Cpu::OpMovwSfrpImm(uint8_t) {
    const uint16_t addr = ConsumeSfrP();
    const uint8_t lo = ConsumeByte();
    BusWrite(addr, lo);
    const uint8_t hi = ConsumeByte();
    BusWrite(static_cast<uint16_t>(addr + 1u), hi);
    inst_cycles_ += 2;
}

// =========================================================================
// 0x31 Prefixed Handlers
// =========================================================================

void K0Cpu::Op31AluHlIdx(uint8_t op2) {
    const uint8_t alu = (op2 >> 4) & 7u;
    const uint16_t addr = (op2 & 1u) ? BasedHlB() : BasedHlC();
    const uint8_t a = ReadReg(REG_A);
    const uint8_t b = BusRead(addr);
    switch (alu) {
    case 0: WriteReg(REG_A, OpAdd(a, b)); break;
    case 1: WriteReg(REG_A, OpSub(a, b)); break;
    case 2: WriteReg(REG_A, OpAddc(a, b)); break;
    case 3: WriteReg(REG_A, OpSubc(a, b)); break;
    case 4: OpCmp(a, b); break;
    case 5: WriteReg(REG_A, OpAnd(a, b)); break;
    case 6: WriteReg(REG_A, OpOr(a, b)); break;
    case 7: WriteReg(REG_A, OpXor(a, b)); break;
    }
    inst_cycles_ += 5;
}

void K0Cpu::Op31Rol4(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    if ((addr & 0xFF00u) == 0xFF00u) {
        LOG_WARN("ROL4 [HL] targeting SFR 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    const uint8_t a = ReadReg(REG_A);
    const uint8_t m = BusRead(addr);
    const uint8_t new_a = static_cast<uint8_t>((a & 0xF0u) | (m >> 4));
    const uint8_t new_m = static_cast<uint8_t>(((m & 0x0Fu) << 4) | (a & 0x0Fu));
    WriteReg(REG_A, new_a);
    BusWrite(addr, new_m);
    inst_cycles_ += 6;
}

void K0Cpu::Op31Ror4(uint8_t) {
    const uint16_t addr = ReadRegPair(RP_HL);
    if ((addr & 0xFF00u) == 0xFF00u) {
        LOG_WARN("ROR4 [HL] targeting SFR 0x%04X at PC=0x%04X", addr, current_insn_pc_);
    }
    const uint8_t a = ReadReg(REG_A);
    const uint8_t m = BusRead(addr);
    const uint8_t new_a = static_cast<uint8_t>((a & 0xF0u) | (m & 0x0Fu));
    const uint8_t new_m = static_cast<uint8_t>(((a & 0x0Fu) << 4) | (m >> 4));
    WriteReg(REG_A, new_a);
    BusWrite(addr, new_m);
    inst_cycles_ += 6;
}

void K0Cpu::Op31Divuw(uint8_t) {
    const uint16_t ax = ReadRegPair(RP_AX);
    const uint8_t c = ReadReg(REG_C);
    uint16_t q = 0xFFFFu;
    uint8_t r = static_cast<uint8_t>(ax & 0xFFu);
    if (c != 0) {
        q = static_cast<uint16_t>(ax / c);
        r = static_cast<uint8_t>(ax % c);
    }
    WriteRegPair(RP_AX, q);
    WriteReg(REG_C, r);
    inst_cycles_ += 23;
}

void K0Cpu::Op31Mulu(uint8_t) {
    const uint16_t a = ReadReg(REG_A);
    const uint16_t x = ReadReg(REG_X);
    WriteRegPair(RP_AX, static_cast<uint16_t>(a * x));
    inst_cycles_ += 14;
}

void K0Cpu::Op31XchHlIdx(uint8_t op2) {
    const uint16_t addr = (op2 & 1u) ? BasedHlB() : BasedHlC();
    const uint8_t m = BusRead(addr);
    const uint8_t a = ReadReg(REG_A);
    WriteReg(REG_A, m);
    BusWrite(addr, a);
    inst_cycles_ += 4;
}

void K0Cpu::Op31BrAx(uint8_t) {
    pc_ = ReadRegPair(RP_AX);
    inst_cycles_ += 6;
}

void K0Cpu::Op31BitBranchSaddr(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint16_t addr = ConsumeSaddr();
    const uint8_t disp = ConsumeByte();
    const uint8_t val = BusRead(addr);
    const bool set = (val & (1u << bit)) != 0;

    if (kind == 0x01u) {  // BTCLR saddr.bit, $rel
        if (set) {
            BusWrite(addr, static_cast<uint8_t>(val & ~(1u << bit)));
            pc_ = ResolveRel(pc_, disp);
        } else {
            // Preserve exact 10/12 RMW bus timing without dirtying volatile SFRs
            inst_cycles_ += bus_->IsHighSpeed(addr) ? 1u : 2u;
        }
        inst_cycles_ += 4;
    } else {  // BF saddr.bit, $rel (0x03)
        if (!set) {
            pc_ = ResolveRel(pc_, disp);
        }
        inst_cycles_ += 5;
    }
}

void K0Cpu::Op31BitBranchSfr(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint16_t addr = ConsumeSfr();
    const uint8_t disp = ConsumeByte();
    const uint8_t val = BusRead(addr);
    const bool set = (val & (1u << bit)) != 0;

    if (kind == 0x05u) {  // BTCLR sfr.bit, $rel
        if (set) {
            BusWrite(addr, static_cast<uint8_t>(val & ~(1u << bit)));
            pc_ = ResolveRel(pc_, disp);
        } else {
            inst_cycles_ += bus_->IsHighSpeed(addr) ? 1u : 2u;
        }
        inst_cycles_ += 4;
    } else if (kind == 0x06u) {  // BT sfr.bit, $rel
        if (set) {
            pc_ = ResolveRel(pc_, disp);
        }
        inst_cycles_ += 5;
    } else {  // BF sfr.bit, $rel (0x07)
        if (!set) {
            pc_ = ResolveRel(pc_, disp);
        }
        inst_cycles_ += 5;
    }
}

void K0Cpu::Op31BitBranchA(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint8_t disp = ConsumeByte();
    const uint8_t val = ReadReg(REG_A);
    const bool set = (val & (1u << bit)) != 0;

    if (kind == 0x0Du) {  // BTCLR A.bit, $rel
        if (set) {
            WriteReg(REG_A, static_cast<uint8_t>(val & ~(1u << bit)));
            pc_ = ResolveRel(pc_, disp);
        }
    } else if (kind == 0x0Eu) {  // BT A.bit, $rel
        if (set) {
            pc_ = ResolveRel(pc_, disp);
        }
    } else {  // BF A.bit, $rel (0x0F)
        if (!set) {
            pc_ = ResolveRel(pc_, disp);
        }
    }
    inst_cycles_ += 5;
}

void K0Cpu::Op31BitBranchHl(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint8_t disp = ConsumeByte();
    const uint16_t addr = ReadRegPair(RP_HL);
    const uint8_t val = BusRead(addr);
    const bool set = (val & (1u << bit)) != 0;

    if (kind == 0x05u) {  // BTCLR [HL].bit, $rel
        if (set) {
            BusWrite(addr, static_cast<uint8_t>(val & ~(1u << bit)));
            pc_ = ResolveRel(pc_, disp);
        } else {
            inst_cycles_ += bus_->IsHighSpeed(addr) ? 1u : 2u;
        }
        inst_cycles_ += 5;
    } else if (kind == 0x06u) {  // BT [HL].bit, $rel
        if (set) {
            pc_ = ResolveRel(pc_, disp);
        }
        inst_cycles_ += 6;
    } else {  // BF [HL].bit, $rel (0x07)
        if (!set) {
            pc_ = ResolveRel(pc_, disp);
        }
        inst_cycles_ += 6;
    }
}

// =========================================================================
// 0x61 Prefixed Handlers
// =========================================================================

void K0Cpu::Op61AluReg(uint8_t op2) {
    const uint8_t alu = (op2 >> 4) & 7u;
    const uint8_t reg = op2 & 7u;
    const bool a_is_dst = (op2 & 0x08u) != 0;
    const uint8_t lhs = a_is_dst ? ReadReg(REG_A) : ReadReg(reg);
    const uint8_t rhs = a_is_dst ? ReadReg(reg) : ReadReg(REG_A);
    const uint8_t dst = a_is_dst ? REG_A : reg;

    switch (alu) {
    case 0: WriteReg(dst, OpAdd(lhs, rhs)); break;
    case 1: WriteReg(dst, OpSub(lhs, rhs)); break;
    case 2: WriteReg(dst, OpAddc(lhs, rhs)); break;
    case 3: WriteReg(dst, OpSubc(lhs, rhs)); break;
    case 4: OpCmp(lhs, rhs); break;
    case 5: WriteReg(dst, OpAnd(lhs, rhs)); break;
    case 6: WriteReg(dst, OpOr(lhs, rhs)); break;
    case 7: WriteReg(dst, OpXor(lhs, rhs)); break;
    }
    inst_cycles_ += 2;
}

void K0Cpu::Op61Adjba(uint8_t) {
    uint8_t psw = GetPSW();
    bool cy = (psw & PSW_CY) != 0;
    bool ac = (psw & PSW_AC) != 0;
    uint8_t a = ReadReg(REG_A);
    const uint8_t lo = a & 0x0Fu;
    const uint8_t hi = a >> 4;

    if (!ac) {
        if (lo <= 9u) {
            if (hi <= 9u && !cy) {
                cy = false;
                ac = false;
            } else {
                a = static_cast<uint8_t>(a + 0x60u);
                cy = true;
                ac = false;
            }
        } else {
            if (hi < 9u && !cy) {
                a = static_cast<uint8_t>(a + 0x06u);
                cy = false;
                ac = true;
            } else {
                a = static_cast<uint8_t>(a + 0x66u);
                cy = true;
                ac = true;
            }
        }
    } else {
        if (hi <= 9u && !cy) {
            a = static_cast<uint8_t>(a + 0x06u);
            cy = false;
            ac = false;
        } else {
            a = static_cast<uint8_t>(a + 0x66u);
            cy = true;
            ac = false;
        }
    }

    psw &= static_cast<uint8_t>(~(PSW_AC | PSW_CY | PSW_Z));
    if (cy) psw |= PSW_CY;
    if (ac) psw |= PSW_AC;
    if (a == 0) psw |= PSW_Z;
    SetPSW(psw);
    WriteReg(REG_A, a);
    inst_cycles_ += 2;
}

void K0Cpu::Op61Adjbs(uint8_t) {
    uint8_t psw = GetPSW();
    bool cy = (psw & PSW_CY) != 0;
    bool ac = (psw & PSW_AC) != 0;
    uint8_t a = ReadReg(REG_A);

    if (!ac) {
        if (!cy) {
            cy = false;
            ac = false;
        } else {
            a = static_cast<uint8_t>(a - 0x60u);
            cy = true;
            ac = false;
        }
    } else {
        if (!cy) {
            a = static_cast<uint8_t>(a - 0x06u);
            cy = false;
            ac = false;
        } else {
            a = static_cast<uint8_t>(a - 0x66u);
            cy = true;
            ac = false;
        }
    }

    psw &= static_cast<uint8_t>(~(PSW_AC | PSW_CY | PSW_Z));
    if (cy) psw |= PSW_CY;
    if (ac) psw |= PSW_AC;
    if (a == 0) psw |= PSW_Z;
    SetPSW(psw);
    WriteReg(REG_A, a);
    inst_cycles_ += 2;
}

void K0Cpu::Op61SelRb(uint8_t op2) {
    const uint8_t rb = static_cast<uint8_t>(((op2 >> 4) & 0x02u) | ((op2 >> 3) & 0x01u));
    SetRB(rb);
    inst_cycles_ += 2;
}

void K0Cpu::Op61BitOpA(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    uint8_t a = ReadReg(REG_A);
    const bool abit = (a & (1u << bit)) != 0;
    const bool cy = GetCY();

    switch (kind) {
    case 0x09u:  // MOV1 A.bit, CY
        a = cy ? static_cast<uint8_t>(a | (1u << bit))
               : static_cast<uint8_t>(a & ~(1u << bit));
        WriteReg(REG_A, a);
        break;
    case 0x0Au:  // SET1 A.bit
        WriteReg(REG_A, static_cast<uint8_t>(a | (1u << bit)));
        break;
    case 0x0Bu:  // CLR1 A.bit
        WriteReg(REG_A, static_cast<uint8_t>(a & ~(1u << bit)));
        break;
    case 0x0Cu:  // MOV1 CY, A.bit
        SetCY(abit);
        break;
    case 0x0Du:  // AND1 CY, A.bit
        SetCY(cy && abit);
        break;
    case 0x0Eu:  // OR1 CY, A.bit
        SetCY(cy || abit);
        break;
    case 0x0Fu:  // XOR1 CY, A.bit
        SetCY(cy != abit);
        break;
    }
    inst_cycles_ += 2;
}

// =========================================================================
// 0x71 Prefixed Handlers
// =========================================================================

void K0Cpu::Op71Stop(uint8_t) {
    inst_cycles_ += 4;  // 2 fetch + 4 = 6 clocks per 78K0KX2.pdf p.768
    stop_entered_ = true;
    if (clock_) {
        clock_->OnEnterStop();
    }
}

void K0Cpu::Op71Halt(uint8_t) {
    inst_cycles_ += 4;  // 2 fetch + 4 = 6 clocks per 78K0KX2.pdf p.768
    halt_entered_ = true;
}

void K0Cpu::Op71BitOpSaddr(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint16_t addr = ConsumeSaddr();
    const uint8_t m = BusRead(addr);
    const bool mbit = (m & (1u << bit)) != 0;
    const bool cy = GetCY();

    if (kind == 0x01u) {  // MOV1 saddr.bit, CY
        const uint8_t next = cy ? static_cast<uint8_t>(m | (1u << bit))
                                : static_cast<uint8_t>(m & ~(1u << bit));
        BusWrite(addr, next);
        inst_cycles_ += 1;
        return;
    }
    switch (kind) {
    case 0x04u: SetCY(mbit); break;        // MOV1 CY, saddr.bit
    case 0x05u: SetCY(cy && mbit); break;  // AND1 CY, saddr.bit
    case 0x06u: SetCY(cy || mbit); break;  // OR1 CY, saddr.bit
    case 0x07u: SetCY(cy != mbit); break;  // XOR1 CY, saddr.bit
    }
    inst_cycles_ += 2;
}

void K0Cpu::Op71BitOpSfr(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint16_t addr = ConsumeSfr();
    const uint8_t m = BusRead(addr);
    const bool mbit = (m & (1u << bit)) != 0;
    const bool cy = GetCY();

    switch (kind) {
    case 0x09u:  // MOV1 sfr.bit, CY
        BusWrite(addr, cy ? static_cast<uint8_t>(m | (1u << bit))
                          : static_cast<uint8_t>(m & ~(1u << bit)));
        inst_cycles_ += 1;
        return;
    case 0x0Au:  // SET1 sfr.bit
        BusWrite(addr, static_cast<uint8_t>(m | (1u << bit)));
        inst_cycles_ += 1;
        return;
    case 0x0Bu:  // CLR1 sfr.bit
        BusWrite(addr, static_cast<uint8_t>(m & ~(1u << bit)));
        inst_cycles_ += 1;
        return;
    case 0x0Cu: SetCY(mbit); break;        // MOV1 CY, sfr.bit
    case 0x0Du: SetCY(cy && mbit); break;  // AND1 CY, sfr.bit
    case 0x0Eu: SetCY(cy || mbit); break;  // OR1 CY, sfr.bit
    case 0x0Fu: SetCY(cy != mbit); break;  // XOR1 CY, sfr.bit
    }
    inst_cycles_ += 2;
}

void K0Cpu::Op71BitOpHl(uint8_t op2) {
    const uint8_t bit = (op2 >> 4) & 7u;
    const uint8_t kind = op2 & 0x0Fu;
    const uint16_t addr = ReadRegPair(RP_HL);
    const uint8_t m = BusRead(addr);
    const bool mbit = (m & (1u << bit)) != 0;
    const bool cy = GetCY();

    switch (kind) {
    case 0x01u:  // MOV1 [HL].bit, CY
        BusWrite(addr, cy ? static_cast<uint8_t>(m | (1u << bit))
                          : static_cast<uint8_t>(m & ~(1u << bit)));
        inst_cycles_ += 2;
        return;
    case 0x02u:  // SET1 [HL].bit
        BusWrite(addr, static_cast<uint8_t>(m | (1u << bit)));
        inst_cycles_ += 2;
        return;
    case 0x03u:  // CLR1 [HL].bit
        BusWrite(addr, static_cast<uint8_t>(m & ~(1u << bit)));
        inst_cycles_ += 2;
        return;
    case 0x04u: SetCY(mbit); break;        // MOV1 CY, [HL].bit
    case 0x05u: SetCY(cy && mbit); break;  // AND1 CY, [HL].bit
    case 0x06u: SetCY(cy || mbit); break;  // OR1 CY, [HL].bit
    case 0x07u: SetCY(cy != mbit); break;  // XOR1 CY, [HL].bit
    }
    inst_cycles_ += 3;
}

}  // namespace k0
