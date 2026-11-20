#pragma once

#include <array>
#include <cstdint>
#include <unordered_set>

#include "memory.h"

namespace k0 {

inline constexpr uint16_t kResetVectorAddress = 0x0000u;
inline constexpr uint16_t kBrkVectorAddress   = 0x003Eu;
inline constexpr uint16_t kCalltTableStart    = 0x0040u;
inline constexpr uint16_t kRegBank0Base       = 0xFEF8u;
inline constexpr uint16_t kSpAddress          = 0xFF1Cu;
inline constexpr uint16_t kPswAddress         = 0xFF1Eu;

enum Reg8 : uint8_t {
    REG_X = 0,
    REG_A = 1,
    REG_C = 2,
    REG_B = 3,
    REG_E = 4,
    REG_D = 5,
    REG_L = 6,
    REG_H = 7,
};

enum Reg16 : uint8_t {
    RP_AX = 0,
    RP_BC = 1,
    RP_DE = 2,
    RP_HL = 3,
};

enum PswFlag : uint8_t {
    PSW_CY   = 0x01u,
    PSW_ISP  = 0x02u,
    PSW_RBS0 = 0x08u,
    PSW_AC   = 0x10u,
    PSW_RBS1 = 0x20u,
    PSW_Z    = 0x40u,
    PSW_IE   = 0x80u,
    PSW_MASK = 0xFBu,  // Bit 2 of PSW is always 0
};

enum class RunState : uint8_t {
    Running = 0,
    Halted  = 1,
    Stopped = 2,
};

enum class StopReason : uint8_t {
    None = 0,
    Breakpoint,
    Watchpoint,
    BreakInsn,
    Halt,
    Stop,
    UnmappedMemory,
    InvalidInsn,
    WdtReset,
};

struct StopInfo {
    StopReason reason = StopReason::None;
    uint16_t pc = 0;
    uint32_t detail = 0;
    bool is_write = false;
};

struct PendingInterrupt {
    bool pending = false;
    uint8_t source_index = 0;
    bool high_priority = false;
    uint16_t vector_address = 0;
};

class InterruptControllerBase : public PeripheralDevice {
public:
    virtual PendingInterrupt EvaluatePending() const = 0;
    virtual bool HasUnmaskedPending() const = 0;
    virtual void Acknowledge(uint8_t source_index) = 0;
};

class K0ClockSource {
public:
    virtual ~K0ClockSource() = default;
    virtual void OnEnterStop() {}
    virtual void OnExitStop() {}
    virtual void ComputeSubClocks(uint32_t cpu_cycles,
                                  bool in_halt,
                                  bool in_stop,
                                  uint32_t *prs_cycles_out,
                                  uint32_t *sub_cycles_out,
                                  uint32_t *rl_cycles_out) = 0;
};

class K0Cpu {
public:
    K0Cpu();

    void AttachBus(K0Bus *bus);
    void AttachIntc(InterruptControllerBase *intc) { intc_ = intc; }
    void AttachClock(K0ClockSource *clock) { clock_ = clock; }

    void Reset();
    void ResetTo(uint16_t entry_pc);

    // Execute one instruction (or advance one standby tick when HALT/STOP).
    StopInfo Step(bool ignore_bpt_at_pc = false);

    // Register & status access (uses side-effect-free bus access for GPRs).
    uint16_t GetPC() const { return pc_; }
    void SetPC(uint16_t pc) { pc_ = pc; }

    uint16_t GetSP() const { return sp_; }
    void SetSP(uint16_t sp) { sp_ = sp; }

    uint8_t GetPSW() const { return psw_ & PSW_MASK; }
    void SetPSW(uint8_t psw) { psw_ = psw & PSW_MASK; }

    uint8_t GetRB() const {
        return static_cast<uint8_t>(((psw_ & PSW_RBS1) >> 4) | ((psw_ & PSW_RBS0) >> 3));
    }
    void SetRB(uint8_t rb) {
        const uint8_t b = rb & 3u;
        psw_ = static_cast<uint8_t>((psw_ & ~(PSW_RBS0 | PSW_RBS1)) |
                                    ((b & 1u) << 3) | ((b & 2u) << 4));
    }

    bool GetCY() const { return (psw_ & PSW_CY) != 0; }
    void SetCY(bool cy) {
        if (cy) psw_ |= PSW_CY;
        else psw_ &= ~PSW_CY;
    }

    uint16_t AddressOfReg(uint8_t reg, uint8_t bank) const {
        return static_cast<uint16_t>(kRegBank0Base - static_cast<uint16_t>(bank & 3u) * 8u + (reg & 7u));
    }
    uint8_t ReadReg(uint8_t reg) const { return ReadRegBank(reg, GetRB()); }
    void WriteReg(uint8_t reg, uint8_t val) { WriteRegBank(reg, GetRB(), val); }
    uint16_t ReadRegPair(uint8_t rp) const { return ReadRegPairBank(rp, GetRB()); }
    void WriteRegPair(uint8_t rp, uint16_t val) { WriteRegPairBank(rp, GetRB(), val); }

    uint8_t ReadRegBank(uint8_t reg, uint8_t bank) const;
    void WriteRegBank(uint8_t reg, uint8_t bank, uint8_t val);
    uint16_t ReadRegPairBank(uint8_t rp, uint8_t bank) const;
    void WriteRegPairBank(uint8_t rp, uint8_t bank, uint16_t val);

    // Breakpoint management.
    void AddBreakpoint(uint16_t addr);
    void RemoveBreakpoint(uint16_t addr);
    void ClearBreakpoints();
    bool HasBreakpoint(uint16_t addr) const;

    // Standby & runtime statistics.
    RunState GetRunState() const { return run_state_; }
    void SetRunState(RunState state) { run_state_ = state; }
    uint64_t TotalCycles() const { return total_cycles_; }
    uint32_t LastInsnCycles() const { return inst_cycles_; }
    uint64_t InstructionCount() const { return insn_count_; }
    bool IsInterruptDelayed() const { return interrupt_delayed_; }
    void RequestWdtReset() { wdt_reset_pending_ = true; }

    // Execution stop flags.
    bool stop_on_brk = false;   // if false, BRK vectors through 0x003E when non-0x0000/0xFFFF
    bool stop_on_halt = false;  // if true, HALT breaks to debugger instead of idling
    bool stop_on_stop = false;  // if true, STOP breaks to debugger instead of idling

private:
    class StatusSfrDevice final : public PeripheralDevice {
    public:
        explicit StatusSfrDevice(K0Cpu *cpu) : cpu_(cpu) {}
        uint8_t Read(uint16_t addr) override;
        void Write(uint16_t addr, uint8_t value) override;
        uint8_t Peek(uint16_t addr) const override;
        void Poke(uint16_t addr, uint8_t value) override;
    private:
        K0Cpu *cpu_;
    };

    using OpcodeHandler = void (K0Cpu::*)(uint8_t);

    void InitTables();
    void CheckInterruptHold(uint16_t addr);
    void TickBus(uint32_t cycles, bool in_halt, bool in_stop);
    void DispatchInterruptIfReady();

    uint8_t ConsumeByte();
    uint16_t ConsumeWord();
    uint16_t ConsumeSfr();
    uint16_t ConsumeSfrP();
    uint16_t ConsumeSaddr();
    uint16_t ConsumeSaddrP();

    uint8_t BusRead(uint16_t addr);
    void BusWrite(uint16_t addr, uint8_t value);
    void PushByte(uint8_t value);
    uint8_t PopByte();
    void PushWord(uint16_t value);
    uint16_t PopWord();

    uint16_t BasedHlImm(uint8_t imm) const;
    uint16_t BasedHlB() const;
    uint16_t BasedHlC() const;
    static uint16_t ResolveRel(uint16_t pc, uint8_t disp);

    void UpdatePswZ(uint8_t value);
    uint8_t OpAdd(uint8_t a, uint8_t b);
    uint8_t OpAddc(uint8_t a, uint8_t b);
    uint8_t OpSub(uint8_t a, uint8_t b);
    uint8_t OpSubc(uint8_t a, uint8_t b);
    void OpCmp(uint8_t a, uint8_t b);
    uint8_t OpAnd(uint8_t a, uint8_t b);
    uint8_t OpOr(uint8_t a, uint8_t b);
    uint8_t OpXor(uint8_t a, uint8_t b);
    uint8_t OpInc(uint8_t val);
    uint8_t OpDec(uint8_t val);
    uint16_t OpAddw(uint16_t a, uint16_t b);
    uint16_t OpSubw(uint16_t a, uint16_t b);

    // Opcode handlers.
    void OpInvalid(uint8_t opcode);
    void OpPrefix31(uint8_t opcode);
    void OpPrefix61(uint8_t opcode);
    void OpPrefix71(uint8_t opcode);

    // Unprefixed
    void OpNop(uint8_t opcode);
    void OpNot1Cy(uint8_t opcode);
    void OpMovwAxAddr16(uint8_t opcode);
    void OpMovwAddr16Ax(uint8_t opcode);
    void OpDbnzSaddr(uint8_t opcode);
    void OpXchADe(uint8_t opcode);
    void OpXchAHl(uint8_t opcode);
    void OpAddAAddr16(uint8_t opcode);
    void OpAddAHlDisp(uint8_t opcode);
    void OpSet1Saddr(uint8_t opcode);
    void OpClr1Saddr(uint8_t opcode);
    void OpCallf(uint8_t opcode);
    void OpAddAImm(uint8_t opcode);
    void OpAddASaddr(uint8_t opcode);
    void OpAddAHl(uint8_t opcode);
    void OpMovwRpImm(uint8_t opcode);
    void OpMovSaddrImm(uint8_t opcode);
    void OpMovSfrImm(uint8_t opcode);
    void OpSubAAddr16(uint8_t opcode);
    void OpSubAHlDisp(uint8_t opcode);
    void OpSubAImm(uint8_t opcode);
    void OpSubASaddr(uint8_t opcode);
    void OpSubAHl(uint8_t opcode);
    void OpSet1Cy(uint8_t opcode);
    void OpClr1Cy(uint8_t opcode);
    void OpPushPsw(uint8_t opcode);
    void OpPopPsw(uint8_t opcode);
    void OpRorA(uint8_t opcode);
    void OpRorcA(uint8_t opcode);
    void OpRolA(uint8_t opcode);
    void OpRolcA(uint8_t opcode);
    void OpAddcAAddr16(uint8_t opcode);
    void OpAddcAHlDisp(uint8_t opcode);
    void OpAddcAImm(uint8_t opcode);
    void OpAddcASaddr(uint8_t opcode);
    void OpAddcAHl(uint8_t opcode);
    void OpXchAReg(uint8_t opcode);
    void OpSubcAAddr16(uint8_t opcode);
    void OpSubcAHlDisp(uint8_t opcode);
    void OpSubcAImm(uint8_t opcode);
    void OpSubcASaddr(uint8_t opcode);
    void OpSubcAHl(uint8_t opcode);
    void OpIncReg(uint8_t opcode);
    void OpCmpAAddr16(uint8_t opcode);
    void OpCmpAHlDisp(uint8_t opcode);
    void OpCmpAImm(uint8_t opcode);
    void OpCmpASaddr(uint8_t opcode);
    void OpCmpAHl(uint8_t opcode);
    void OpDecReg(uint8_t opcode);
    void OpAndAAddr16(uint8_t opcode);
    void OpAndAHlDisp(uint8_t opcode);
    void OpAndAImm(uint8_t opcode);
    void OpAndASaddr(uint8_t opcode);
    void OpAndAHl(uint8_t opcode);
    void OpMovAReg(uint8_t opcode);
    void OpOrAAddr16(uint8_t opcode);
    void OpOrAHlDisp(uint8_t opcode);
    void OpOrAImm(uint8_t opcode);
    void OpOrASaddr(uint8_t opcode);
    void OpOrAHl(uint8_t opcode);
    void OpMovRegA(uint8_t opcode);
    void OpXorAAddr16(uint8_t opcode);
    void OpXorAHlDisp(uint8_t opcode);
    void OpXorAImm(uint8_t opcode);
    void OpXorASaddr(uint8_t opcode);
    void OpXorAHl(uint8_t opcode);
    void OpIncwRp(uint8_t opcode);
    void OpIncSaddr(uint8_t opcode);
    void OpXchASaddr(uint8_t opcode);
    void OpMovADe(uint8_t opcode);
    void OpMovAHl(uint8_t opcode);
    void OpAddSaddrImm(uint8_t opcode);
    void OpMovwAxSaddrp(uint8_t opcode);
    void OpDbnzC(uint8_t opcode);
    void OpDbnzB(uint8_t opcode);
    void OpBtSaddr(uint8_t opcode);
    void OpBc(uint8_t opcode);
    void OpMovAAddr16(uint8_t opcode);
    void OpReti(uint8_t opcode);
    void OpDecwRp(uint8_t opcode);
    void OpDecSaddr(uint8_t opcode);
    void OpXchASfr(uint8_t opcode);
    void OpMovDeA(uint8_t opcode);
    void OpMovHlA(uint8_t opcode);
    void OpSubSaddrImm(uint8_t opcode);
    void OpMovwSaddrpAx(uint8_t opcode);
    void OpCallAddr16(uint8_t opcode);
    void OpBrAddr16(uint8_t opcode);
    void OpBnc(uint8_t opcode);
    void OpMovAddr16A(uint8_t opcode);
    void OpRetb(uint8_t opcode);
    void OpMovRegImm(uint8_t opcode);
    void OpAddcSaddrImm(uint8_t opcode);
    void OpMovwAxSfrp(uint8_t opcode);
    void OpMovAHlC(uint8_t opcode);
    void OpMovAHlB(uint8_t opcode);
    void OpBz(uint8_t opcode);
    void OpMovAHlDisp(uint8_t opcode);
    void OpRet(uint8_t opcode);
    void OpPopRp(uint8_t opcode);
    void OpPushRp(uint8_t opcode);
    void OpSubcSaddrImm(uint8_t opcode);
    void OpMovwSfrpAx(uint8_t opcode);
    void OpMovHlCA(uint8_t opcode);
    void OpMovHlBA(uint8_t opcode);
    void OpBnz(uint8_t opcode);
    void OpMovHlDispA(uint8_t opcode);
    void OpBrk(uint8_t opcode);
    void OpMovwAxRp(uint8_t opcode);
    void OpCmpSaddrImm(uint8_t opcode);
    void OpAddwAxImm(uint8_t opcode);
    void OpXchAAddr16(uint8_t opcode);
    void OpCallt(uint8_t opcode);
    void OpMovwRpAx(uint8_t opcode);
    void OpAndSaddrImm(uint8_t opcode);
    void OpSubwAxImm(uint8_t opcode);
    void OpXchAHlDisp(uint8_t opcode);
    void OpXchwAxRp(uint8_t opcode);
    void OpOrSaddrImm(uint8_t opcode);
    void OpCmpwAxImm(uint8_t opcode);
    void OpMovwSaddrpImm(uint8_t opcode);
    void OpMovASaddr(uint8_t opcode);
    void OpMovSaddrA(uint8_t opcode);
    void OpMovASfr(uint8_t opcode);
    void OpMovSfrA(uint8_t opcode);
    void OpXorSaddrImm(uint8_t opcode);
    void OpBrRel(uint8_t opcode);
    void OpMovwSfrpImm(uint8_t opcode);

    // 0x31 prefixed
    void Op31AluHlIdx(uint8_t op2);
    void Op31Rol4(uint8_t op2);
    void Op31Ror4(uint8_t op2);
    void Op31Divuw(uint8_t op2);
    void Op31Mulu(uint8_t op2);
    void Op31XchHlIdx(uint8_t op2);
    void Op31BrAx(uint8_t op2);
    void Op31BitBranchSaddr(uint8_t op2);
    void Op31BitBranchSfr(uint8_t op2);
    void Op31BitBranchA(uint8_t op2);
    void Op31BitBranchHl(uint8_t op2);

    // 0x61 prefixed
    void Op61AluReg(uint8_t op2);
    void Op61Adjba(uint8_t op2);
    void Op61Adjbs(uint8_t op2);
    void Op61SelRb(uint8_t op2);
    void Op61BitOpA(uint8_t op2);

    // 0x71 prefixed
    void Op71Stop(uint8_t op2);
    void Op71Halt(uint8_t op2);
    void Op71BitOpSaddr(uint8_t op2);
    void Op71BitOpSfr(uint8_t op2);
    void Op71BitOpHl(uint8_t op2);

    K0Bus *bus_ = nullptr;
    InterruptControllerBase *intc_ = nullptr;
    K0ClockSource *clock_ = nullptr;
    StatusSfrDevice status_dev_;

    uint16_t pc_ = 0;
    uint16_t sp_ = 0;
    uint8_t psw_ = PSW_ISP;

    RunState run_state_ = RunState::Running;
    uint64_t total_cycles_ = 0;
    uint32_t inst_cycles_ = 0;
    uint64_t insn_count_ = 0;
    bool interrupt_delayed_ = false;
    bool invalid_insn_ = false;
    bool brk_stopped_ = false;
    bool halt_entered_ = false;
    bool stop_entered_ = false;
    bool wdt_reset_pending_ = false;
    uint16_t current_insn_pc_ = 0;
    uint32_t last_invalid_opcode_ = 0;

    std::unordered_set<uint16_t> breakpoints_;

    std::array<OpcodeHandler, 256> tbl_unprefixed_{};
    std::array<OpcodeHandler, 256> tbl_prefix31_{};
    std::array<OpcodeHandler, 256> tbl_prefix61_{};
    std::array<OpcodeHandler, 256> tbl_prefix71_{};
};

}  // namespace k0
