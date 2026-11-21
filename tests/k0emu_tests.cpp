#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "debugger.h"
#include "disasm.h"
#include "machine.h"

namespace {

int g_failures = 0;

void CheckTrue(bool cond, const char *expr, const char *file, int line) {
    if (!cond) {
        std::fprintf(stderr, "[FAIL] %s:%d: expected true: %s\n", file, line, expr);
        ++g_failures;
    }
}

void CheckEqU64(uint64_t actual, uint64_t expected, const char *a_expr, const char *e_expr,
                const char *file, int line) {
    if (actual != expected) {
        std::fprintf(stderr, "[FAIL] %s:%d: %s (0x%llX / %llu) != %s (0x%llX / %llu)\n",
                     file, line,
                     a_expr, static_cast<unsigned long long>(actual), static_cast<unsigned long long>(actual),
                     e_expr, static_cast<unsigned long long>(expected), static_cast<unsigned long long>(expected));
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond) CheckTrue((cond), #cond, __FILE__, __LINE__)
#define EXPECT_EQ(a, e) CheckEqU64(static_cast<uint64_t>(a), static_cast<uint64_t>(e), #a, #e, __FILE__, __LINE__)
#define EXPECT_STREQ(a, e) CheckTrue((a) == (e), #a " == " #e, __FILE__, __LINE__)

k0::K0Machine MakeMachine(MachineProfile profile = MachineProfile::Kx2) {
    k0::K0Machine m;
    if (profile == MachineProfile::Legacy0831) {
        m.Configure(MachineProfile::Legacy0831, 0xF000u, 0xF800u, 0xF800u, K0Bus::kHighSpeedRamStart);
    } else {
        m.Configure(MachineProfile::Kx2, 0xC000u, 0xF400u, 0xF800u, K0Bus::kHighSpeedRamStart);
    }
    m.bus.ClearMemory();
    m.Reset(0x0100);
    return m;
}

void WriteBytes(k0::K0Machine &m, uint16_t addr, std::initializer_list<uint8_t> bytes) {
    std::vector<uint8_t> buf(bytes);
    m.bus.WriteDebug(addr, buf.size(), buf.data());
}

std::string HexEncodeAscii(const std::string &s) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out.push_back(kHex[(c >> 4) & 0xFu]);
        out.push_back(kHex[c & 0xFu]);
    }
    return out;
}

void TestResetAndRegisterBanks() {
    auto m = MakeMachine();
    EXPECT_EQ(m.cpu.GetPSW(), 0x02u);  // ISP=1, IE=0, RB=0, bit2=0
    EXPECT_EQ(m.cpu.GetRB(), 0u);
    EXPECT_EQ(m.cpu.GetSP(), 0x0000u);

    // PSW bit 2 is always forced to 0 on writes and SFR reads.
    m.bus.PokeByte(k0::kPswAddress, 0xFFu);
    EXPECT_EQ(m.cpu.GetPSW(), 0xFBu);
    EXPECT_EQ(m.bus.PeekByte(k0::kPswAddress), 0xFBu);
    m.cpu.SetPSW(0x02u);

    // Write RB0..RB3 via SEL RBn (0x61 0xD0 / 0xD8 / 0xF0 / 0xF8) + MOV A, #imm
    WriteBytes(m, 0x0100, {
        0x61, 0xD0, 0xA1, 0x10,  // sel rb0; mov A, #10h -> RB0 (0xFEF8+1 = 0xFEF9)
        0x61, 0xD8, 0xA1, 0x20,  // sel rb1; mov A, #20h -> RB1 (0xFEF0+1 = 0xFEF1)
        0x61, 0xF0, 0xA1, 0x30,  // sel rb2; mov A, #30h -> RB2 (0xFEE8+1 = 0xFEE9)
        0x61, 0xF8, 0xA1, 0x40,  // sel rb3; mov A, #40h -> RB3 (0xFEE0+1 = 0xFEE1)
    });
    for (int i = 0; i < 8; ++i) {
        m.Step();
    }
    EXPECT_EQ(m.cpu.GetRB(), 3u);
    EXPECT_EQ(m.bus.PeekByte(0xFEF9u), 0x10u);
    EXPECT_EQ(m.bus.PeekByte(0xFEF1u), 0x20u);
    EXPECT_EQ(m.bus.PeekByte(0xFEE9u), 0x30u);
    EXPECT_EQ(m.bus.PeekByte(0xFEE1u), 0x40u);
    EXPECT_EQ(m.cpu.ReadRegBank(k0::REG_A, 0), 0x10u);
    EXPECT_EQ(m.cpu.ReadRegBank(k0::REG_A, 1), 0x20u);
    EXPECT_EQ(m.cpu.ReadRegBank(k0::REG_A, 2), 0x30u);
    EXPECT_EQ(m.cpu.ReadRegBank(k0::REG_A, 3), 0x40u);
}

void TestAluMulDivBcdAndShifts() {
    auto m = MakeMachine();

    // Test ADD / ADDC / SUB / SUBC / MULU / DIVUW / ADJBA / ADJBS
    // MOV AX, #0x1234 -> 10 34 12
    // MULU X -> (0x1234: A=0x12, X=0x34) -> A*X = 0x12 * 0x34 = 0x03A8 -> AX=0x03A8 (2 bytes: 31 88)
    // MOV C, #0x10 -> A2 10
    // DIVUW C -> AX=0x03A8 / 0x10 = 0x003A, rem 0x08 -> AX=0x003A, C=0x08 (31 82)
    WriteBytes(m, 0x0100, {
        0x10, 0x34, 0x12,
        0x31, 0x88,
        0xA2, 0x10,
        0x31, 0x82,
    });
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0x1234u);
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0x03A8u);
    m.Step();
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0x003Au);
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_C), 0x08u);

    // DIVUW C with C == 0 (divide by zero yields AX=0xFFFF, C=0 per 78K0 manual / python ref)
    m.cpu.SetPC(0x0200);
    m.cpu.WriteRegPair(k0::RP_AX, 0x1234u);
    m.cpu.WriteReg(k0::REG_C, 0x00u);
    WriteBytes(m, 0x0200, { 0x31, 0x82 });
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0xFFFFu);

    // BCD addition (28 + 34 = 62): ADD A, #34h -> 5Ch, AC=0, lo>9 -> ADJBA -> 62h, CY=0
    m.cpu.SetPC(0x0210);
    m.cpu.SetPSW(0x02u);
    m.cpu.WriteReg(k0::REG_A, 0x28u);
    WriteBytes(m, 0x0210, { 0x0D, 0x34, 0x61, 0x80 });
    m.Step();
    m.Step();
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0x62u);
    EXPECT_TRUE(!m.cpu.GetCY());

    // BCD addition with carry (59 + 48 = 107 -> A=07h, CY=1)
    m.cpu.SetPC(0x0220);
    m.cpu.SetPSW(0x02u);
    m.cpu.WriteReg(k0::REG_A, 0x59u);
    WriteBytes(m, 0x0220, { 0x0D, 0x48, 0x61, 0x80 });
    m.Step();
    m.Step();
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0x07u);
    EXPECT_TRUE(m.cpu.GetCY());

    // BCD subtraction (42 - 19 = 23): SUB A, #19h -> 29h with AC=1 -> ADJBS -> 23h
    m.cpu.SetPC(0x0230);
    m.cpu.SetPSW(0x02u);
    m.cpu.WriteReg(k0::REG_A, 0x42u);
    WriteBytes(m, 0x0230, { 0x1D, 0x19, 0x61, 0x90 });
    m.Step();
    m.Step();
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0x23u);
    EXPECT_TRUE(!m.cpu.GetCY());

    // ROL4 [HL] (0x31 0x80) and ROR4 [HL] (0x31 0x90)
    m.cpu.SetPC(0x0240);
    m.cpu.WriteRegPair(k0::RP_HL, 0xFB20u);
    m.bus.PokeByte(0xFB20u, 0x3Au);
    m.cpu.WriteReg(k0::REG_A, 0xF5u);
    WriteBytes(m, 0x0240, { 0x31, 0x80, 0x31, 0x90 });
    m.Step();  // ROL4: [HL]=A3?, wait: [HL] hi<-lo (A), lo<-A_lo (5) => [HL]=0xA5, A_lo <- [HL]_hi (3) => A=0xF3
    EXPECT_EQ(m.bus.PeekByte(0xFB20u), 0xA5u);
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0xF3u);
    m.Step();  // ROR4 inverse restores
    EXPECT_EQ(m.bus.PeekByte(0xFB20u), 0x3Au);
    EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0xF5u);

    // 16-bit ADDW AX, #imm / SUBW AX, #imm / CMPW AX, #imm
    m.cpu.SetPC(0x0250);
    m.cpu.WriteRegPair(k0::RP_AX, 0xFFFFu);
    WriteBytes(m, 0x0250, {
        0xCA, 0x02, 0x00,  // addw ax, #2 -> ax=0x0001, CY=1
        0xEA, 0x01, 0x00,  // cmpw ax, #1 -> Z=1, CY=0
        0xDA, 0x02, 0x00,  // subw ax, #2 -> ax=0xFFFF, CY=1
    });
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0x0001u);
    EXPECT_TRUE(m.cpu.GetCY());
    m.Step();
    EXPECT_TRUE((m.cpu.GetPSW() & k0::PSW_Z) != 0);
    EXPECT_TRUE(!m.cpu.GetCY());
    m.Step();
    EXPECT_EQ(m.cpu.ReadRegPair(k0::RP_AX), 0xFFFFu);
    EXPECT_TRUE(m.cpu.GetCY());
}

void TestBitOpsBranchesCallsAndCycles() {
    auto m = MakeMachine();
    m.cpu.SetSP(0xFED0u);

    // Note 1 vs Note 2 cycle checks:
    // MOV A, !addr16 (0x8E lo hi): 8 clocks if addr in FB00..FEFF (Note 1), 9 clocks otherwise (Note 2)
    m.bus.PokeByte(0xFB50u, 0xA5u);
    m.bus.PokeByte(0xF500u, 0x5Au);
    m.cpu.SetPC(0x0100);
    WriteBytes(m, 0x0100, {
        0x00,              // nop (2)
        0x8E, 0x50, 0xFB,  // mov A, !0FB50h (8 -> Note 1 high-speed RAM)
        0x8E, 0x00, 0xF5,  // mov A, !0F500h (9 -> Note 2 EXP_RAM)
        0x02, 0x10, 0xFE,  // movw AX, !0FE10h (10 -> Note 1 high-speed RAM)
        0x02, 0x10, 0xF5,  // movw AX, !0F510h (12 -> Note 2 EXP_RAM)
    });
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 2u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 8u); EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0xA5u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 9u); EXPECT_EQ(m.cpu.ReadReg(k0::REG_A), 0x5Au);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 10u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 12u);

    // CALL !addr16 (7 clocks), RET (6), CALLF (5), CALLT (6), BRK (6), RETB (6)
    m.cpu.SetPC(0x0200);
    WriteBytes(m, 0x0040, { 0x60, 0x02 });  // CALLT [40h] -> 0x0260
    WriteBytes(m, 0x003E, { 0x70, 0x02 });  // BRK vector -> 0x0270
    WriteBytes(m, 0x0200, {
        0x9A, 0x50, 0x02,  // call !0250h
        0x0C, 0x55,        // callf 0855h
        0xC1,              // callt [40h]
        0xBF,              // brk
        0x00,              // nop (return from brk)
    });
    WriteBytes(m, 0x0250, { 0xAF });        // ret
    WriteBytes(m, 0x0855, { 0xAF });        // ret
    WriteBytes(m, 0x0260, { 0xAF });        // ret
    WriteBytes(m, 0x0270, { 0x9F });        // retb

    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 7u); EXPECT_EQ(m.cpu.GetPC(), 0x0250u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0203u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 5u); EXPECT_EQ(m.cpu.GetPC(), 0x0855u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0205u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0260u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0206u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0270u);
    m.Step(); EXPECT_EQ(m.cpu.LastInsnCycles(), 6u); EXPECT_EQ(m.cpu.GetPC(), 0x0207u);

    // BTCLR saddr.bit (0x31 0x31 saddr rel -> bit 3)
    m.cpu.SetPC(0x0300);
    m.bus.PokeByte(0xFE20u, 0x08u);
    WriteBytes(m, 0x0300, { 0x31, 0x31, 0x20, 0x05 });  // btclr 0FE20h.3, +5
    m.Step();
    EXPECT_EQ(m.cpu.LastInsnCycles(), 10u);  // Note 1 high-speed RAM
    EXPECT_EQ(m.bus.PeekByte(0xFE20u), 0x00u);
    EXPECT_EQ(m.cpu.GetPC(), 0x0309u);

    // HALT (71 10) and STOP (71 00) take 6 clocks per 78K0KX2.pdf p.768
    m.cpu.stop_on_halt = true;
    m.cpu.stop_on_stop = true;
    m.cpu.SetPC(0x0320);
    WriteBytes(m, 0x0320, { 0x71, 0x10, 0x71, 0x00 });
    const k0::StopInfo hstop = m.Step();
    EXPECT_EQ(static_cast<int>(hstop.reason), static_cast<int>(k0::StopReason::Halt));
    EXPECT_EQ(m.cpu.LastInsnCycles(), 6u);
    m.cpu.SetRunState(k0::RunState::Running);
    const k0::StopInfo sstop = m.Step();
    EXPECT_EQ(static_cast<int>(sstop.reason), static_cast<int>(k0::StopReason::Stop));
    EXPECT_EQ(m.cpu.LastInsnCycles(), 6u);
}

void TestInterruptsPriorityHoldAndStandbyWakeup() {
    auto m = MakeMachine();
    m.cpu.SetSP(0xFED0u);
    m.cpu.stop_on_halt = false;
    m.cpu.stop_on_stop = false;

    // Install vector for INTP0 (source 1 -> 0x0006) and INTP1 (source 2 -> 0x0008)
    WriteBytes(m, 0x0006, { 0x00, 0x04 });  // 0x0400 (low prio)
    WriteBytes(m, 0x0008, { 0x20, 0x04 });  // 0x0420 (high prio)

    // Test 1: interrupt hold after EI (writes PSW = 0xFF1E -> 71 7B 1E? Better: MOV PSW, #0x82 -> 13 1E 82)
    // Wait: EI is 71 7A 1E, wait 71 7A 1E (SET1 PSW.7), let's check both!
    WriteBytes(m, 0x0100, {
        0x71, 0x7A, 0x1E,  // EI (set1 PSW.7) -> hold for 1 instruction!
        0x00,              // nop (must execute before pending IRQ dispatches!)
        0x00,              // nop
    });
    WriteBytes(m, 0x0400, {
        0x71, 0x7A, 0x1E,  // EI inside low-prio ISR so high-prio INTP1 can preempt!
        0x00,              // nop
        0x8F,              // reti
    });
    WriteBytes(m, 0x0420, {
        0x8F,              // reti
    });

    // Unmask INTP0 (MK0L bit 1 = 0) and INTP1 (MK0L bit 2 = 0); set PR0L bit 1 = 1 (low), bit 2 = 0 (high)
    m.bus.PokeByte(0xFFE4u, 0xF9u);
    m.bus.PokeByte(0xFFE8u, 0x02u);  // INTP0 low priority, INTP1 high priority
    m.intc.RaiseIrq(1);  // INTP0 pending

    m.Step();  // executes EI -> hold prevents INTP0 dispatch on EI itself; DispatchInterruptIfReady clears hold for next insn
    EXPECT_EQ(m.cpu.GetPC(), 0x0103u);
    EXPECT_TRUE(!m.cpu.IsInterruptDelayed());

    m.Step();  // executes NOP at 0x0103, THEN dispatches INTP0 -> 0x0400
    EXPECT_EQ(m.cpu.GetPC(), 0x0400u);
    EXPECT_TRUE((m.cpu.GetPSW() & k0::PSW_IE) == 0);
    EXPECT_TRUE((m.cpu.GetPSW() & k0::PSW_ISP) != 0);

    // Raise INTP1 (high priority) while inside low-priority ISR
    m.intc.RaiseIrq(2);
    m.Step();  // executes EI at 0x0400 -> hold active -> PC=0x0403
    EXPECT_EQ(m.cpu.GetPC(), 0x0403u);
    m.Step();  // executes NOP at 0x0403 -> dispatches high-prio INTP1 -> 0x0420
    EXPECT_EQ(m.cpu.GetPC(), 0x0420u);
    EXPECT_TRUE((m.cpu.GetPSW() & k0::PSW_ISP) == 0);

    m.Step();  // RETI from 0x0420 -> back to 0x0404 (with hold for 1 insn)
    EXPECT_EQ(m.cpu.GetPC(), 0x0404u);
    m.Step();  // RETI from 0x0404 -> back to 0x0104
    EXPECT_EQ(m.cpu.GetPC(), 0x0104u);

    // Test 2: HALT and STOP wakeup even when EI=0 (IF unmasked wakes CPU without taking vector if EI=0)
    m.cpu.SetPSW(0x02u);  // DI
    m.bus.PokeByte(0xFFE0u, 0x00u);  // clear IF0L
    m.cpu.SetPC(0x0500);
    WriteBytes(m, 0x0500, { 0x71, 0x10, 0x00 });  // halt; nop
    m.Step();
    EXPECT_EQ(static_cast<int>(m.cpu.GetRunState()), static_cast<int>(k0::RunState::Halted));
    m.intc.RaiseIrq(1);
    m.Step();  // wakes from HALT, DI so stays at next PC 0x0502
    EXPECT_EQ(static_cast<int>(m.cpu.GetRunState()), static_cast<int>(k0::RunState::Running));
    EXPECT_EQ(m.cpu.GetPC(), 0x0502u);

    // STOP wakeup with EI=1 dispatches ISR
    m.bus.PokeByte(0xFFE0u, 0x00u);
    m.cpu.SetPSW(k0::PSW_IE | k0::PSW_ISP);
    m.cpu.SetPC(0x0510);
    WriteBytes(m, 0x0510, { 0x71, 0x00 });  // stop
    m.Step();
    EXPECT_EQ(static_cast<int>(m.cpu.GetRunState()), static_cast<int>(k0::RunState::Stopped));
    m.intc.RaiseIrq(2);  // high prio unmasked
    m.Step();  // exits STOP and vectors to 0x0420
    EXPECT_EQ(static_cast<int>(m.cpu.GetRunState()), static_cast<int>(k0::RunState::Running));
    EXPECT_EQ(m.cpu.GetPC(), 0x0420u);
}

void TestKx2Peripherals() {
    // 1. Bank switching (BANK 0xFFF3) on 96KB ROM image
    {
        k0::K0Machine m;
        std::vector<uint8_t> rom96(0x18000u, 0xFFu);
        rom96[0x0000] = 0x00; rom96[0x0001] = 0x01;
        rom96[0x8000] = 0xB0u;  // Bank 0
        rom96[0xC000] = 0xB1u;  // Bank 1 (0x0C000..0x0FFFF)
        rom96[0x10000] = 0xB2u; // Bank 2 (0x10000..0x13FFF)
        EXPECT_TRUE(m.LoadRomBytes(rom96.data(), rom96.size(), 0));
        m.Reset();
        EXPECT_EQ(m.bus.PeekByte(0x8000u), 0xB0u);
        m.bus.WriteCpu(0xFFF3u, 1u);
        EXPECT_EQ(m.bus.PeekByte(0x8000u), 0xB1u);
        m.bus.WriteCpu(0xFFF3u, 2u);
        EXPECT_EQ(m.bus.PeekByte(0x8000u), 0xB2u);
    }

    // 2. Option byte 0x0080 enabling WDT + WDTE kick & overflow reset
    {
        auto m = MakeMachine();
        // Option byte: 0x10 => WDTON=1 (bit4), WDCS=0 (2^10 = 1024 RL clocks), LSROSC=0
        m.bus.PokeByte(0x0080u, 0x10u);
        m.bus.PokeByte(0x0000u, 0x00u);
        m.bus.PokeByte(0x0001u, 0x01u);
        m.Reset();
        EXPECT_TRUE(m.wdt.IsEnabled());
        EXPECT_EQ(m.wdt.GetOverflowPeriod(), 1024u);

        // Kick WDT with 0xAC resets counter
        m.bus.WriteCpu(0xFF99u, 0xACu);
        EXPECT_EQ(m.wdt.GetCounter(), 0u);

        // Advance with LSR running at ~240kHz (~33.3 CPU clocks/RL -> ~34k CPU cycles): execute br $-2 until WDT overflow
        WriteBytes(m, 0x0100, { 0xFA, 0xFE });  // br $-2 infinite loop
        m.wdt.halt_on_reset = true;
        bool hit_wdt_reset = false;
        for (int i = 0; i < 15000; ++i) {
            const auto s = m.Step();
            if (s.reason == k0::StopReason::WdtReset) {
                hit_wdt_reset = true;
                break;
            }
        }
        EXPECT_TRUE(hit_wdt_reset);
        EXPECT_TRUE((m.sysctrl.GetResf() & 0x10u) != 0);
    }

    // 3. Clock generator (OSCCTL / RCM.RSTS / PCC.CLS)
    {
        auto m = MakeMachine();
        m.bus.WriteCpu(0xFF9Fu, 0x41u);
        EXPECT_EQ(m.bus.PeekByte(0xFF9Fu), 0x41u);
        EXPECT_TRUE((m.bus.PeekByte(0xFFA0u) & 0x80u) != 0);  // RSTS always ready
        m.bus.WriteCpu(0xFFFBu, 0x10u);  // CSS=1 (select subclock)
        EXPECT_TRUE((m.bus.PeekByte(0xFFFBu) & 0x20u) != 0);  // CLS mirrors CSS
    }

    // 4. Ports & INTP edge interrupt
    {
        auto m = MakeMachine();
        m.bus.WriteCpu(0xFF48u, 0x01u);  // EGP bit 0 = rising edge INTP0
        m.ports.SetExternalInput(12, 0, false);
        m.ports.SetExternalInput(12, 0, true);  // P12.0 triggers INTP0 (source 1 -> IF0L bit 1)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE0u) & 0x02u) != 0);
    }

    // 5. Timers: TM00 (16-bit), TM50 (8-bit), TMH0 (8-bit), WTM (watch timer)
    {
        auto m = MakeMachine();
        // TM00: CR000 = 2, TMC00 = 0x0C (clear & start on TM00 == CR000), PRM00 = 0x00 (div 1)
        m.bus.WriteCpu(0xFF12u, 0x02u);
        m.bus.WriteCpu(0xFF13u, 0x00u);
        m.bus.WriteCpu(0xFFBBu, 0x00u);
        m.bus.WriteCpu(0xFFBAu, 0x0Cu);
        m.tm00.Tick(4, 4, 0, 0, false, false);
        // INTTM000 = source 14 -> reg_offset=1 (IF0H), bit=6 (0x40)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x40u) != 0);

        // TM50: CR50 = 2, TCL50 = 0x02 (fPRS/1), TMC50 = 0x80
        m.bus.WriteCpu(0xFF17u, 0x02u);
        m.bus.WriteCpu(0xFF6Au, 0x02u);
        m.bus.WriteCpu(0xFF6Bu, 0x80u);
        m.tm50.Tick(4, 4, 0, 0, false, false);
        // INTTM50 = source 13 -> IF0H bit 5 (0x20)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x20u) != 0);

        // TMH0: CMP00 = 2, TMHMD0 = 0x80 (start, div 1)
        m.bus.WriteCpu(0xFF18u, 0x02u);
        m.bus.WriteCpu(0xFF69u, 0x80u);
        m.tmh0.Tick(4, 4, 0, 0, false, false);
        // INTTMH0 = source 12 -> IF0H bit 4 (0x10)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x10u) != 0);

        // WTM: WTM = 0x83 (subclock selected, fastest WTI = 2^4 = 16 sub clocks)
        m.bus.WriteCpu(0xFF6Fu, 0x83u);
        m.wtm.Tick(200, 200, 32, 0, false, false);
        // INTWTI = source 18 -> IF1L bit 2 (0x04)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE2u) & 0x04u) != 0);
    }

    // 6. ADC conversion -> ADCR (left aligned 10-bit) + INTAD
    {
        auto m = MakeMachine();
        m.adc.SetChannelValue(2, 0x02A5u);
        m.bus.WriteCpu(0xFF29u, 0x02u);  // ADS = channel 2
        m.bus.WriteCpu(0xFF28u, 0xA8u);  // ADM: ADCS=1 (0x80), FR=5 (44 cycles)
        m.adc.Tick(50, 50, 0, 0, false, false);
        const uint16_t adcr = static_cast<uint16_t>(m.bus.PeekByte(0xFF08u)) |
                              (static_cast<uint16_t>(m.bus.PeekByte(0xFF09u)) << 8);
        EXPECT_EQ(adcr, static_cast<uint16_t>(0x02A5u << 6));
        // INTAD = source 16 -> IF1L bit 0 (0x01)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE2u) & 0x01u) != 0);
    }

    // 7. UART6 & UART0 TX/RX + IRQs
    {
        auto m = MakeMachine();
        m.bus.WriteCpu(0xFF50u, 0xE0u);  // ASIM6 POWER|TXE|RXE
        m.bus.WriteCpu(0xFF0Bu, 'K');    // TXB6
        m.uart6.Tick(200, 200, 0, 0, false, false);
        EXPECT_EQ(m.uart6.TxLog().size(), 1u);
        EXPECT_EQ(m.uart6.TxLog()[0], 'K');
        // INTST6 = source 9 -> IF0H bit 1 (0x02)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x02u) != 0);

        m.uart6.InjectRxByte('Z');
        // INTSR6 = source 8 -> IF0H bit 0 (0x01)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x01u) != 0);
        EXPECT_EQ(m.bus.ReadCpu(0xFF0Au), 'Z');

        m.bus.WriteCpu(0xFF70u, 0xC0u);  // ASIM0 POWER|TXE
        m.bus.WriteCpu(0xFF74u, '0');    // TXS0
        m.uart0.Tick(200, 200, 0, 0, false, false);
        EXPECT_EQ(m.uart0.TxLog().size(), 1u);
        EXPECT_EQ(m.uart0.TxLog()[0], '0');
    }

    // 8. CSI10 callback + IRQ
    {
        auto m = MakeMachine();
        uint8_t captured_tx = 0;
        m.csi10.SetSpiCallback([&](uint8_t tx) -> uint8_t {
            captured_tx = tx;
            return static_cast<uint8_t>(tx ^ 0xFFu);
        });
        m.bus.WriteCpu(0xFF80u, 0xC0u);  // CSIM10 enable
        m.bus.WriteCpu(0xFF84u, 0xA3u);  // SOTB10 trigger
        EXPECT_EQ(captured_tx, 0xA3u);
        EXPECT_EQ(m.bus.ReadCpu(0xFF0Fu), 0x5Cu);
        // INTCSI10 = source 10 -> IF0H bit 2 (0x04)
        EXPECT_TRUE((m.bus.PeekByte(0xFFE1u) & 0x04u) != 0);
    }

    // 9. IIC0 Kx2 IICS0 flags (SPD0=0x01, STD0=0x02, ACKD0=0x04) + Target I2C read/write
    {
        struct FakeI2c : public k0::I2cTargetDevice {
            uint8_t last_w = 0;
            void I2cStart(bool) override {}
            void I2cStop() override {}
            uint8_t I2cRead() override { return 0x77u; }
            bool I2cWrite(uint8_t b) override { last_w = b; return true; }
        } dev;

        auto m = MakeMachine();
        m.iic0.AddTarget(0x50u, &dev);
        m.bus.WriteCpu(0xFFA6u, 0x80u);  // IICC0.IICE = 1
        m.bus.WriteCpu(0xFFA6u, 0x82u);  // STT0 = 1 (Start condition armed)
        m.bus.WriteCpu(0xFFA5u, static_cast<uint8_t>(0x50u << 1));  // write address triggers START + ACK
        EXPECT_TRUE((m.bus.PeekByte(0xFFAAu) & 0x02u) != 0);  // STD0=0x02
        EXPECT_TRUE((m.bus.PeekByte(0xFFAAu) & 0x04u) != 0);  // ACKD0=0x04
        m.bus.WriteCpu(0xFFA5u, 0x5Au);
        EXPECT_EQ(dev.last_w, 0x5Au);
        m.bus.WriteCpu(0xFFA6u, 0x81u);  // SPT0 = 1 (Stop condition)
        EXPECT_TRUE((m.bus.PeekByte(0xFFAAu) & 0x01u) != 0);  // SPD0=0x01
    }

    // 10. Multiplier/Divider (FF60..FF68)
    {
        auto m = MakeMachine();
        // 16x16 multiply: 300 * 200 = 60000 (0xEA60)
        m.bus.WriteCpu(0xFF62u, 0x2Cu); m.bus.WriteCpu(0xFF63u, 0x01u);  // MDA0L = 300
        m.bus.WriteCpu(0xFF66u, 0xC8u); m.bus.WriteCpu(0xFF67u, 0x00u);  // MDB0 = 200
        m.bus.WriteCpu(0xFF68u, 0x81u);  // start MUL
        m.muldiv.Tick(32, 32, 0, 0, false, false);
        const uint32_t prod = m.bus.PeekByte(0xFF62u) |
                              (uint32_t(m.bus.PeekByte(0xFF63u)) << 8) |
                              (uint32_t(m.bus.PeekByte(0xFF64u)) << 16) |
                              (uint32_t(m.bus.PeekByte(0xFF65u)) << 24);
        EXPECT_EQ(prod, 60000u);

        // 32/16 divide: 60007 / 100 = 600, rem 7
        m.bus.WriteCpu(0xFF62u, 60007u & 0xFFu);
        m.bus.WriteCpu(0xFF63u, (60007u >> 8) & 0xFFu);
        m.bus.WriteCpu(0xFF64u, 0);
        m.bus.WriteCpu(0xFF65u, 0);
        m.bus.WriteCpu(0xFF66u, 100u);
        m.bus.WriteCpu(0xFF67u, 0u);
        m.bus.WriteCpu(0xFF68u, 0x80u);  // start DIV
        m.muldiv.Tick(40, 40, 0, 0, false, false);
        const uint16_t quot = static_cast<uint16_t>(m.bus.PeekByte(0xFF62u) | (m.bus.PeekByte(0xFF63u) << 8));
        const uint16_t rem = static_cast<uint16_t>(m.bus.PeekByte(0xFF60u) | (m.bus.PeekByte(0xFF61u) << 8));
        EXPECT_EQ(quot, 600u);
        EXPECT_EQ(rem, 7u);
    }
}

void TestBreakpointsWatchpointsDisasmAndGdb() {
    auto m = MakeMachine();
    WriteBytes(m, 0x0100, {
        0x10, 0x34, 0x12,  // movw ax, #1234h
        0x03, 0x00, 0xFB,  // movw !0FB00h, ax (3 bytes -> next PC 0x0106)
        0x00,              // nop (0x0106)
        0x00,              // nop (0x0107)
    });

    // Disassembler & SFR name lookup
    const auto d0 = k0::DisassembleAt(m.bus, 0x0100);
    EXPECT_TRUE(d0.valid);
    EXPECT_EQ(d0.length, 3u);
    EXPECT_TRUE(d0.Format().find("movw") != std::string::npos);
    EXPECT_TRUE(std::strcmp(k0::LookupSfrName(0xFFE0u, MachineProfile::Kx2), "IF0L") == 0);
    EXPECT_TRUE(std::strcmp(k0::LookupSfrName(0xFFAAu, MachineProfile::Kx2), "IICS0") == 0);

    // Watchpoint + Breakpoint test
    m.bus.AddWatchpoint(0xFB00u, 2u, 1);  // write watchpoint
    m.cpu.AddBreakpoint(0x0107u);
    auto r1 = m.RunSteps(100);
    EXPECT_EQ(static_cast<int>(r1.reason), static_cast<int>(k0::StopReason::Watchpoint));
    EXPECT_EQ(r1.detail, 0xFB00u);
    auto r2 = m.RunSteps(100, true);
    EXPECT_EQ(static_cast<int>(r2.reason), static_cast<int>(k0::StopReason::Breakpoint));
    EXPECT_EQ(r2.pc, 0x0107u);

    // GDB RSP packet dispatcher test
    m.Reset(0x0100);
    m.bus.ClearWatchpoints();
    m.cpu.ClearBreakpoints();
    k0::Debugger dbg(&m, 0);

    EXPECT_TRUE(dbg.ProcessPacket("qSupported:multiprocess+").find("qXfer:features:read+") != std::string::npos);
    const std::string target_xml = dbg.ProcessPacket("qXfer:features:read:target.xml:0,fff");
    EXPECT_TRUE(target_xml.find("78k0") != std::string::npos);
    const std::string mmap_xml = dbg.ProcessPacket("qXfer:memory-map:read::0,fff");
    EXPECT_TRUE(mmap_xml.find("<memory-map>") != std::string::npos);

    EXPECT_STREQ(dbg.ProcessPacket("m100,3"), "103412");
    EXPECT_STREQ(dbg.ProcessPacket("Mfb10,2:aabb"), "OK");
    EXPECT_EQ(m.bus.PeekByte(0xFB10u), 0xAAu);
    EXPECT_EQ(m.bus.PeekByte(0xFB11u), 0xBBu);

    EXPECT_STREQ(dbg.ProcessPacket("Z0,106,1"), "OK");
    EXPECT_TRUE(m.cpu.HasBreakpoint(0x0106u));
    const std::string creply = dbg.ProcessPacket("c");
    EXPECT_TRUE(creply.rfind("T05", 0) == 0);
    EXPECT_EQ(m.cpu.GetPC(), 0x0106u);
    EXPECT_STREQ(dbg.ProcessPacket("z0,106,1"), "OK");
    EXPECT_TRUE(!m.cpu.HasBreakpoint(0x0106u));

    const std::string status_hex = dbg.ProcessPacket("qRcmd," + HexEncodeAscii("status"));
    EXPECT_TRUE(!status_hex.empty() && status_hex != "E01");
}

bool TryLoadProgrammerRomFromRepo(k0::K0Machine &m) {
    static const char *const kRelPaths[] = {
        "78k0_programmer_fw.bin",
        "../78k0_programmer_fw.bin",
        "../../78k0_programmer_fw.bin",
    };
    for (const char *p : kRelPaths) {
        if (m.LoadProgrammerRomFile(p)) {
            return true;
        }
    }
    return false;
}

void WriteProtectedReg(K0Bus &bus, uint16_t addr, uint8_t value) {
    bus.WriteCpu(0xFFC0u, 0xA5u);
    bus.WriteCpu(addr, value);
    bus.WriteCpu(addr, static_cast<uint8_t>(~value));
    bus.WriteCpu(addr, value);
}

void TestProgrammerRomAndEaFlash() {
    // 1. PFCMD (0xFFC0) write-protection state machine on FLPMC (0xFFC4) & FLREG (0xFFCA)
    {
        auto m = MakeMachine();
        std::vector<uint8_t> dummy_prog(K0Bus::kProgRomSize, 0xAAu);
        EXPECT_TRUE(m.LoadProgrammerRomBytes(dummy_prog.data(), dummy_prog.size()));

        // Unprotected write rejected
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x03u, 0u);

        // Wrong complement rejected
        m.bus.WriteCpu(0xFFC0u, 0xA5u);
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        m.bus.WriteCpu(0xFFC4u, 0xAAu);
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);

        // Wrong 3rd confirmation rejected
        m.bus.WriteCpu(0xFFC0u, 0xA5u);
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        m.bus.WriteCpu(0xFFC4u, 0xFEu);
        m.bus.WriteCpu(0xFFC4u, 0x03u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);

        // Switching target register mid-sequence rejected
        m.bus.WriteCpu(0xFFC0u, 0xA5u);
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        m.bus.WriteCpu(0xFFCAu, 0xFEu);
        m.bus.WriteCpu(0xFFC4u, 0x01u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);

        // Valid sequences for 0xFFC4 and 0xFFCA
        WriteProtectedReg(m.bus, 0xFFC4u, 0x01u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 1u);
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x03u, 1u);

        m.bus.WriteCpu(0xFFCAu, 0x01u);  // unprotected FLREG write ignored
        EXPECT_EQ(m.bus.PeekByte(0xFFCAu), 0x00u);
        WriteProtectedReg(m.bus, 0xFFCAu, 0x81u);
        EXPECT_EQ(m.bus.PeekByte(0xFFCAu), 0x81u);
    }

    // 2. Two-stage overlay (8 KB and 64 KB images, plus 32 KB chip where 0x8000 is above rom_end)
    {
        k0::K0Machine m;
        m.Configure(MachineProfile::Kx2, 0x8000u, 0xF400u, 0xF800u);  // 32 KB user ROM
        m.bus.ClearMemory();
        m.bus.PokeByte(0x0010u, 0x12u);
        m.bus.PokeByte(0x0123u, 0x34u);

        // 8 KB programmer ROM
        std::vector<uint8_t> prog8k(K0Bus::kProgRomSize, 0xFFu);
        prog8k[0x0010u] = 0x5Au;
        prog8k[0x0123u] = 0x7Bu;
        EXPECT_TRUE(m.LoadProgrammerRomBytes(prog8k.data(), prog8k.size()));
        m.Reset(0x0100);

        EXPECT_EQ(m.bus.PeekByte(0x0010u), 0x12u);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0xFFu);  // unmapped above 0x8000

        WriteProtectedReg(m.bus, 0xFFC4u, 0x01u);   // bit 0 -> high window only
        EXPECT_EQ(m.bus.PeekByte(0x0010u), 0x12u);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0x5Au);
        EXPECT_EQ(m.bus.PeekByte(0x8123u), 0x7Bu);

        WriteProtectedReg(m.bus, 0xFFC4u, 0x03u);   // bits 0|1 -> both windows
        EXPECT_EQ(m.bus.PeekByte(0x0010u), 0x5Au);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0x5Au);

        // Mask ROM is read-only even via Poke/WriteCpu
        m.bus.WriteCpu(0x8010u, 0x00u);
        m.bus.PokeByte(0x0010u, 0x00u);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0x5Au);
        EXPECT_EQ(m.bus.PeekByte(0x0010u), 0x5Au);

        // Clear bit 1 -> unmaps low window, keeps high window
        WriteProtectedReg(m.bus, 0xFFC4u, 0x09u);
        EXPECT_EQ(m.bus.PeekByte(0x0010u), 0x12u);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0x5Au);

        // Clear bit 0 -> unmaps both
        WriteProtectedReg(m.bus, 0xFFC4u, 0x00u);
        EXPECT_EQ(m.bus.PeekByte(0x8010u), 0xFFu);

        // 64 KB dump with programmer image populated only at 0x8000..0x9FFF
        std::vector<uint8_t> prog64k(0x10000u, 0xFFu);
        prog64k[0x8055u] = 0xC3u;
        EXPECT_TRUE(m.LoadProgrammerRomBytes(prog64k.data(), prog64k.size()));
        WriteProtectedReg(m.bus, 0xFFC4u, 0x03u);
        EXPECT_EQ(m.bus.PeekByte(0x0055u), 0xC3u);
        EXPECT_EQ(m.bus.PeekByte(0x8055u), 0xC3u);
    }

    // 3. FLMD0 pin modes & 0xFFF5 product ID derivation
    {
        k0::K0Machine m;
        auto check_prod = [&](uint32_t rom_size, uint8_t expected_prod) {
            m.Configure(MachineProfile::Kx2,
                        static_cast<uint16_t>(rom_size <= 0xF000u ? rom_size : 0xC000u),
                        0xF400u, 0xF800u);
            if (rom_size > 0xF000u) {
                std::vector<uint8_t> big(rom_size, 0xFFu);
                EXPECT_TRUE(m.LoadRomBytes(big.data(), big.size(), 0));
            }
            EXPECT_EQ(m.bus.PeekByte(0xFFF5u), expected_prod);
        };
        check_prod(0x4000u, 0x10u);
        check_prod(0x6000u, 0x20u);
        check_prod(0x8000u, 0x30u);
        check_prod(0xC000u, 0x40u);
        check_prod(0xF000u, 0x50u);
        check_prod(0x18000u, 0x60u);
        check_prod(0x20000u, 0x70u);

        // 0xFFF5 is CPU read-only, overridable via Poke/SetProductOverride
        m.bus.WriteCpu(0xFFF5u, 0x00u);
        EXPECT_EQ(m.bus.PeekByte(0xFFF5u), 0x70u);
        m.bus.PokeByte(0xFFF5u, 0x42u);
        EXPECT_EQ(m.bus.PeekByte(0xFFF5u), 0x42u);
        m.flash.SetProductOverride(-1);
        EXPECT_EQ(m.bus.PeekByte(0xFFF5u), 0x70u);

        // FLMD0 modes
        m.Reset(0x0100);
        m.flash.SetFlmd0Mode(k0::Kx2FlashCtrl::Flmd0Mode::High);
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x04u, 0x04u);
        m.flash.SetFlmd0Mode(k0::Kx2FlashCtrl::Flmd0Mode::Low);
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x04u, 0x00u);
        m.flash.SetFlmd0Mode(k0::Kx2FlashCtrl::Flmd0Mode::PinP23);
        m.bus.WriteCpu(0xFF22u, 0xF3u);  // PM2.3 = output
        m.bus.WriteCpu(0xFF02u, 0x00u);  // P2.3 = 0
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x04u, 0x00u);
        m.bus.WriteCpu(0xFF02u, 0x08u);  // P2.3 = 1
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x04u, 0x04u);
    }

    // 4. Extra Area (0x800 bytes) & main-flash reads through 0xF8F2..0xF8F5 swapped halfwords
    {
        auto m = MakeMachine();
        std::vector<uint8_t> ea(k0::Kx2FlashCtrl::kEaSize, 0xEEu);
        ea[0x0790u] = 0x11u;
        ea[0x0791u] = 0x22u;
        ea[0x0792u] = 0x33u;
        ea[0x0793u] = 0x44u;
        EXPECT_TRUE(m.LoadEaBytes(ea.data(), ea.size()));

        std::vector<uint8_t> prog(K0Bus::kProgRomSize, 0xAAu);
        prog[0x0100u] = 0x01u;
        prog[0x0101u] = 0x02u;
        prog[0x0102u] = 0x03u;
        prog[0x0103u] = 0x04u;
        EXPECT_TRUE(m.LoadProgrammerRomBytes(prog.data(), prog.size()));

        // Underlying main flash at 0x0100..0x0103
        WriteBytes(m, 0x0100u, { 0xDEu, 0xADu, 0xBEu, 0xEFu });

        // Enable both overlays (FLPMC = 0x03)
        WriteProtectedReg(m.bus, 0xFFC4u, 0x03u);

        // Read EA at 0x0790
        WriteProtectedReg(m.bus, 0xFFCAu, 0x01u);  // EA region
        m.bus.WriteCpu(0xFFC7u, 0x00u);
        m.bus.WriteCpu(0xFFC8u, 0x90u);
        m.bus.WriteCpu(0xFFC9u, 0x07u);
        m.bus.WriteCpu(0xFFC6u, 0x00u);
        m.bus.WriteCpu(0xFFC1u, 0x80u);
        m.bus.WriteCpu(0xFFC5u, 0x08u);
        m.bus.WriteCpu(0xFFC5u, 0x0Au);            // rising edge bit 1
        EXPECT_EQ(m.bus.ReadCpu(0xF8F4u), 0x11u);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F5u), 0x22u);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F2u), 0x33u);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F3u), 0x44u);

        // Out-of-range EA offset (>= 0x800) returns 0xFF
        m.bus.WriteCpu(0xFFC8u, 0x00u);
        m.bus.WriteCpu(0xFFC9u, 0x08u);
        m.bus.WriteCpu(0xFFC5u, 0x08u);
        m.bus.WriteCpu(0xFFC5u, 0x0Au);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F4u), 0xFFu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F5u), 0xFFu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F2u), 0xFFu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F3u), 0xFFu);

        // Main flash read (0xFFCA=0x00) bypasses prog_rom_ overlay even with FLPMC=0x03
        WriteProtectedReg(m.bus, 0xFFCAu, 0x00u);
        m.bus.WriteCpu(0xFFC8u, 0x00u);
        m.bus.WriteCpu(0xFFC9u, 0x01u);
        m.bus.WriteCpu(0xFFC6u, 0x00u);
        m.bus.WriteCpu(0xFFC5u, 0x08u);
        m.bus.WriteCpu(0xFFC5u, 0x0Au);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F4u), 0xDEu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F5u), 0xADu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F2u), 0xBEu);
        EXPECT_EQ(m.bus.ReadCpu(0xF8F3u), 0xEFu);
    }

    // 5. Self-contained CPU execution test exercising overlay switch, EA read, unmap, and return
    {
        auto m = MakeMachine();
        m.cpu.SetSP(0xFECEu);
        m.cpu.stop_on_brk = true;

        std::vector<uint8_t> ea(k0::Kx2FlashCtrl::kEaSize, 0xFFu);
        ea[0x0790u] = 0xA1u; ea[0x0791u] = 0xB2u; ea[0x0792u] = 0xC3u; ea[0x0793u] = 0xD4u;
        EXPECT_TRUE(m.LoadEaBytes(ea.data(), ea.size()));

        std::vector<uint8_t> prog(K0Bus::kProgRomSize, 0xFFu);
        // Helper in prog_rom at 0x0180 (called as !0x0180 once FLPMC.1=1)
        const uint8_t helper[] = {
            0x71, 0x1B, 0xC5,        // clr1 0xFFC5.1
            0x71, 0x1A, 0xC5,        // set1 0xFFC5.1 (rising edge latches 0xF8F2..0xF8F5)
            0xAF,                    // ret
        };
        std::memcpy(prog.data() + 0x0180u, helper, sizeof(helper));

        // Firmware entry in prog_rom at 0x0100 (called as !0x8100 from user code)
        const uint8_t fw_entry[] = {
            0x13, 0xC0, 0xA5,        // mov PFCMD, #0xA5
            0x13, 0xC4, 0x03,        // mov FLPMC, #0x03
            0x13, 0xC4, 0xFC,        // mov FLPMC, #0xFC
            0x13, 0xC4, 0x03,        // mov FLPMC, #0x03 (low + high overlay)
            0x13, 0xC0, 0xA5,        // mov PFCMD, #0xA5
            0x13, 0xCA, 0x01,        // mov FLREG, #0x01 (EA)
            0x13, 0xCA, 0xFE,        // mov FLREG, #0xFE
            0x13, 0xCA, 0x01,        // mov FLREG, #0x01
            0x13, 0xC8, 0x90,        // mov FLADRL, #0x90
            0x13, 0xC9, 0x07,        // mov FLADRM, #0x07
            0x13, 0xC6, 0x00,        // mov FLADRH, #0x00
            0x13, 0xC7, 0x00,        // mov FLSTS, #0x00
            0x13, 0xC1, 0x80,        // mov FLM0, #0x80
            0x71, 0x3A, 0xC5,        // set1 0xFFC5.3
            0x9A, 0x80, 0x01,        // call !0x0180 (uses low overlay)
            0x8E, 0xF4, 0xF8,        // mov A, !0xF8F4
            0x9E, 0x58, 0xFD,        // mov !0xFD58, A
            0x8E, 0xF5, 0xF8,        // mov A, !0xF8F5
            0x9E, 0x59, 0xFD,        // mov !0xFD59, A
            0x8E, 0xF2, 0xF8,        // mov A, !0xF8F2
            0x9E, 0x5A, 0xFD,        // mov !0xFD5A, A
            0x8E, 0xF3, 0xF8,        // mov A, !0xF8F3
            0x9E, 0x5B, 0xFD,        // mov !0xFD5B, A
            0x13, 0xC0, 0xA5,        // mov PFCMD, #0xA5
            0x13, 0xC4, 0x09,        // mov FLPMC, #0x09 (unmap low)
            0x13, 0xC4, 0xF6,        // mov FLPMC, #0xF6
            0x13, 0xC4, 0x09,        // mov FLPMC, #0x09
            0xAF,                    // ret
        };
        std::memcpy(prog.data() + 0x0100u, fw_entry, sizeof(fw_entry));
        EXPECT_TRUE(m.LoadProgrammerRomBytes(prog.data(), prog.size()));

        // User code at 0x0200 (safe from low overlay)
        WriteBytes(m, 0x0200u, {
            0x13, 0xC0, 0xA5,        // mov PFCMD, #0xA5
            0x13, 0xC4, 0x01,        // mov FLPMC, #0x01
            0x13, 0xC4, 0xFE,        // mov FLPMC, #0xFE
            0x13, 0xC4, 0x01,        // mov FLPMC, #0x01
            0x9A, 0x00, 0x81,        // call !0x8100
            0x13, 0xC0, 0xA5,        // mov PFCMD, #0xA5
            0x13, 0xC4, 0x00,        // mov FLPMC, #0x00
            0x13, 0xC4, 0xFF,        // mov FLPMC, #0xFF
            0x13, 0xC4, 0x00,        // mov FLPMC, #0x00
            0xBF,                    // brk
        });
        m.cpu.SetPC(0x0200u);
        const auto stop = m.RunSteps(1000);
        EXPECT_EQ(static_cast<int>(stop.reason), static_cast<int>(k0::StopReason::BreakInsn));
        EXPECT_EQ(m.bus.PeekByte(0xFD58u), 0xA1u);
        EXPECT_EQ(m.bus.PeekByte(0xFD59u), 0xB2u);
        EXPECT_EQ(m.bus.PeekByte(0xFD5Au), 0xC3u);
        EXPECT_EQ(m.bus.PeekByte(0xFD5Bu), 0xD4u);
        EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u), 0x04u);
    }

    // 6. Diagnostics / CLI flash commands / FLASH_BUF region
    {
        auto m = MakeMachine();
        const auto regs = m.bus.GetRegions();
        bool found_flash_buf = false;
        for (const auto &r : regs) {
            if (r.name == "FLASH_BUF" && r.start == 0xF8F0u && r.size == 0x10u) {
                found_flash_buf = true;
            }
        }
        EXPECT_TRUE(found_flash_buf);

        std::string cmd_out;
        EXPECT_TRUE(m.ExecuteCommand("flash", cmd_out));
        EXPECT_TRUE(cmd_out.find("PROD(FFF5)=40") != std::string::npos);
        EXPECT_TRUE(m.ExecuteCommand("flmd0 0", cmd_out));
        EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x04u, 0u);
        EXPECT_TRUE(m.ExecuteCommand("product 0x60", cmd_out));
        EXPECT_EQ(m.bus.PeekByte(0xFFF5u), 0x60u);
        EXPECT_TRUE(m.ExecuteCommand("product auto", cmd_out));
        EXPECT_EQ(m.bus.PeekByte(0xFFF5u), 0x40u);
    }

    // 7. Real 78k0_programmer_fw.bin end-to-end verification (when available in workspace)
    {
        auto m = MakeMachine();
        if (TryLoadProgrammerRomFromRepo(m)) {
            std::vector<uint8_t> ea(k0::Kx2FlashCtrl::kEaSize, 0xFFu);
            for (size_t i = 0; i < 8; ++i) {
                ea[0x0790u + i] = static_cast<uint8_t>(0x30u + i);
            }
            EXPECT_TRUE(m.LoadEaBytes(ea.data(), ea.size()));

            // Distinct user ROM bytes at 0x0100..0x0103 to test FLREG=0x00 main-flash bypass
            WriteBytes(m, 0x0100u, { 0x51u, 0x62u, 0x73u, 0x84u });

            // Stub helpers matching TA-096 (at 0x57AF..0x57FA) + test driver at 0x5500
            WriteBytes(m, 0x57AFu, {
                0x13, 0xC0, 0xA5, 0x13, 0xC4, 0x01, 0x13, 0xC4, 0xFE, 0x13, 0xC4, 0x01, 0xAF,  // enable_programmer (0x57AF)
                0x13, 0xC0, 0xA5, 0x13, 0xC4, 0x00, 0x13, 0xC4, 0xFF, 0x13, 0xC4, 0x00, 0xAF,  // disable_programmer (0x57BC)
                0x22, 0xB1, 0x61, 0xF8, 0xB6, 0xA2, 0x00, 0x9A, 0x00, 0x81,
                0xA1, 0x09, 0xBE, 0x13, 0xBE, 0x14, 0x23, 0xAF,                                // rom_func_0 (0x57C9)
                0x22, 0x61, 0xF8, 0xA2, 0x0E, 0x9A, 0x00, 0x81, 0x23,
                0xF0, 0xE3, 0x72, 0xA3, 0x00, 0xAF,                                            // rom_func_E (0x57DB)
                0x22, 0xB1, 0x61, 0xF8, 0xB6, 0xA2, 0x0F, 0x9A, 0x00, 0x81, 0x23,
                0xF0, 0xE3, 0x72, 0xA3, 0x00, 0xAF,                                            // rom_func_F (0x57EA)
            });

            // Driver at 0x5500:
            // enable_programmer -> rom_func_0(0xFD60) -> rom_func_E (store C to 0xFD4F)
            // -> rom_func_F(EA 0x0790 -> 0xFD58) -> rom_func_F(EA 0x0794 -> 0xFD5C)
            // -> rom_func_F(MAIN 0x0100 -> 0xFD50) -> disable_programmer -> brk
            WriteBytes(m, 0x5500u, {
                0x9A, 0xAF, 0x57,              // call !enable_programmer
                0x10, 0x60, 0xFD,              // movw AX, #0xFD60
                0x9A, 0xC9, 0x57,              // call !rom_func_0
                0x9A, 0xDB, 0x57,              // call !rom_func_E
                0x62,                          // mov A, C
                0x9E, 0x4F, 0xFD,              // mov !0xFD4F, A

                // EA read #1: 0x0790 -> 0xFD58
                0x10, 0x90, 0x07, 0x03, 0x60, 0xFD,
                0x10, 0x00, 0xFF, 0x03, 0x62, 0xFD,
                0x10, 0x58, 0xFD, 0x03, 0x64, 0xFD,
                0x10, 0x60, 0xFD, 0x9A, 0xEA, 0x57,

                // EA read #2: 0x0794 -> 0xFD5C
                0x10, 0x94, 0x07, 0x03, 0x60, 0xFD,
                0x10, 0x5C, 0xFD, 0x03, 0x64, 0xFD,
                0x10, 0x60, 0xFD, 0x9A, 0xEA, 0x57,
                0x62, 0x9E, 0x4E, 0xFD,        // save last status C to 0xFD4E

                // Main flash read: addr=0x0100, flag=0x00 -> 0xFD50
                0x10, 0x00, 0x01, 0x03, 0x60, 0xFD,
                0x10, 0x00, 0x00, 0x03, 0x62, 0xFD,
                0x10, 0x50, 0xFD, 0x03, 0x64, 0xFD,
                0x10, 0x60, 0xFD, 0x9A, 0xEA, 0x57,
                0x62, 0x9E, 0x4D, 0xFD,        // save main-flash status C to 0xFD4D

                0x9A, 0xBC, 0x57,              // call !disable_programmer
                0xBF,                          // brk
            });

            m.cpu.SetSP(0xFECEu);
            m.cpu.stop_on_brk = true;
            m.cpu.SetPC(0x5500u);
            const auto s1 = m.RunSteps(200000);
            EXPECT_EQ(static_cast<int>(s1.reason), static_cast<int>(k0::StopReason::BreakInsn));
            EXPECT_EQ(m.bus.PeekByte(0xFD4Fu), 0x00u);  // CheckFLMD_E == 0
            EXPECT_EQ(m.bus.PeekByte(0xFD4Eu), 0x00u);  // EA read status == 0
            EXPECT_EQ(m.bus.PeekByte(0xFD4Du), 0x00u);  // Main flash read status == 0
            for (size_t i = 0; i < 8; ++i) {
                EXPECT_EQ(m.bus.PeekByte(static_cast<uint16_t>(0xFD58u + i)),
                          static_cast<uint8_t>(0x30u + i));
            }
            EXPECT_EQ(m.bus.PeekByte(0xFD50u), 0x51u);
            EXPECT_EQ(m.bus.PeekByte(0xFD51u), 0x62u);
            EXPECT_EQ(m.bus.PeekByte(0xFD52u), 0x73u);
            EXPECT_EQ(m.bus.PeekByte(0xFD53u), 0x84u);
            EXPECT_EQ(m.bus.GetProgOverlayMask(), 0u);
            EXPECT_EQ(m.bus.PeekByte(0xFFC4u) & 0x03u, 0u);

            // Also verify CheckFLMD_E returns 1 when FLMD0 pin is low
            m.Reset(0x5500);
            m.cpu.SetSP(0xFECEu);
            m.cpu.stop_on_brk = true;
            m.flash.SetFlmd0Mode(k0::Kx2FlashCtrl::Flmd0Mode::Low);
            const auto s2 = m.RunSteps(200000);
            EXPECT_EQ(static_cast<int>(s2.reason), static_cast<int>(k0::StopReason::BreakInsn));
            EXPECT_EQ(m.bus.PeekByte(0xFD4Fu), 0x01u);  // CheckFLMD_E == 1
        }
    }
}

}  // namespace

int main() {
    TestResetAndRegisterBanks();
    TestAluMulDivBcdAndShifts();
    TestBitOpsBranchesCallsAndCycles();
    TestInterruptsPriorityHoldAndStandbyWakeup();
    TestKx2Peripherals();
    TestBreakpointsWatchpointsDisasmAndGdb();
    TestProgrammerRomAndEaFlash();

    if (g_failures == 0) {
        std::printf("[PASS] All k0emu C++ tests passed.\n");
        return 0;
    }
    std::fprintf(stderr, "[FAIL] %d assertion(s) failed.\n", g_failures);
    return 1;
}
