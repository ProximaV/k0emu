#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "cpu.h"
#include "memory.h"

namespace k0 {

// ============================================================================
// Interrupt Controller (0xFFE0..0xFFEB) - Kx2 (29 sources) & Legacy0831 (28 sources)
// ============================================================================

struct IrqSourceDef {
    uint8_t index;
    uint8_t reg_offset;  // 0=IF0L, 1=IF0H, 2=IF1L, 3=IF1H
    uint8_t bit_mask;
    uint16_t vector_addr;
    const char *name;
};

class Kx2Intc final : public InterruptControllerBase {
public:
    explicit Kx2Intc(MachineProfile profile = MachineProfile::Kx2);

    void SetProfile(MachineProfile profile);

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;

    PendingInterrupt EvaluatePending() const override;
    bool HasUnmaskedPending() const override;
    void Acknowledge(uint8_t source_index) override;

    void RaiseIrq(uint8_t source_index);
    void ClearIrq(uint8_t source_index);
    int FindIrqByName(const char *name) const;
    const std::vector<IrqSourceDef> &Sources() const { return sources_; }

private:
    MachineProfile profile_ = MachineProfile::Kx2;
    std::vector<IrqSourceDef> sources_;
    std::array<uint8_t, 12> regs_{};  // 0..3 IF, 4..7 MK, 8..11 PR
};

// ============================================================================
// Clock Generator (0xFF9F..0xFFA4, 0xFFFB)
// ============================================================================

class Kx2Clock final : public PeripheralDevice, public K0ClockSource {
public:
    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    void OnEnterStop() override;
    void OnExitStop() override;
    void ComputeSubClocks(uint32_t cpu_cycles,
                          bool in_halt,
                          bool in_stop,
                          uint32_t *prs_cycles_out,
                          uint32_t *sub_cycles_out,
                          uint32_t *rl_cycles_out) override;

    uint8_t GetOscctl() const { return oscctl_; }
    uint8_t GetRcm() const;
    uint8_t GetMcm() const;
    uint8_t GetMoc() const { return moc_; }
    uint8_t GetOstc() const { return ostc_; }
    uint8_t GetOsts() const { return osts_; }
    uint8_t GetPcc() const;

    bool IsLsrStopped() const { return (rcm_ & 0x02u) != 0; }
    bool IsSubClockSelected() const { return (pcc_ & 0x10u) != 0; }

private:
    void UpdateOstc();

    uint8_t oscctl_ = 0x00u;
    uint8_t rcm_ = 0x80u;
    uint8_t mcm_ = 0x00u;
    uint8_t moc_ = 0x80u;
    uint8_t ostc_ = 0x00u;
    uint8_t osts_ = 0x05u;
    uint8_t pcc_ = 0x01u;
    uint32_t sub_acc_ = 0;
    uint32_t rl_acc_ = 0;
    uint32_t ostc_timer_ = 0;
};

// ============================================================================
// System Control / Memory Bank / Reset Flag / LVI (0xFFAC, FFBE, FFBF, FFC0, FFC4, FFF0, FFF3, FFF4)
// ============================================================================

class Kx2SystemCtrl final : public PeripheralDevice {
public:
    explicit Kx2SystemCtrl(K0Bus *bus) : bus_(bus) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;

    void SetResetFlag(uint8_t mask) { resf_ |= mask; }
    void ClearResetFlags() { resf_ = 0; }
    uint8_t GetIms() const { return ims_; }
    uint8_t GetBank() const { return bank_; }
    uint8_t GetIxs() const { return ixs_; }
    uint8_t GetResf() const { return resf_; }
    uint8_t GetLvim() const { return lvim_; }
    uint8_t GetLvis() const { return lvis_; }

private:
    K0Bus *bus_ = nullptr;
    uint8_t ims_ = 0xCFu;
    uint8_t bank_ = 0x00u;
    uint8_t ixs_ = 0x0Cu;
    uint8_t resf_ = 0x00u;
    uint8_t lvim_ = 0x00u;
    uint8_t lvis_ = 0x00u;
    uint8_t pfcmd_ = 0x00u;
    uint8_t flpmc_ = 0x00u;
};

// ============================================================================
// Watchdog Timer (Kx2: 0xFF99 WDTE; Legacy0831: 0xFF42 WDCS / 0xFFF9 WDTM)
// ============================================================================

class Kx2Wdt final : public PeripheralDevice {
public:
    Kx2Wdt(K0Bus *bus, K0Cpu *cpu, Kx2SystemCtrl *sys, Kx2Clock *clk, Kx2Intc *intc)
        : bus_(bus), cpu_(cpu), sys_(sys), clk_(clk), intc_(intc) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    bool IsEnabled() const { return wdton_; }
    uint32_t GetCounter() const { return counter_; }
    uint32_t GetOverflowPeriod() const { return overflow_period_; }
    uint8_t GetOptionByte() const { return option_byte_; }
    bool halt_on_reset = true;

private:
    void TriggerReset();

    K0Bus *bus_ = nullptr;
    K0Cpu *cpu_ = nullptr;
    Kx2SystemCtrl *sys_ = nullptr;
    Kx2Clock *clk_ = nullptr;
    Kx2Intc *intc_ = nullptr;

    // Kx2 state (0xFF99)
    uint8_t option_byte_ = 0x00u;
    bool wdton_ = false;
    bool lsrosc_ = false;
    uint8_t wdcs_ = 7u;
    uint8_t window_ = 3u;
    bool kicked_once_ = false;
    uint32_t counter_ = 0;
    uint32_t overflow_period_ = (1u << 17);

    // Legacy 0831Y state (0xFF42 / 0xFFF9)
    uint8_t legacy_wdcs_ = 0;
    uint8_t legacy_wdtm_ = 0;
};

// ============================================================================
// GPIO Ports & Edge/Key Interrupts (P0..P7, P12..P14, PM*, PU*, EGP/EGN/KRM/ISC/ADPC)
// ============================================================================

class Kx2Ports final : public PeripheralDevice {
public:
    explicit Kx2Ports(Kx2Intc *intc) : intc_(intc) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;

    void SetExternalInput(uint8_t port, uint8_t pin, bool high);
    void SetExternalPortByte(uint8_t port, uint8_t value);
    uint8_t GetPinState(uint8_t port) const;
    uint8_t GetLatch(uint8_t port) const { return (port < 15) ? latch_[port] : 0; }
    uint8_t GetMode(uint8_t port) const { return (port < 15) ? mode_[port] : 0xFFu; }
    uint8_t GetExternalInput(uint8_t port) const { return (port < 15) ? ext_in_[port] : 0xFFu; }

private:
    void CheckEdgeIntp(uint8_t port, uint8_t pin, bool old_high, bool new_high);

    Kx2Intc *intc_ = nullptr;
    std::array<uint8_t, 15> latch_{};
    std::array<uint8_t, 15> mode_{};
    std::array<uint8_t, 15> pullup_{};
    std::array<uint8_t, 15> ext_in_{};
    uint8_t adpc_ = 0;
    uint8_t egp_ = 0;
    uint8_t egn_ = 0;
    uint8_t isc_ = 0;
    uint8_t krm_ = 0;
};

// ============================================================================
// 16-bit Timer/Event Counter (TM00 / TM01)
// ============================================================================

class Kx2Timer16 final : public PeripheralDevice {
public:
    Kx2Timer16(uint8_t ch, Kx2Intc *intc, uint8_t irq_cmp0, uint8_t irq_cmp1)
        : ch_(ch), intc_(intc), irq_cmp0_(irq_cmp0), irq_cmp1_(irq_cmp1) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    uint16_t GetCounter() const { return tm_; }
    uint16_t GetCr0() const { return cr0_; }
    uint16_t GetCr1() const { return cr1_; }
    uint8_t GetTmc() const { return tmc_; }
    uint8_t GetPrm() const { return prm_; }

private:
    uint32_t PrescalerDivisor() const;

    uint8_t ch_ = 0;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_cmp0_ = 0;
    uint8_t irq_cmp1_ = 0;

    uint16_t tm_ = 0;
    uint16_t cr0_ = 0;
    uint16_t cr1_ = 0;
    uint8_t tmc_ = 0;
    uint8_t prm_ = 0;
    uint8_t crc_ = 0;
    uint8_t toc_ = 0;
    uint32_t prescaler_acc_ = 0;
};

// ============================================================================
// 8-bit Timer/Event Counter (TM50 / TM51)
// ============================================================================

class Kx2Timer8 final : public PeripheralDevice {
public:
    Kx2Timer8(uint8_t ch, Kx2Intc *intc, uint8_t irq_match)
        : ch_(ch), intc_(intc), irq_match_(irq_match) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    uint8_t GetCounter() const { return tm_; }
    uint8_t GetCompare() const { return cr_; }
    uint8_t GetTmc() const { return tmc_; }

private:
    uint32_t PrescalerDivisor() const;

    uint8_t ch_ = 0;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_match_ = 0;

    uint8_t tm_ = 0;
    uint8_t cr_ = 0;
    uint8_t tcl_ = 0;
    uint8_t tmc_ = 0;
    uint32_t prescaler_acc_ = 0;
};

// ============================================================================
// 8-bit Timer H (TMH0 / TMH1)
// ============================================================================

class Kx2TimerH final : public PeripheralDevice {
public:
    Kx2TimerH(uint8_t ch, Kx2Intc *intc, uint8_t irq_match)
        : ch_(ch), intc_(intc), irq_match_(irq_match) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    uint8_t GetCounter() const { return cnt_; }
    uint8_t GetCmp0() const { return cmp0_; }
    uint8_t GetCmp1() const { return cmp1_; }
    uint8_t GetMode() const { return tmhmd_; }

private:
    uint8_t ch_ = 0;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_match_ = 0;

    uint8_t cnt_ = 0;
    uint8_t cmp0_ = 0;
    uint8_t cmp1_ = 0;
    uint8_t tmhmd_ = 0;
    uint8_t tmcyc1_ = 0;
    uint32_t prescaler_acc_ = 0;
};

// ============================================================================
// Watch Timer (Kx2: 0xFF6F WTM; Legacy0831: 0xFF41 WTNM0)
// ============================================================================

class Kx2WatchTimer final : public PeripheralDevice {
public:
    Kx2WatchTimer(MachineProfile profile, Kx2Intc *intc, uint8_t irq_wti, uint8_t irq_wt)
        : profile_(profile), intc_(intc), irq_wti_(irq_wti), irq_wt_(irq_wt) {}

    void SetProfile(MachineProfile profile, uint8_t irq_wti, uint8_t irq_wt);

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    uint8_t GetWtm() const { return wtm_; }
    uint32_t GetPrescalerCounter() const { return prescaler_counter_; }

private:
    uint32_t PrescalerIntervalPrs() const;
    uint32_t WatchIntervalPrs() const;

    MachineProfile profile_ = MachineProfile::Kx2;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_wti_ = 18;
    uint8_t irq_wt_ = 21;

    uint8_t wtm_ = 0;
    uint32_t prescaler_counter_ = 0;
    uint32_t watch_counter_ = 0;
};

// ============================================================================
// A/D Converter (Kx2: ADCR/ADCRH/ADM/ADS; Legacy0831: ADCR00/ADM00/ADS00)
// ============================================================================

class Kx2Adc final : public PeripheralDevice {
public:
    Kx2Adc(MachineProfile profile, Kx2Intc *intc, uint8_t irq_ad)
        : profile_(profile), intc_(intc), irq_ad_(irq_ad) {
        channels_.fill(0x0200u);
    }

    void SetProfile(MachineProfile profile, uint8_t irq_ad);
    void SetChannelValue(uint8_t ch, uint16_t val10);
    uint16_t GetChannelValue(uint8_t ch) const { return channels_[ch & 7u]; }

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

private:
    MachineProfile profile_ = MachineProfile::Kx2;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_ad_ = 16;

    std::array<uint16_t, 8> channels_{};
    uint16_t adcr_ = 0;
    uint8_t adm_ = 0;
    uint8_t ads_ = 0;
    uint32_t conv_ticks_ = 0;
    bool converting_ = false;
};

// ============================================================================
// UART6 (0xFF0A/0B/50/53/55..58) & UART0 (0xFF70..74)
// ============================================================================

class Kx2Uart6 final : public PeripheralDevice {
public:
    Kx2Uart6(Kx2Intc *intc, uint8_t irq_rx, uint8_t irq_tx, uint8_t irq_err)
        : intc_(intc), irq_rx_(irq_rx), irq_tx_(irq_tx), irq_err_(irq_err) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    void InjectRxByte(uint8_t byte);
    const std::vector<uint8_t> &TxLog() const { return tx_log_; }
    void ClearTxLog() { tx_log_.clear(); }
    void SetTxCallback(std::function<void(uint8_t)> cb) { tx_cb_ = std::move(cb); }

private:
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_rx_ = 8;
    uint8_t irq_tx_ = 9;
    uint8_t irq_err_ = 7;

    uint8_t rxb_ = 0xFFu;
    uint8_t txb_ = 0xFFu;
    uint8_t asim_ = 0x01u;
    uint8_t asis_ = 0x00u;
    uint8_t asif_ = 0x00u;
    uint8_t cksr_ = 0x00u;
    uint8_t brgc_ = 0xFFu;
    uint8_t asicl_ = 0x16u;
    bool rx_unread_ = false;
    uint32_t tx_ticks_left_ = 0;
    std::vector<uint8_t> tx_log_;
    std::function<void(uint8_t)> tx_cb_;
};

class Kx2Uart0 final : public PeripheralDevice {
public:
    Kx2Uart0(Kx2Intc *intc, uint8_t irq_rx, uint8_t irq_tx)
        : intc_(intc), irq_rx_(irq_rx), irq_tx_(irq_tx) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

    void InjectRxByte(uint8_t byte);
    const std::vector<uint8_t> &TxLog() const { return tx_log_; }
    void ClearTxLog() { tx_log_.clear(); }

private:
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_rx_ = 17;
    uint8_t irq_tx_ = 10;

    uint8_t asim_ = 0x01u;
    uint8_t brgc_ = 0x1Fu;
    uint8_t rxb_ = 0xFFu;
    uint8_t asis_ = 0x00u;
    uint8_t txs_ = 0xFFu;
    bool tx_busy_ = false;
    uint32_t tx_ticks_left_ = 0;
    std::vector<uint8_t> tx_log_;
};

// ============================================================================
// CSI10 / CSI11 (3-wire SPI)
// ============================================================================

class Kx2Csi final : public PeripheralDevice {
public:
    using SpiCallback = std::function<uint8_t(uint8_t tx)>;

    Kx2Csi(uint8_t ch, MachineProfile profile, Kx2Intc *intc, uint8_t irq_xfer)
        : ch_(ch), profile_(profile), intc_(intc), irq_xfer_(irq_xfer) {}

    void SetProfile(MachineProfile profile, uint8_t irq_xfer);
    void SetSpiCallback(SpiCallback cb) { spi_cb_ = std::move(cb); }

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;

private:
    void DoTransfer(uint8_t tx);

    uint8_t ch_ = 0;
    MachineProfile profile_ = MachineProfile::Kx2;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_xfer_ = 10;

    uint8_t sio_ = 0x00u;
    uint8_t sotb_ = 0x00u;
    uint8_t csim_ = 0x00u;
    uint8_t csic_ = 0x00u;
    SpiCallback spi_cb_;
};

// ============================================================================
// IIC0 (Kx2: 0xFFA5..0xFFAB; Legacy0831: 0xFF1F, 0xFFA8..0xFFAA)
// ============================================================================

class I2cTargetDevice {
public:
    virtual ~I2cTargetDevice() = default;
    virtual void I2cStart(bool is_read) = 0;
    virtual void I2cStop() = 0;
    virtual uint8_t I2cRead() = 0;
    virtual bool I2cWrite(uint8_t byte) = 0;
};

class Kx2Iic0 final : public PeripheralDevice {
public:
    Kx2Iic0(MachineProfile profile, Kx2Intc *intc, uint8_t irq_iic)
        : profile_(profile), intc_(intc), irq_iic_(irq_iic) {}

    void SetProfile(MachineProfile profile, uint8_t irq_iic);
    void AddTarget(uint8_t addr7, I2cTargetDevice *target);

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;

private:
    void WriteIicc0(uint8_t val);
    void DoStart();
    void DoStop();
    void DoNextByte();

    MachineProfile profile_ = MachineProfile::Kx2;
    Kx2Intc *intc_ = nullptr;
    uint8_t irq_iic_ = 24;

    std::unordered_map<uint8_t, I2cTargetDevice *> targets_;
    I2cTargetDevice *active_target_ = nullptr;

    uint8_t iic0_ = 0;
    uint8_t iicc0_ = 0;
    uint8_t sva0_ = 0;
    uint8_t iiccl0_ = 0;
    uint8_t iicx0_ = 0;
    uint8_t iics0_ = 0;
    uint8_t iicf0_ = 0;
    bool is_read_ = false;
    bool waiting_ = false;
    bool start_pending_ = false;
};

// ============================================================================
// Multiplier/Divider (0xFF60..0xFF68)
// ============================================================================

class Kx2MulDiv final : public PeripheralDevice {
public:
    Kx2MulDiv(Kx2Intc *intc, uint8_t irq_dmu)
        : intc_(intc), irq_dmu_(irq_dmu) {}

    uint8_t Read(uint16_t addr) override;
    void Write(uint16_t addr, uint8_t value) override;
    uint8_t Peek(uint16_t addr) const override;
    void Poke(uint16_t addr, uint8_t value) override;
    void Reset() override;
    void Tick(uint32_t cpu_cycles, uint32_t prs_cycles, uint32_t sub_cycles,
              uint32_t rl_cycles, bool in_halt, bool in_stop) override;

private:
    void CompleteOperation();

    Kx2Intc *intc_ = nullptr;
    uint8_t irq_dmu_ = 24;

    uint16_t sdr0_ = 0;
    uint32_t mda0_ = 0;
    uint16_t mdb0_ = 0;
    uint8_t dmuc0_ = 0;
    uint32_t ticks_left_ = 0;
    bool running_ = false;
};

}  // namespace k0
