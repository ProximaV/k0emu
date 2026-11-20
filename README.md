# k0emu — NEC 78K0 / 78K0-Kx2 Emulator & Native IDA Pro Debugger Plugin

`k0emu` provides a native C++17 NEC 78K0 (`78K0` / `78K0/Kx2`) CPU emulator core, standalone headless runner and GDB Remote Serial Protocol (RSP) server, unit/integration test suite, and an integrated native IDA Pro 9.x debugger plugin (`k0dbg.dll`).

The original Python reference implementation in `k0emu/` (`bus.py`, `system.py`, `devices.py`, `processor.py`, `run.py`, `k0emu/tests/`) is preserved alongside the C++ engine.

---

## Architecture & Targets

| Component | Source Files | Output | Description |
| --- | --- | --- | --- |
| Core library | `src/cpu.{h,cpp}`, `src/memory.{h,cpp}`, `src/kx2_peripherals.{h,cpp}`, `src/machine.{h,cpp}`, `src/disasm.{h,cpp}`, `src/debugger.{h,cpp}`, `src/log.{h,cpp}` | `k0emu_core.lib` | Cycle-accurate 78K0 CPU, 64 KB + banked memory bus, Kx2 / Legacy 0831Y peripherals, disassembler, CLI command processor, GDB RSP server |
| IDA Debugger Plugin | `src/ida_dbg_plugin.cpp` | `k0dbg.dll` | Native IDA Pro 9.x `PLUGIN_DBG \| PLUGIN_PROC \| PLUGIN_MULTI` debugger backend (`k0emu`) with `HT_IDD`, `HT_IDP`, `HT_UI`, and `k0dbg_*` IDC helpers |
| Standalone CLI / GDB Server | `src/main.cpp` | `k0emu.exe` | Headless ROM runner with optional trace output or GDB RSP TCP server |
| Test Suite | `tests/k0emu_tests.cpp` | `k0emu_tests.exe` | C++ unit and peripheral integration tests registered with CTest |
| Headless IDA Test | `tests/ida_headless_test.py` | `build/ida_headless_report.json` | End-to-end verification under `idat.exe` against `sample_db.i64` |

---

## Hardware Fidelity (78K0 / 78K0-Kx2)

- **CPU Core (`K0Cpu`)**:
  - Complete unprefixed, `0x31`, `0x61`, and `0x71` opcode tables (`MULU X`, `DIVUW C`, `ADJBA`, `ADJBS`, `ROL4`, `ROR4`, `BT`/`BF`/`BTCLR`, `CALL`/`CALLF`/`CALLT`/`BRK`, `RETI`/`RETB`, `SEL RBn`, `HALT`, `STOP`).
  - Four GPR banks (`RB0` at `0xFEF8..0xFEFF` down to `RB3` at `0xFEE0..0xFEE7`), `SP` (`0xFF1C..0xFF1D`), and `PSW` (`0xFF1E`, bit 2 fixed to `0`, reset `0x02`).
  - Exact Note 1 (internal high-speed RAM `0xFB00..0xFEFF`) vs. Note 2 (ROM, `EXP_RAM`, SFR) instruction cycle timing per `78K0KX2.pdf` Ch. 29 (`HALT` / `STOP` = 6 clocks).
  - Interrupt controller prioritization (`ISP` / `PR`), standby wakeup (`HALT`/`STOP`), and 1-instruction interrupt hold following `PSW`, `RETI`, `RETB`, `PUSH PSW`, `POP PSW`, `EI`/`DI`, and `0xFFE0..0xFFEB` accesses.
- **Memory Bus (`K0Bus`)**:
  - 64 KB address space with common ROM, optional 96/128 KB banked flash window (`0x8000..0xBFFF` via `BANK` `0xFFF3`), `EXP_RAM`, high-speed internal RAM (`0xFB00..0xFEDF`), GPRs (`0xFEE0..0xFEFF`), and SFR dispatch (`0xFF00..0xFFFF`).
  - Separated CPU vs. side-effect-free `PeekByte`/`PokeByte`/`ReadDebug`/`WriteDebug` access paths plus read/write/rw watchpoints.
- **Peripherals (`Kx2` default profile & `Legacy0831` compatibility profile)**:
  - `Kx2Intc`: 29 Kx2 interrupt sources / 28 0831Y sources (`IF0L..IF1H`, `MK0L..MK1H`, `PR0L..PR1H`).
  - `Kx2Clock`: `OSCCTL`, `RCM`, `MCM`, `MOC`, `OSTC`, `OSTS`, `PCC`.
  - `Kx2SystemCtrl`: `IMS`, `IXS`, `BANK`, `RESF`, `LVIM`, `LVIS`, `PFCMD`, `FLPMC`.
  - `Kx2Wdt`: Option byte (`0x0080`) enable/interval configuration, `WDTE=0xAC` kick, overflow reset (`RESF.WDTRF`), plus legacy `WDCS`/`WDTM`.
  - `Kx2Ports`: `P*`/`PM*`/`PU*`, `EGP`/`EGN` (`INTP*` edge interrupts), `KRM`, `ISC`, `ADPC`.
  - Timers: `TM00`/`TM01` (16-bit), `TM50`/`TM51` (8-bit), `TMH0`/`TMH1` (8-bit H timers), `WTM` (Watch Timer).
  - `Kx2Adc`, `Kx2Uart6`, `Kx2Uart0`, `Kx2Csi` (`CSI10`/`CSI11`), `Kx2Iic0` (`IICS0` Kx2 & 0831Y flag layouts), `Kx2MulDiv`.

---

## Building & Installing

Configure and build Release x64 from the project root. `IDA_SDK_DIR` automatically resolves to `../..` when placed under `src/plugins/k0emu`, or you can pass `-DIDA_SDK_DIR=<path-to-ida-sdk>/src`:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 "-DIDA_SDK_DIR=../.."
cmake --build build --config Release
```

To install the plugin into IDA Pro:

```powershell
Copy-Item -Force .\build\Release\k0dbg.dll "$env:APPDATA\Hex-Rays\IDA Pro\plugins\k0dbg.dll"
```

`k0dbg.dll` activates automatically on NEC 78K0 databases (`PLFM_NEC_78K0` / `"78k0"`), auto-detects memory layout from IDB segments and device name (`"$ 78k0"`), loads initialized segments below `0xFF00`, and resets to the `[0x0000]` reset vector (or `start_ip` / `main` / `RESET`).

---

## Standalone CLI & GDB RSP Usage

```text
Usage: k0emu [options]
Options:
  --rom <path>           ROM binary to load at 0x0000
  --profile <kx2|0831y>  Hardware profile (default: kx2)
  --pc <addr>            Override initial PC (default: reset vector [0x0000])
  --sp <addr>            Override initial SP (default: 0x0000)
  --trace                Print instruction trace during headless run
  --max-steps <n>        Maximum instructions in headless mode (0 = unlimited)
  --map                  Print memory map and exit
  --gdb, -g              Start GDB RSP server
  --gdb-port <port>      GDB RSP TCP port (default: 23946, implies --gdb)
  --headless             Run headless (default)
  --help, -h             Show this help message
```

---

## IDA Debugger Commands & IDC Helpers

### Debugger CLI (`ev_rexec` / GDB `monitor`)

In IDA's debugger CLI bar (`k0emu`) or via `ida_dbg.send_dbg_command(...)` / GDB `qRcmd`:

- `help` / `?` — List available commands
- `status`, `banks`, `intc`, `clock`, `timers`, `ports`, `map` — Inspect CPU, GPR banks, INTC, clocks/WDT, timers, GPIOs, and memory map
- `disasm [addr] [count]` — Disassemble instructions at `addr` (hex) or current `PC`
- `step [n]` — Step `n` instructions
- `irq <name|idx>` — Raise an interrupt request (e.g. `irq INTP0`)
- `pin <port> <bit> <0|1>` — Set external GPIO input level
- `adc <ch> <val10>` — Set 10-bit ADC channel value
- `uart6rx <hex|ascii>`, `uart6tx` — Inject UART6 RX byte / inspect TX buffer
- `bank <n>` — Switch active flash memory bank (`0..5`)

### Registered IDC Functions

- `k0dbg_start()`, `k0dbg_stop()`
- `k0dbg_step(count)`, `k0dbg_run_to(target_ea, max_steps)`
- `k0dbg_get_reg(name)`, `k0dbg_set_reg(name, val)`
- `k0dbg_read_u8(addr)`, `k0dbg_write_u8(addr, val)`
- `k0dbg_read_u16(addr)`, `k0dbg_write_u16(addr, val)`
- `k0dbg_add_bpt(addr)`, `k0dbg_del_bpt(addr)`
- `k0dbg_exec(cmd)`

---

## Running Tests

```powershell
# C++ unit & peripheral integration tests
.\build\Release\k0emu_tests.exe
ctest --test-dir build -C Release --output-on-failure

# Headless IDA Pro 9.5 integration test against sample_db.i64
Copy-Item -Force .\sample_db.i64 .\build\sample_db_test.i64
idat.exe -A -S".\tests\ida_headless_test.py" ".\build\sample_db_test.i64"
```
