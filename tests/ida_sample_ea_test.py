import ctypes
import json
import os
import traceback

import ida_auto
import ida_dbg
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro
import idc

REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "build",
    "ida_ta096_ea_report.json",
)


def default_plugin_ea_path():
    appdata = os.environ.get("APPDATA", "")
    return os.path.join(appdata, "Hex-Rays", "IDA Pro", "plugins", "EA.bin")


def eval_idc(expr_str):
    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, expr_str)
    if err:
        raise RuntimeError(f"eval_idc_expr({expr_str!r}) failed: {err}")
    if rv.vtype == ida_expr.VT_STR:
        return rv.c_str()
    if rv.vtype == ida_expr.VT_INT64:
        return int(rv.i64)
    return int(rv.num)


def run_tests():
    ida_auto.auto_wait()
    report = {
        "ok": False,
        "flash_before": "",
        "flash_after": "",
        "checks": {},
        "errors": [],
    }

    try:
        ea_path = os.environ.get("K0EMU_TEST_EA_PATH") or default_plugin_ea_path()
        with open(ea_path, "rb") as fp:
            ea_data = fp.read()
        assert len(ea_data) == 0x800, f"Expected 0x800-byte EA.bin, got {len(ea_data)} bytes"

        loaded = ida_dbg.load_debugger("k0emu", False) or ida_dbg.load_debugger("k0dbg.dll", False)
        if not loaded:
            ida_loader.load_plugin("k0dbg")
            loaded = ida_dbg.load_debugger("k0emu", False) or ida_dbg.load_debugger("k0dbg.dll", False)
        assert loaded, "Failed to load k0emu debugger backend"

        started = ida_dbg.start_process("", "", "")
        assert started == 1, f"start_process returned {started}"
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP

        flash_before = eval_idc('k0dbg_exec("flash")')
        report["flash_before"] = flash_before
        assert "ProgROM=loaded" in flash_before, f"Programmer ROM not auto-loaded: {flash_before!r}"
        assert "EA=loaded" in flash_before, f"EA.bin not auto-loaded: {flash_before!r}"
        assert "PROD(FFF5)=40" in flash_before, f"Unexpected PROD ID: {flash_before!r}"
        assert ida_dbg.get_reg_val("PROD") == 0x40

        # Prepare call to sub_5637 (0x5637) with sentinel return address 0x0200 at SP=0xFECE.
        ret_addr = 0x0200
        sp_init = 0xFECE
        assert ida_dbg.put_dbg_byte(sp_init, ret_addr & 0xFF)
        assert ida_dbg.put_dbg_byte(sp_init + 1, (ret_addr >> 8) & 0xFF)
        assert ida_dbg.set_reg_val("SP", sp_init)
        assert ida_dbg.set_reg_val("PC", 0x5637)

        # Break at 0x56B0 (right after all four user_programmer_access copies, before encryption).
        assert ida_dbg.add_bpt(0x56B0)
        assert ida_dbg.add_bpt(ret_addr)
        assert ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc_mid = ida_dbg.get_reg_val("PC")
        report["checks"]["pc_at_56b0"] = hex(pc_mid)
        assert pc_mid == 0x56B0, f"Expected stop at 0x56B0, got {hex(pc_mid)}"
        assert ida_dbg.del_bpt(0x56B0)

        slices = [
            ("ea_0790_at_f600", 0xF600, 0x0790),
            ("ea_0798_at_f618", 0xF618, 0x0798),
            ("ea_07c0_at_f5e0", 0xF5E0, 0x07C0),
            ("ea_07c8_at_f5e8", 0xF5E8, 0x07C8),
        ]
        for label, ram_ea, ea_off in slices:
            got = idc.get_bytes(ram_ea, 8, True)
            exp = ea_data[ea_off : ea_off + 8]
            report["checks"][label] = {"got": got.hex(), "expected": exp.hex()}
            assert got == exp, f"{label} mismatch: got {got.hex()}, expected {exp.hex()}"

        flpmc_mid = ida_dbg.get_reg_val("FLPMC")
        report["checks"]["flpmc_after_access"] = hex(flpmc_mid)
        assert (flpmc_mid & 0x03) == 0, f"Expected overlay unmapped, got FLPMC={hex(flpmc_mid)}"

        flash_mid = eval_idc('k0dbg_exec("flash")')
        report["checks"]["flash_mid"] = flash_mid
        assert "reads=16 " in flash_mid, f"Expected 16 strobe latches (8 calls x 2 pulses) after sub_5637 copy stage, got: {flash_mid!r}"

        # Direct call check for user_programmer_access (0x55CF) with AX = 0x0790.
        direct_ret = 0x5637
        assert ida_dbg.put_dbg_byte(sp_init, direct_ret & 0xFF)
        assert ida_dbg.put_dbg_byte(sp_init + 1, (direct_ret >> 8) & 0xFF)
        assert ida_dbg.set_reg_val("SP", sp_init)
        assert ida_dbg.set_reg_val("AX", 0x0790)
        assert ida_dbg.set_reg_val("PC", 0x55CF)
        assert ida_dbg.del_bpt(ret_addr)
        assert ida_dbg.add_bpt(direct_ret)
        assert ida_dbg.continue_process()
        wres = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
        pstate = ida_dbg.get_process_state()
        assert wres and pstate == ida_dbg.DSTATE_SUSP, (
            f"Direct user_programmer_access did not suspend at {hex(direct_ret)} (wres={wres}, state={pstate})"
        )
        pc_end = ida_dbg.get_reg_val("PC")
        bc_end = ida_dbg.get_reg_val("BC")
        direct_bytes = idc.get_bytes(0xFD58, 8, True)
        exp_direct = ea_data[0x0790:0x0798]
        flpmc_end = ida_dbg.get_reg_val("FLPMC")
        report["checks"]["pc_at_ret"] = hex(pc_end)
        report["checks"]["bc_at_ret"] = hex(bc_end)
        report["checks"]["direct_fd58"] = {"got": direct_bytes.hex(), "expected": exp_direct.hex()}
        report["checks"]["flpmc_end"] = hex(flpmc_end)
        assert pc_end == direct_ret, f"Expected return to {hex(direct_ret)}, got {hex(pc_end)}"
        assert bc_end == 0, f"Expected BC=0 status from user_programmer_access, got {hex(bc_end)}"
        assert direct_bytes == exp_direct, f"0xFD58 mismatch: {direct_bytes.hex()} vs {exp_direct.hex()}"
        assert (flpmc_end & 0x03) == 0, f"Expected overlay unmapped, got FLPMC={hex(flpmc_end)}"
        assert ida_dbg.del_bpt(direct_ret)

        flash_after = eval_idc('k0dbg_exec("flash")')
        report["flash_after"] = flash_after
        assert "reads=20 " in flash_after, f"Expected 20 strobe latches (10 calls x 2 pulses), got: {flash_after!r}"

        assert ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        report["ok"] = True
    except Exception as exc:
        report["errors"].append(f"{exc}\n{traceback.format_exc()}")
    finally:
        with open(REPORT_PATH, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
        ida_pro.qexit(0 if report["ok"] else 1)


class _ReadyHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        self.unhook()
        run_tests()


_READY_HOOKS = None

if __name__ == "__main__":
    if ctypes.windll.kernel32.GetModuleHandleW("ida.exe") != 0:
        _READY_HOOKS = _ReadyHooks()
        _READY_HOOKS.hook()
    else:
        run_tests()
