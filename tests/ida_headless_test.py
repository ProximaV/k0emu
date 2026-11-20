import ctypes
import json
import os
import traceback

import ida_auto
import ida_bytes
import ida_dbg
import ida_expr
import ida_ida
import ida_idaapi
import ida_idd
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import idc

REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "build",
    "ida_headless_report.json",
)


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


def disasm_at(ea):
    text = ida_lines.generate_disasm_line(ea, 0)
    if text:
        return ida_lines.tag_remove(text).strip()
    return idc.GetDisasm(ea).strip()


def run_tests():
    ida_auto.auto_wait()
    report = {
        "ok": False,
        "checks": {},
        "segments": [],
        "reg_info": {},
        "ida_dbg": {},
        "step_trace": [],
        "rexec": {},
        "errors": [],
    }

    try:
        # 1. Verify 78K0 processor & IDB segments
        proc_name = ida_ida.inf_get_procname()
        proc_id = ida_idp.ph_get_id()
        report["checks"]["proc_name"] = proc_name
        report["checks"]["proc_id"] = proc_id
        assert proc_name.lower() == "78k0", f"Expected proc_name '78k0', got {proc_name!r}"
        assert proc_id == 38, f"Expected PLFM_NEC_78K0 (38), got {proc_id}"

        seg_names = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue
            sname = ida_segment.get_segm_name(seg)
            seg_names.append(sname)
            report["segments"].append({
                "name": sname,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "perm": seg.perm,
            })
        assert "ROM_" in seg_names, f"Missing ROM_ segment: {seg_names}"
        assert "RAM_" in seg_names, f"Missing RAM_ segment: {seg_names}"

        vec0 = ida_bytes.get_word(0x0000)
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, vec0)
        assert insn_len > 0, f"Failed to decode reset entry insn at {hex(vec0)}"
        report["checks"]["reset_vector"] = hex(vec0)
        report["checks"]["entry_disasm"] = disasm_at(vec0)

        # 2. Verify k0dbg.dll / k0emu debugger backend selection
        was_dbg_on = bool(ida_dbg.is_debugger_on())
        loaded_dbg = ida_dbg.load_debugger("k0emu", False) or ida_dbg.load_debugger("k0dbg.dll", False)
        if not loaded_dbg:
            ida_loader.load_plugin("k0dbg")
            loaded_dbg = ida_dbg.load_debugger("k0emu", False) or ida_dbg.load_debugger("k0dbg.dll", False)
        report["ida_dbg"]["was_debugger_on_before_load"] = was_dbg_on
        report["ida_dbg"]["load_debugger"] = bool(loaded_dbg)
        assert loaded_dbg, "Failed to load k0emu debugger backend"

        # 3. Verify IDA procmod regnames & parse_reg_name for core 78k0 registers
        report["checks"]["ph_regnames"] = list(ida_idp.ph_get_regnames())
        for rname in ["X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE", "HL", "SP", "PSW", "CY"]:
            ri = ida_idp.reg_info_t()
            ok = ida_idp.parse_reg_name(ri, rname)
            assert ok, f"parse_reg_name failed for {rname!r}"
            report["reg_info"][rname] = {"reg": ri.reg, "size": ri.size}

        is_ida_gui = bool(ctypes.windll.kernel32.GetModuleHandleW("ida.exe"))
        report["checks"]["host_exe"] = "ida.exe" if is_ida_gui else "idat.exe"

        # 4. Full ida_dbg execution flow on sample_db.i64
        started = ida_dbg.start_process("", "", "")
        report["ida_dbg"]["start_process"] = int(started)
        assert started == 1, f"start_process returned {started}"
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP, (
            f"Expected suspended state after start_process, got {ida_dbg.get_process_state()}"
        )

        pc0 = ida_dbg.get_reg_val("PC")
        psw0 = ida_dbg.get_reg_val("PSW")
        report["ida_dbg"]["initial_pc"] = hex(pc0)
        report["ida_dbg"]["initial_psw"] = hex(psw0)
        assert pc0 == 0x014E, f"Expected initial PC=0x014E, got {hex(pc0)}"
        assert psw0 == 0x02, f"Expected initial PSW=0x02, got {hex(psw0)}"

        # Verify ev_get_reg_info + ev_read_registers across all register classes & aliases
        dbg_reg_sample = {}
        for dr in ["SP", "AX", "BC", "DE", "HL", "A", "X", "RB", "CY",
                   "RB0_AX", "IF0L", "MK0L", "IMS", "BANK", "PCC", "WDTE",
                   "TM00", "TMHMD0", "WTM", "CYCLES", "R0", "R1", "RP0", "SPL", "SPH"]:
            v = ida_dbg.get_reg_val(dr)
            assert v is not None, f"ida_dbg.get_reg_val({dr!r}) returned None"
            dbg_reg_sample[dr] = hex(v)
        report["ida_dbg"]["dbg_reg_sample"] = dbg_reg_sample

        idb_entry_bytes = ida_bytes.get_bytes(0x014E, 4)
        dbg_entry_bytes = idc.get_bytes(0x014E, 4, True)
        assert dbg_entry_bytes == idb_entry_bytes, (
            f"Live memory mismatch at 0x014E: {dbg_entry_bytes!r} vs {idb_entry_bytes!r}"
        )

        # Single step (step_into)
        assert ida_dbg.step_into()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc1 = ida_dbg.get_reg_val("PC")
        report["ida_dbg"]["pc_after_step_into"] = hex(pc1)
        assert pc1 != pc0, f"step_into did not advance PC (stayed at {hex(pc1)})"

        # Find first call instruction in startup sequence and test step_over
        found_call = False
        for _ in range(40):
            cur = ida_dbg.get_reg_val("PC")
            dline = disasm_at(cur).lower()
            if dline.startswith("call ") or dline.startswith("callf ") or dline.startswith("callt "):
                ins = ida_ua.insn_t()
                ilen = ida_ua.decode_insn(ins, cur)
                assert ilen > 0
                expected_ret = cur + ilen
                assert ida_dbg.step_over(), "step_over failed"
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
                pc_after_over = ida_dbg.get_reg_val("PC")
                report["ida_dbg"]["step_over_call_ea"] = hex(cur)
                report["ida_dbg"]["step_over_expected_pc"] = hex(expected_ret)
                report["ida_dbg"]["step_over_actual_pc"] = hex(pc_after_over)
                assert pc_after_over == expected_ret, (
                    f"step_over from {hex(cur)} landed at {hex(pc_after_over)}, expected {hex(expected_ret)}"
                )
                found_call = True
                break
            assert ida_dbg.step_into()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert found_call, "Did not encounter a call instruction in first 40 startup steps"

        # Continue to main (0x026B)
        main_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "main")
        if main_ea == ida_idaapi.BADADDR:
            main_ea = 0x026B
        report["ida_dbg"]["main_ea"] = hex(main_ea)
        assert ida_dbg.add_bpt(main_ea)
        assert ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc_main = ida_dbg.get_reg_val("PC")
        report["ida_dbg"]["bpt_main_pc"] = hex(pc_main)
        assert pc_main == main_ea, f"Expected breakpoint hit at {hex(main_ea)}, got {hex(pc_main)}"
        assert ida_dbg.del_bpt(main_ea)

        # Continue into main loop (0x02DD right after EI at 0x02DB)
        assert ida_dbg.add_bpt(0x02DD)
        assert ida_dbg.continue_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        pc_loop = ida_dbg.get_reg_val("PC")
        ie_bit = (ida_dbg.get_reg_val("PSW") >> 7) & 1
        report["ida_dbg"]["bpt_loop_pc"] = hex(pc_loop)
        report["ida_dbg"]["ie_at_loop"] = ie_bit
        assert pc_loop == 0x02DD, f"Expected main loop at 0x02DD, got {hex(pc_loop)}"
        assert ie_bit == 1, "Expected PSW.IE == 1 after EI at 0x02DB"
        assert ida_dbg.del_bpt(0x02DD)

        # Verify EXP_RAM copy happened (0xF400 should not be all zero if initialized during startup)
        exp_sample = idc.get_bytes(0xF400, 4, True)
        report["ida_dbg"]["exp_ram_f400"] = exp_sample.hex()

        # Verify register read/write via ida_dbg
        old_ax = ida_dbg.get_reg_val("AX")
        assert ida_dbg.set_reg_val("AX", 0xBEEF)
        assert ida_dbg.get_reg_val("AX") == 0xBEEF
        assert ida_dbg.get_reg_val("A") == 0xBE
        assert ida_dbg.set_reg_val("AX", old_ax)

        # Verify memory R/W in RAM and GPR mirror sync
        old_ram0 = ida_dbg.get_dbg_byte(0xFB80)
        old_ram1 = ida_dbg.get_dbg_byte(0xFB81)
        assert ida_dbg.put_dbg_byte(0xFB80, 0x12)
        assert ida_dbg.put_dbg_byte(0xFB81, 0x34)
        assert idc.get_bytes(0xFB80, 2, True) == b"\x12\x34"
        assert ida_dbg.put_dbg_byte(0xFB80, old_ram0)
        assert ida_dbg.put_dbg_byte(0xFB81, old_ram1)

        old_gpr_x = ida_dbg.get_dbg_byte(0xFEF8)
        assert ida_dbg.put_dbg_byte(0xFEF8, 0x77)
        assert ida_dbg.get_reg_val("X") == 0x77
        assert ida_dbg.put_dbg_byte(0xFEF8, old_gpr_x)

        # Hardware write watchpoint test on next call's stack slot (SP - 2)
        found_call2 = False
        for _ in range(50):
            cur = ida_dbg.get_reg_val("PC")
            dline = disasm_at(cur).lower()
            if dline.startswith("call ") or dline.startswith("callf ") or dline.startswith("callt "):
                sp_before = ida_dbg.get_reg_val("SP")
                wp_addr = (sp_before - 2) & 0xFFFF
                assert ida_dbg.add_bpt(wp_addr, 2, ida_idd.BPT_WRITE)
                assert ida_dbg.continue_process()
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
                assert ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP
                report["ida_dbg"]["watchpoint_addr"] = hex(wp_addr)
                report["ida_dbg"]["watchpoint_stop_pc"] = hex(ida_dbg.get_reg_val("PC"))
                assert ida_dbg.del_bpt(wp_addr)
                found_call2 = True
                break
            assert ida_dbg.step_into()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        assert found_call2, "Did not encounter a call in main loop to trigger stack write watchpoint"

        # Exercise ev_rexec
        rexec_res = ida_dbg.send_dbg_command("status")
        report["rexec"]["send_dbg_command_ok"] = bool(rexec_res is not None)

        assert ida_dbg.exit_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        report["ida_dbg"]["mode"] = "full_ida_dbg_passed"

        # 5. Exercise deterministic k0dbg_* IDC helpers
        entry = eval_idc("k0dbg_start()")
        assert entry == 0x014E, f"Expected k0dbg_start()==0x014E, got {hex(entry)}"

        for sidx in range(6):
            cpc = eval_idc('k0dbg_get_reg("PC")')
            dtext = disasm_at(cpc)
            npc = eval_idc("k0dbg_step(1)")
            report["step_trace"].append({
                "step": sidx,
                "pc": hex(cpc),
                "disasm": dtext,
                "next_pc": hex(npc),
            })

        stopped_main = eval_idc("k0dbg_run_to(0x026B, 100000)")
        assert stopped_main == 0x026B, f"k0dbg_run_to(0x026B) stopped at {hex(stopped_main)}"
        report["checks"]["idc_run_to_main"] = hex(stopped_main)

        assert eval_idc('k0dbg_set_reg("AX", 0xCAFE)') == 1
        assert eval_idc('k0dbg_get_reg("AX")') == 0xCAFE
        assert eval_idc("k0dbg_write_u8(0xFB90, 0xA5)") == 1
        assert eval_idc("k0dbg_read_u8(0xFB90)") == 0xA5
        assert eval_idc("k0dbg_write_u16(0xFB92, 0x1357)") == 1
        assert eval_idc("k0dbg_read_u16(0xFB92)") == 0x1357

        assert eval_idc("k0dbg_add_bpt(0x02DD)") == 1
        bpt_pc = eval_idc("k0dbg_run_to(0xFFFF, 100000)")
        assert bpt_pc == 0x02DD, f"k0dbg_add_bpt(0x02DD) stopped at {hex(bpt_pc)}"
        assert eval_idc("k0dbg_del_bpt(0x02DD)") == 1

        for cmd in ("status", "intc", "clock", "timers", "ports", "map"):
            out = eval_idc(f'k0dbg_exec("{cmd}")')
            report["rexec"][cmd] = out
            assert out and "Unknown" not in out, f"k0dbg_exec({cmd!r}) unexpected: {out!r}"

        assert eval_idc("k0dbg_stop()") == 1
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
