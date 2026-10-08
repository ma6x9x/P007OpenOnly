import SwiftUI
import UIKit
import Darwin

struct ContentView: View {
    @State private var text = "Hot: P057 AKS sel0/1 hex. Ident first. One TAP. Prove/parked → More."
    @State private var copiedFlash = false
    @State private var running = false
    @State private var showMore = false
    @State private var kreadSignal = P007Board.shared().kreadSignal

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    Text(text)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        // Cap layout cost — huge recovered logs froze first paint.
                        .lineLimit(running ? 8 : 400)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(.secondarySystemBackground))
                .allowsHitTesting(!running)

                Divider()

                VStack(spacing: 8) {
                    HStack(spacing: 8) {
                        hotButton("P057 AKS slide", id: "p057")
                        hotButton("P050 buflet", id: "p050")
                    }
                    HStack(spacing: 8) {
                        hotButton("64 p017v2", id: "p017v2")
                        hotButton("LuminaKRW", id: "luminakrw")
                    }
                    HStack(spacing: 8) {
                        hotButton("P053 NECP", id: "p053")
                        hotButton("P045 VNOP census", id: "p045")
                    }
                    HStack(spacing: 8) {
                        Button("Ident") { run("ident") }
                            .buttonStyle(.bordered)
                            .disabled(running)
                        Button {
                            showRecoveredLog()
                        } label: {
                            Image(systemName: "doc.text.magnifyingglass")
                        }
                        .buttonStyle(.bordered)
                        .disabled(running)
                        Button {
                            UIPasteboard.general.string = text
                            copiedFlash = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copiedFlash = false }
                        } label: {
                            Image(systemName: copiedFlash ? "checkmark" : "doc.on.doc")
                        }
                        .buttonStyle(.bordered)
                        .disabled(running)
                        Button("More…") { showMore = true }
                            .buttonStyle(.bordered)
                            .disabled(running)
                        if running {
                            ProgressView().controlSize(.small)
                            Button("Unlock") {
                                running = false
                                text = "Manually unlocked UI (probe may still run in background).\n" + text
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        Spacer(minLength: 0)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .navigationTitle("Lumina Lab")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .top, spacing: 0) {
                Text(kreadSignal)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
            }
        }
        // Do NOT scan Documents on first frame — that caused ~1s freeze.
        .preferredColorScheme(.light)
        .sheet(isPresented: $showMore) {
            NavigationStack {
                List {
                    Section("NEW") {
                        moreRow("P057 AKS 65343 sel0/1 hex (not 163-sel, not hasKread)", "p057")
                        moreRow("P050 buflet UAF v3 (not 65349)", "p050")
                        moreRow("P051 gamed/AKS xattr (v3)", "p051")
                        moreRow("P052 nstream extend v2", "p052")
                        moreRow("P053 NECP connect×close v2", "p053")
                        moreRow("P054 APFS reap list", "p054")
                        moreRow("P055 IOSurface UPL", "p055")
                    }
                    Section("ClearSword KRW (phys_oob → PCB)") {
                        moreRow("CS KRW. mapped theory (runKRW, 23F77 offsets)", "cskrw")
                        moreRow("CS calib. phys_oob race only (not KRW)", "cscali")
                    }
                    Section("Prove (23F77 live — Ident first)") {
                        moreRow("0. Device identity + prove matrix", "ident")
                        moreRow("Board JSON + hasKread (p007_board.json)", "board")
                        moreRow("F  82. P009 PathB detach+replace", "p009pathb")
                        moreRow("H  64. p017v2 holder/install", "p017v2")
                        moreRow("K− 62. P010 qleak word1=+0x558", "p010qleak")
                        moreRow("D  84. P040 ns dest create/destroy", "p040")
                        moreRow("W− 83. P038 W-hunt OPEN only", "p038")
                        moreRow("43724 dest MAP only (no #536)", "p041")
                        moreRow("P042. IOGPU type1 sel kptr scan (not #536)", "p042")
                        moreRow("P043. write-class dests + ANE reach", "p043")
                        moreRow("P046. leftover MAP v2 (43722/24, G71 caps, no fire)", "p046")
                        moreRow("P045. APFS VNOP coverage census v16 (not kread)", "p045")
                        moreRow("P022GC v34. Game Center path oracle (not KRW)", "p022GC")
                    }
                    Section("ANE / occupancy") {
                        moreRow("71. P032 ANE OPEN only", "p032")
                        moreRow("72. P033 CoreML 1-in/1-out", "p033")
                        moreRow("73. P034 kmsg 0x820 occupancy", "p034")
                        moreRow("P044. 1-in MobileNet MIL (no evaluate)", "p044")
                        moreRow("P046. leftover MAP v2 (print only)", "p046")
                        moreRow("P045. APFS VNOP coverage census v16", "p045")
                    }
                    Section("64788 ABI extras") {
                        moreRow("F½ 4. P009 detach only (no OOL)", "p009detach")
                        moreRow("80. P009 ranges 0x82", "p009ranges")
                        moreRow("81. P009 types inventory", "p009types")
                    }
                    Section("Parked — do not grind") {
                        moreRow("79. P039 AVE (sandbox wall)", "p039")
                        moreRow("35. P035 AVE wrap", "p035")
                        moreRow("18. P024 NECP (socket lock)", "p024")
                        moreRow("31. P005 JIT disclose", "p005")
                    }
                    Section("Intercepted — tap returns STOP") {
                        moreRow("40. IOGPU close (XR sel)", "iogpu_close")
                        moreRow("54. T014 serial (XR)", "t014a")
                        moreRow("61. P014 close (XR)", "p014close")
                        moreRow("1. P010obj last-ref SURVIVED", "p010obj")
                        moreRow("53. T019 Lookup-nil SURVIVED", "t019")
                    }
                }
                .navigationTitle("All probes")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { showMore = false }
                    }
                }
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
    }

    @ViewBuilder
    private func hotButton(_ title: String, id: String) -> some View {
        Button(title) { run(id) }
            .buttonStyle(.borderedProminent)
            .tint(.purple)
            .controlSize(.regular)
            .frame(maxWidth: .infinity)
            .lineLimit(1)
            .minimumScaleFactor(0.75)
            .disabled(running)
    }

    private func moreRow(_ title: String, _ id: String) -> some View {
        Button(title) {
            showMore = false
            run(id)
        }
    }

    // After panic+reboot: prefer the log for the *last TAP* (p011_tap_log),
    // not whichever *_log.txt happens to have the newest mtime. A completed
    // p024 SURVIVED session often outlives a panicked p017v2 log that never
    // made it to durable storage — that looks like the "wrong" probe.
    func showRecoveredLog() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let fm = FileManager.default

        let tapToLog: [String: String] = [
            "ident": "device_ident_log.txt",
            "board": "p007_board.json",
            "p022GC": "p022_gc_escape_log.txt",
            "ave47map": "ave64747_map_log.txt",
            "ave47ctl": "ave64747_control_log.txt",
            "p035": "p035_ave_wrap_log.txt",
            "p036": "p036_ave_paint_log.txt",
            "p037": "p037_ave_paint_log.txt",
            "p039": "p039_ave_trigger_log.txt",
            "b1p1": "b1b2_lab_log.txt",
            "b1p2": "b1b2_lab_log.txt",
            "b1p3": "b1b2_lab_log.txt",
            "b1p4": "b1b2_lab_log.txt",
            "p005": "p005_probe_log.txt",
            "p017v2": "p017_confused_deputy_log.txt",
            "p017": "p017_legacy_confused_deputy_log.txt",
            "p024": "p024_necp_string_race_log.txt",
            "p025": "p025_necp_string_spray_log.txt",
            "p026": "p026_metal_nq_cite_log.txt",
            "p027": "p027_metal_callback_log.txt",
            "p028": "p028_reentry_a_log.txt",
            "p029": "p029_hammer_log.txt",
            "p030": "p030_two_queue_log.txt",
            "p031": "p031_reclaim_hit_log.txt",
            "p032": "p032_ane_open_log.txt",
            "p038": "p038_w_hunt_log.txt",
            "p040": "p040_ns_dest_log.txt",
            "p041": "p041_slide_dest_map_log.txt",
            "p009pathb": "p009_pathb_log.txt",
            "p009ranges": "p009_ranges_log.txt",
            "p009types": "p009_types_log.txt",
            "p009detach": "p009_detach_log.txt",
            "p033": "p033_coreml_1in1out_log.txt",
            "p042": "p042_reachability_log.txt",
            "p034": "p034_kmsg3072_occupancy_log.txt",
            "p043": "p043_write_class_map_log.txt",
            "p044": "p044_aks_kaslr_reach_log.txt",
            "p057": "p057_aks_deserialize_log.txt",
            "aks": "p057_aks_deserialize_log.txt",
            "p045": "p045_kmsg_recv_oracle_log.txt",
            "p046": "p046_f77_patch_oracle_log.txt",
            "p009iopl": "p009_iopl_merge_log.txt",
            "p010obj": "p010_a14_obj_uaf_log.txt",
            "p010leak": "p010_queue_leak_log.txt",
            "p010qleak": "p010_queue_leak_log.txt",
            "p010qspray": "p010_queuespray.txt",
            "p010remain": "p010_remain.txt",
            "p011v3": "p011_wire_log.txt",
            "p011v4": "p011_v4_log.txt",
            "p011v5": "p011_v5_log.txt",
            "p011v6": "p011_v6_log.txt",
            "p011v7": "p011_v7_log.txt",
            "p011v8": "p011_v8_log.txt",
            "p011v9": "p011_v9_log.txt",
            "p011v10": "p011_v10_log.txt",
            "p012ctx": "p012_ctx_log.txt",
            "p013ave": "p013_ave_log.txt",
            "p001a13vt": "p001_a13_vt_ladder_log.txt",
            "p014ane": "p014_ane_log.txt",
            "p014b": "p014b_ane_log.txt",
            "p014close": "p014_close_method_race_log.txt",
            "p015": "p015_log.txt",
            "p016": "p016_log.txt",
            "p018": "p018_log.txt",
            "p019": "p019_64749_log.txt",
            "p020": "p020_magazine_reclaim_log.txt",
            "p020v2": "p020v2_magazine_drain_log.txt",
            "p021": "p021_agx_stage_mask_log.txt",
            "p022": "p022_cpu0_drain_delay_log.txt",
            "p023": "p023_vt_extreme_log.txt",
            "jpeg_dest": "jpeg_dest_timeout_log.txt",
            "jpeg_fw": "jpeg_fw_decode_log.txt",
            "iogpu_close": "a14_iogpu_close_log.txt",
            "necp": "necp_probe_log.txt",
            "necprace": "necp_race_log.txt",
            "p050": "p050_getattrlist_oob_log.txt",
            "p051": "p051_apfs_xattr_log.txt",
            "p052": "p052_nstream_extend_log.txt",
            "iopl": "iopl_leak_log.txt",
            "aio": "aio_uaf_log.txt",
            "t018": "t018_cow_log.txt",
            "t018shadow": "t018_cow_log.txt",
            "t018ver": "t018_cow_log.txt",
            "t019": "t019_plreq_log.txt",
            "t014a": "t014_close_log.txt",
            "t014b": "t014_close_log.txt",
            "t014c": "t014_close_log.txt",
            "t014d": "t014_close_log.txt",
            "t014e": "t014_close_log.txt",
            "t014f": "t014_close_log.txt",
            "cscali": "racecalib_log.txt",
            "cskrw": "clearsword_krw_log.txt",
            "luminakrw": "lumina_krw_log.txt",
            "OOB PoC": "p050_getattrlist_oob_log.txt",
            "p053": "p053_necp_dfree_log.txt",
            "P053": "p053_necp_dfree_log.txt"
        ]

        var preferredName: String? = nil
        var lastTapId: String? = nil
        let tapURL = docs.appendingPathComponent("p011_tap_log.txt")
        if let tapRaw = try? String(contentsOf: tapURL, encoding: .utf8) {
            for line in tapRaw.split(separator: "\n").reversed() {
                let parts = line.split(separator: " ")
                // "TAP p017v2 <date...>"
                if parts.count >= 2, parts[0] == "TAP" {
                    lastTapId = String(parts[1])
                    preferredName = tapToLog[String(parts[1])]
                    break
                }
            }
        }

        func loadLog(named name: String) -> String? {
            let url = docs.appendingPathComponent(name)
            guard let raw = try? String(contentsOf: url, encoding: .utf8), !raw.isEmpty else { return nil }
            return Self.lastLogSession(raw)
        }

        if let name = preferredName, let body = loadLog(named: name) {
            text = "=== RECOVERED (last TAP \(lastTapId ?? "?") → \(name)) ===\n"
                + P007Board.shared().kreadSignal + "\n"
                + body
                + "\n=== end ===\n"
            kreadSignal = P007Board.shared().kreadSignal
            return
        }

        // Fallback: newest mtime among probe logs (old behavior)
        guard let files = try? fm.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        let skip: Set<String> = ["p011_tap_log.txt", "p007_board.json"]
        let mappedNames = Set(tapToLog.values)
        var newest: (url: URL, date: Date)?
        for url in files {
            let name = url.lastPathComponent
            let looksLikeLog = name.hasSuffix("_log.txt") || name.hasSuffix("log.txt")
                || mappedNames.contains(name)
            guard looksLikeLog else { continue }
            guard !skip.contains(name) else { continue }
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))
                .flatMap(\.contentModificationDate) ?? .distantPast
            if newest == nil || date > newest!.date {
                newest = (url, date)
            }
        }
        guard let win = newest,
              let raw = try? String(contentsOf: win.url, encoding: .utf8),
              !raw.isEmpty else {
            if let tid = lastTapId {
                text = "=== RECOVERED ===\n"
                    + "Last TAP was \(tid), but its log file is missing/empty "
                    + "(common after panic before F_FULLFSYNC).\n"
                    + "Check ips PC; re-run that probe after install.\n"
                    + "=== end ===\n"
            }
            return
        }

        let body = Self.lastLogSession(raw)
        var note = ""
        if let tid = lastTapId, preferredName != nil, win.url.lastPathComponent != preferredName {
            note = "(NOTE: last TAP was \(tid) → wanted \(preferredName!); "
                + "showing newest durable log instead — often an older completed p024.)\n"
        }
        text = "=== RECOVERED (newest mtime: \(win.url.lastPathComponent)) ===\n"
            + note
            + body
            + "\n=== end ===\n"
    }

    /// Last *run* only. Do NOT split on `=== verdict` — that ate the full log.
    /// Session headers look like: `=== p025 session … ===` / `=== p024 v7 session … ===`
    static func lastLogSession(_ full: String) -> String {
        let trimmed = full.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return trimmed }
        let lines = trimmed.split(separator: "\n", omittingEmptySubsequences: false)
        var sessionStarts: [Int] = []
        for (i, line) in lines.enumerated() {
            let s = line.trimmingCharacters(in: .whitespaces)
            // Real session banner: starts with === and contains "session"
            if s.hasPrefix("==="), s.lowercased().contains("session") {
                sessionStarts.append(i)
            }
        }
        guard let start = sessionStarts.last else { return trimmed }
        return lines[start...].joined(separator: "\n")
    }

    static func readFreshLog(named name: String, missing: String) -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let path = docs.appendingPathComponent(name)
        guard let raw = try? String(contentsOf: path, encoding: .utf8), !raw.isEmpty else {
            return missing
        }
        // Probes truncate per run ("w"); still strip older appended sessions if any.
        return lastLogSession(raw)
    }

    // Append a tap marker to the race log with F_FULLFSYNC (the only
    // panic-surviving flush on Apple platforms) BEFORE dispatching the test.
    // After a panic: marker present but no START line = the ObjC entry never ran.
    func logTap(_ id: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let lp = docs.appendingPathComponent("p011_tap_log.txt")
        let fd = open(lp.path, O_CREAT | O_WRONLY | O_APPEND, 0o644)
        if fd >= 0 {
            let s = "TAP \(id) \(LabLocalMilitaryNow() as String)\n"
            s.withCString { write(fd, $0, strlen($0)) }
            fcntl(fd, F_FULLFSYNC)
            close(fd)
        }
    }

    /// Leftover XR / survived / wire-UAF probes. Visible rows still exist so
    /// a mis-tap cannot launch close-vs-method or last-ref UAF.
    func blockedProbeMessage(_ id: String) -> String? {
        switch id {
        case "iogpu_close":
            return "STOP iogpu_close — XR leftover (sel=7-as-create / sel=26-as-submit).\n"
                + "Named 43805 dest is P040: live sel=6 0x410 then sel=7.\n"
                + "Do not run close-vs-method. Not [1].\n"
        case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
            return "STOP T014 — XR leftover close-vs-method / wrong selectors.\n"
                + "23F77 create is sel=6 stIn=0x410. Destroy is sel=7 qid.\n"
                + "Use P040 for dest ABI only.\n"
        case "p014close":
            return "STOP p014close — XR leftover (sel=7 structIn as CREATE).\n"
                + "Not A14 destroy. Do not run close-vs-method.\n"
        case "p010obj":
            return "STOP p010obj — SURVIVED 2026-08-31. Not last-ref UAF. Not KRW.\n"
                + "P010 qleak word1=+0x558 is a small int, not a kptr.\n"
                + "Reconfirmed 2026-09-02. Do not re-tap last-ref.\n"
        case "t019":
            return "STOP t019 — Lookup-nil under lock is XR leak class. exit(0) expected.\n"
                + "Not a 26.5 door. Do not re-tap.\n"
        case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx",
             "p010pduaf", "p010twoconn", "p010pdsweep", "p010krwv2", "p014ane", "p014b", "p015", "p017":
            return "STOP \(id) — leftover wire/UAF race, not in the 23F77 prove set.\n"
                + "Use P009 PathB (F) and p017v2 (H+R+C). Not [1].\n"
        default:
            return nil
        }
    }

    func run(_ id: String) {
        if let stop = blockedProbeMessage(id) {
            logTap(id)
            text = stop
            return
        }

        // p022GC: GameKit can dispatch_sync main while wedged in XPC. Never hold
        // running=true across that — UI stays usable; poll log with magnifying glass.
        if id == "p022GC" {
            logTap(id)
            text = "p022GC v34 — Game Center path oracle. Client write proven earlier.\n"
                + "Want load_raw>=0 or load_over!=client len. NOT KRW.\n"
                + "Log: p022_gc_escape_log.txt  (UI stays unlocked; GameKit can block)\n"
            let th = Thread {
                P022GC_GameCenter_Sandbox_Escape.tap()
                let body = Self.readFreshLog(
                    named: "p022_gc_escape_log.txt",
                    missing: "p022GC finished but Documents/p022_gc_escape_log.txt missing or empty")
                DispatchQueue.main.async {
                    text = body
                }
            }
            th.name = "p022GC-probe"
            th.start()
            return
        }

        guard !running else { return }
        running = true
        // Keep main-thread work tiny while race owns the CPUs.
        text = "Running \(id)…\nDon't touch UI. Classify ips after reboot.\n"
        logTap(id)

        let raceHot = (id == "p017v2" || id == "p031" || id == "cskrw" || id == "cscali"
                       || id == "p050" || id == "p053" || id == "P053")
        if raceHot {
            // Give P-cores to A/B/C (USER_INTERACTIVE in probe). Main/UI → BACKGROUND.
            pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)
            UIApplication.shared.isIdleTimerDisabled = true
        }

        DispatchQueue.global(qos: raceHot ? .userInitiated : .utility).async {
            let result: String
            switch id {
            case "ident":       result = DeviceIdentProbe.runIdentity()
            case "board":       result = P007Board.tap()
            case "jpeg_dest":   result = JPEGDestTimeoutProbe.runDestAndTimeoutOracle()
            case "jpeg_fw":     result = JPEGFrameworkDecodeProbe.runFrameworkDecodeSmoke()
            case "iogpu_close": result = "STOP iogpu_close — intercepted. Use P040."
            case "p009detach":  result = P009ReplaceBackingSmoke.runDetachOnly()
            case "p009iopl":    result = "STOP p009iopl — leftover, not in prove set."
            case "p011v3", "p011v4", "p011v5", "p011v6", "p011v7", "p011v8", "p011v9", "p011v10", "p012ctx":
                result = "STOP \(id) intercepted — leftover wire race. Use P009 PathB + p017v2."
            case "p001a13vt":    result = AVEVTSmoke.performA13AVEVTLadder()
            case "p013ave":     result = AVEVTSmoke.performA14AVEDimLadder()
            case "vt_smoke":    result = AVEVTSmoke.performSmoke()
            case "p001dim":     result = AVEVTSmoke.performP001DimProbe()
            case "p001proc":    result = AVEVTSmoke.performP001ProcessProbe()
            case "p001cap":     result = AVEVTSmoke.performP001CapBoundaryProbe()
            case "p001ladder":  result = AVEVTSmoke.performP001FullLadderProbe()
            case "p001conn":    result = AVEVTSmoke.performP001VTConnHunt()
            case "p001xref":    result = AVEVTSmoke.performP001CrossRefProbe()
            case "p001ports":   result = AVEVTSmoke.performP001NewPortSweep()
            case "spawnattrs":  result = SpawnAttrsProbe.runSpawnAttrsProbe()
            case "p010krwv2", "p010pduaf", "p010twoconn", "p010pdsweep":
                result = "STOP \(id) intercepted — leftover P010 UAF. Use p010qleak (K− only)."
            case "p010qspray":  result = AVEOpenSmoke.runP010QueueSpray()
            case "p010remain":  result = AVEOpenSmoke.runP010Remain()
            case "necp":        result = AVEOpenSmoke.runNECPProbe()
            case "necprace":    result = AVEOpenSmoke.runNECPRace()
            case "p005":        result = AVEOpenSmoke.runP005Probe()
            case "iopl":        result = AVEOpenSmoke.runIOPLLeak()
            case "aio":         result = AVEOpenSmoke.runAIOUAF()
            case "ave47map":    result = AVEOpenSmoke.runAVE64747Map()
            case "ave47ctl":    result = AVEOpenSmoke.runAVE64747Control()
            case "p035":        result = P035AVEWrapProbe.tap()
            case "p036":        result = P036AVEPaintProbe.tap()
            case "p037":        result = P037AVEPaintProbe.tap()
            case "p009pathb":   result = P009ReplaceBackingSmoke.runPathB()
            case "p009ranges":  result = P009ReplaceBackingSmoke.runPathBRanges()
            case "p009types":   result = P009ReplaceBackingSmoke.runTypeInventory()
            case "t018":        result = CowTruncProbe.runCowTruncRace()
            case "t018shadow":  result = CowTruncProbe.runCowTruncShadowRace()
            case "t018ver":     result = CowTruncProbe.runCowTruncVersionRace()
            case "t019":
                result = "STOP t019 intercepted — XR leak class. Do not re-tap."
            case "t014a", "t014b", "t014c", "t014d", "t014e", "t014f":
                result = "STOP T014 intercepted — XR leftover. Use P040 dest ABI only."
            case "cscali":      result = CSRaceCalib.runCalib()
            case "cskrw":       result = LuminaClearSword.runKRW()
            case "p014ane", "p014b", "p015", "p017":
                result = "STOP \(id) intercepted — leftover. Use p017v2 for holder/install."
            case "p016":        result = JPEGDestTimeoutProbe.runP016SoutDestUnlock()
            case "p018":        result = JPEGDestTimeoutProbe.runP018SoutMachPort()
            case "p019":        result = P019IoplBoundsProbe.runP019IoplBounds()
            case "p020":        result = P020MagazineAwareReclaim.run()
            case "p020v2":      result = P020v2MagazineDrain.run()
            case "p021":        result = P021AGXStageMask.run()
            case "p022":        result = P022Cpu0DrainDelay.run()
            case "p023":
                P023VtExtremeProbe.run()
                result = Self.readFreshLog(
                    named: "p023_vt_extreme_log.txt",
                    missing: "p023 finished but Documents/p023_vt_extreme_log.txt missing or empty")
            case "p024":
                P024NecpStringRace.tap()
                result = Self.readFreshLog(
                    named: "p024_necp_string_race_log.txt",
                    missing: "p024 finished but Documents/p024_necp_string_race_log.txt missing or empty")
            case "p014close":
                result = "STOP p014close intercepted — XR leftover. Use P040 dest ABI only."
            case "p010leak", "p010qleak":
                result = P010QueueLeak.tap()
            case "p025":
                P025NecpStringSpray.tap()
                result = Self.readFreshLog(
                    named: "p025_necp_string_spray_log.txt",
                    missing: "p025 finished but Documents/p025_necp_string_spray_log.txt missing or empty")
            case "p017v2":
                result = P017ConfusedDeputy.tap()
            case "p026":
                result = P026MetalNqCite.tap()
            case "p039":
                result = P039AVEExploitTrigger.tap()
            case "p051":
                P051APFSXattr.tap()
                result = Self.readFreshLog(
                    named: "p051_apfs_xattr_log.txt",
                    missing: "p051 finished but log missing")
            case "p052":
                P052APFSNstream.tap()
                result = Self.readFreshLog(
                    named: "p052_nstream_extend_log.txt",
                    missing: "p052 finished but log missing")
            case "p053", "P053":
                P053NECPDoubleFree.tap()
                result = Self.readFreshLog(
                    named:  "p053_necp_dfree_log.txt",
                    missing: "p053 finished but log missing")
            case "p027":
                result = P027MetalCallback.tap()
            case "p028":
                result = P028ReentryA.tap()
            case "p029":
                result = P029Hammer.tap()
            case "p030":
                result = P030TwoQueue.tap()
            case "p031":
                result = P031ReclaimHit.tap()
            case "p032":
                result = P032ANEOpenSmoke.tap()
            case "p038":
                result = P038WHuntSmoke.tap()
            case "p040":
                result = P040NamespaceDestSmoke.tap()
            case "p041":
                result = P041SlideDestMap.tap()
            case "p054":
                result = P054APFSReapList.tap()
            case "p055":
                result = P055IOSurfaceUPL.tap()
            case "p033":
                result = P033CoreML1in1out.tap()
            case "p034":
                result = P034Kmsg3072Occupancy.tap()
            case "b1p1":
                result = B1_B2_LabTest.sharedInstance().phase1_mapAndLatch()
            case "b1p2":
                result = B1_B2_LabTest.sharedInstance().phase2_unmapAndReclaim()
            case "b1p3":
                result = B1_B2_LabTest.sharedInstance().phase3_latchedKick()
            case "b1p4":
                result = B1_B2_LabTest.sharedInstance().phase4_verifyReclaim()
            case "p042":
                result = P042ReachabilityProbe.tap()
            case "p043":
                result = P043WriteClassMap.tap()
            case "p044":
                result = P044AksKaslrReach.tap()
            case "p057", "aks":
                result = P057AksDeserialize.tap()
            case "p045":
                result = P045HybridMap.tap()
            case "p046":
                result = P046F77PatchOracle.tap()
            case "p050":
                P050GetattrlistOOB.tap()
                result = Self.readFreshLog(
                    named: "p050_getattrlist_oob_log.txt",
                    missing: "p050 finished but Documents/p050_getattrlist_oob_log.txt missing or empty")
            case "luminakrw":
                result = LuminaKRW.tap()
            // p022GC handled at top of run(_:) — never wait here with running=true
            default:            result = "unknown"
            }
            DispatchQueue.main.async {
                if raceHot {
                    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)
                    UIApplication.shared.isIdleTimerDisabled = false
                }
                // Truncate monster returns so SwiftUI doesn't layout megabytes.
                if result.count > 48_000 {
                    text = String(result.prefix(48_000)) + "\n…(truncated; full log in Documents)\n"
                } else {
                    text = result
                }
                kreadSignal = P007Board.shared().kreadSignal
                running = false
            }
        }
    }
}
