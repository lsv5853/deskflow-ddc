import Foundation
import CoreGraphics
import ApplicationServices

// Emergency-watch state. File-scope globals (not closure captures) so
// the C event-tap callback below can use them.
var watchPid: Int32 = 0
var watchSecs: UInt64 = 0
var watchMicros: UInt64 = 0
var watchKey: CGKeyCode = 0
var watchFlags: CGEventFlags = []

func watchStartTime(of pid: Int32) -> (UInt64, UInt64)? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    let read = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
    guard read == size, info.pbi_pid == pid else { return nil }
    return (UInt64(info.pbi_start_tvsec), UInt64(info.pbi_start_tvusec))
}

func watchCallback(proxy: CGEventTapProxy, type: CGEventType, event: CGEvent,
                   refcon: UnsafeMutableRawPointer?) -> Unmanaged<CGEvent>? {
    guard type == .keyDown,
          event.getIntegerValueField(.keyboardEventKeycode) == Int64(watchKey),
          event.flags.contains(watchFlags) else {
        return Unmanaged.passUnretained(event)
    }
    if let current = watchStartTime(of: watchPid),
       current.0 == watchSecs, current.1 == watchMicros {
        kill(watchPid, SIGKILL)
    }
    exit(0)
}

let action = CommandLine.arguments.dropFirst().first ?? "check"
if action == "screens" {
    var count: UInt32 = 0
    CGGetActiveDisplayList(0, nil, &count)
    var ids = [CGDirectDisplayID](repeating: 0, count: Int(count))
    CGGetActiveDisplayList(count, &ids, &count)
    let panels: [[String: Any]] = ids.prefix(Int(count)).map { id in
        let b = CGDisplayBounds(id)
        return ["id": String(id), "name": CGDisplayIsBuiltin(id) != 0 ? "内置屏幕" : "屏幕 \(id)", "internal": CGDisplayIsBuiltin(id) != 0,
                "bounds": ["x": b.origin.x, "y": b.origin.y, "width": b.width, "height": b.height]]
    }
    let data = try JSONSerialization.data(withJSONObject: panels)
    print(String(data: data, encoding: .utf8)!)
    exit(0)
}
if action == "check" {
    print(AXIsProcessTrusted() ? "true" : "false")
    exit(0)
}
if action == "pointer" {
    guard CommandLine.arguments.count == 4,
          let x = Double(CommandLine.arguments[2]), let y = Double(CommandLine.arguments[3]),
          x.isFinite, y.isFinite else { exit(2) }
    guard AXIsProcessTrusted() else { fputs("需要辅助功能权限才能定位鼠标\n", stderr); exit(3) }
    let target = CGPoint(x: x, y: y)
    guard CGWarpMouseCursorPosition(target) == .success else { fputs("无法定位鼠标\n", stderr); exit(6) }
    CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: target, mouseButton: .left)?.post(tap: .cghidEventTap)
    print("positioned")
    exit(0)
}
if action == "watch" {
    // Emergency-stop watcher (P0-1). Usage:
    //   mac-hotkey watch <engine-pid> <start-secs> <start-micros> <chord>
    // It installs its own event tap for the emergency chord. On match it
    // re-verifies the engine's kernel start time (PID reuse protection),
    // SIGKILLs it, and exits. It never touches any other process.
    // It exits when stdin closes (the owning app's lease) or when the
    // engine is already gone. Prints "ready" once the tap is installed.
    // NOTE: tap ordering relative to the engine's own tap is not
    // guaranteed; if the engine swallows the chord first, this watcher
    // cannot see it. The in-app shortcut and peer-side stop remain
    // fallbacks. Must be verified on real hardware.
    guard CommandLine.arguments.count == 6,
          let pid = Int32(CommandLine.arguments[2]),
          let secs = UInt64(CommandLine.arguments[3]),
          let micros = UInt64(CommandLine.arguments[4]) else { exit(2) }
    let chord = CommandLine.arguments[5]
    let keycodes: [String: CGKeyCode] = [
        "F1": 122, "F2": 120, "F3": 99, "F4": 118, "F5": 96, "F6": 97,
        "F7": 98, "F8": 100, "F9": 101, "F10": 109, "F11": 103, "F12": 111,
        "F13": 105, "F14": 107, "F15": 113, "F16": 106, "F17": 64,
        "F18": 79, "F19": 80,
    ]
    let parts = chord.split(separator: "+").map(String.init)
    let middle = Array(parts.dropFirst(2).dropLast())
    guard parts.count >= 3, parts[0] == "control", parts[1] == "alt",
          (middle.isEmpty || middle == ["shift"]),
          let key = keycodes[parts.last!] else { exit(2) }
    var flags: CGEventFlags = [.maskControl, .maskAlternate]
    if middle == ["shift"] { flags.insert(.maskShift) }
    watchPid = pid
    watchSecs = secs
    watchMicros = micros
    watchKey = key
    watchFlags = flags
    guard let initial = watchStartTime(of: pid),
          initial.0 == secs, initial.1 == micros else { exit(0) }
    guard AXIsProcessTrusted() else { fputs("需要辅助功能权限才能监听紧急快捷键\n", stderr); exit(3) }
    // Stdin lease: the owning app closes it on normal session end.
    Thread.detachNewThread {
        while FileHandle.standardInput.readData(ofLength: 1).count > 0 {}
        exit(0)
    }
    let mask = CGEventMask(1 << CGEventType.keyDown.rawValue)
    guard let tap = CGEvent.tapCreate(tap: .cghidEventTap, place: .headInsertEventTap,
                                      options: .defaultTap, eventsOfInterest: mask,
                                      callback: watchCallback, userInfo: nil) else {
        fputs("无法安装紧急快捷键监听\n", stderr); exit(3)
    }
    let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .commonModes)
    CGEvent.tapEnable(tap: tap, enable: true)
    print("ready")
    fflush(stdout)
    CFRunLoopRun()
    exit(0)
}
guard action == "host" || action == "peer" else { fputs("Invalid shortcut target\n", stderr); exit(2) }
guard AXIsProcessTrusted() else { fputs("需要辅助功能权限才能发送切换快捷键\n", stderr); exit(3) }
let key: CGKeyCode = action == "host" ? 79 : 80 // F18 and F19
guard let source = CGEventSource(stateID: .hidSystemState),
      let down = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: true),
      let up = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: false) else { exit(4) }
let flags: CGEventFlags = [.maskControl, .maskAlternate, .maskShift]
down.flags = flags; up.flags = flags
down.post(tap: .cghidEventTap)
usleep(35000)
up.post(tap: .cghidEventTap)
print("sent")
