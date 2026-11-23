import Foundation

enum KillSwitch {
    enum Mode: String {
        case off, standby, armed
    }

    static var mode: Mode? {
        let path = "/var/db/io.github.ljste.openwarp.kill-switch"
        do {
            return Mode(rawValue: try String(contentsOfFile: path, encoding: .utf8))
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError {
            return .off
        } catch {
            return nil
        }
    }

    static func apply(_ action: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/Library/PrivilegedHelperTools/io.github.ljste.openwarp.tunnel")
        process.arguments = ["kill-switch", action]
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        let output = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw OpenWARPError(String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}
