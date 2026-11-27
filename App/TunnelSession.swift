import Darwin
import Foundation

struct TunnelStatus: Decodable {
    let state: String
    let detail: String
    var supportsP2P: Bool? = nil
}

final class TunnelSession {
    private var handle: FileHandle?
    private var reader: DispatchSourceRead?
    private var supportsP2P: Bool?
    private var sentP2P = false
    private var pending = Data()
    private let update: (TunnelStatus) -> Void
    var active: Bool { handle != nil }

    init(update: @escaping (TunnelStatus) -> Void) {
        self.update = update
    }

    func connect(identity: Data) throws {
        guard !active else { return }
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.ENFILE) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let path = "/var/run/io.github.ljste.openwarp.sock"
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: path.utf8) }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0 else {
            throw OpenWARPError("Could not reach the network helper. Run the OpenWARP installer, then open OpenWARP from Applications. (\(String(cString: strerror(errno))))")
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 else { throw OpenWARPError("The tunnel helper is not owned by the system.") }
        var enabled: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else {
            throw OpenWARPError("Could not configure the tunnel control socket.")
        }
        let message = try JSONSerialization.data(withJSONObject: JSONSerialization.jsonObject(with: identity)) + Data([10])
        try file.write(contentsOf: message)
        handle = file
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setEventHandler { [weak self] in self?.readStatus() }
        source.setCancelHandler { try? file.close() }
        reader = source
        source.resume()
    }

    func disconnect() {
        if let fd = handle?.fileDescriptor { shutdown(fd, SHUT_RDWR) }
        reader?.cancel()
        reader = nil
        handle = nil
        supportsP2P = nil
        sentP2P = false
        pending.removeAll()
    }

    func setP2P(_ enabled: Bool) throws {
        guard let handle, let supportsP2P, sentP2P != enabled else { return }
        guard supportsP2P else { throw OpenWARPError("Update the OpenWARP tunnel helper to use P2P Mode.") }
        try handle.write(contentsOf: Data(enabled ? [0x31] : [0x30]))
        sentP2P = enabled
    }

    private func readStatus() {
        guard let handle else { return }
        var buffer = [UInt8](repeating: 0, count: 4096)
        let length = Darwin.read(handle.fileDescriptor, &buffer, buffer.count)
        guard length > 0 else {
            disconnect()
            update(TunnelStatus(state: "error", detail: "The tunnel helper closed the connection."))
            return
        }
        pending.append(contentsOf: buffer.prefix(length))
        while let end = pending.firstIndex(of: 10) {
            let line = pending.prefix(upTo: end)
            let status = try? JSONDecoder().decode(TunnelStatus.self, from: line)
            pending.removeSubrange(...end)
            guard let status else { continue }
            if status.state == "connected" { supportsP2P = status.supportsP2P ?? false }
            if status.state == "error" { disconnect() }
            update(status)
        }
    }
}
