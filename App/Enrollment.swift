import CryptoKit
import Foundation

struct OpenWARPError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}

private struct Registration: Decodable {
    let id: String
    let token: String
}

private struct Pending: Codable {
    let id: String
    let token: String
    let key: Data
}

private struct PeerConfiguration: Decodable {
    struct Addresses: Decodable {
        let v4: String
        let v6: String
    }
    struct Interface: Decodable {
        let addresses: Addresses
    }
    struct Peer: Decodable {
        let public_key: String
        let endpoint: Addresses
    }
    let interface: Interface
    let peers: [Peer]
}

private struct Enrolled: Decodable {
    let config: PeerConfiguration
}

enum Enrollment {
    static let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/OpenWARP", isDirectory: true)
    static let identity = directory.appendingPathComponent("identity.json")
    static let terms = URL(string: "https://www.cloudflare.com/application/terms/")!
    private static let endpoint = URL(string: "https://api.cloudflareclient.com/v0a4471/reg")!

    private static func request<T: Decodable>(
        _ method: String, url: URL, body: [String: String], token: String? = nil
    ) async throws -> T {
        var request = URLRequest(url: url, timeoutInterval: 20)
        request.httpMethod = method
        request.httpBody = try JSONEncoder().encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("a-6.35-4471", forHTTPHeaderField: "CF-Client-Version")
        request.setValue("WARP for Android", forHTTPHeaderField: "User-Agent")
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        let session = URLSession(configuration: .ephemeral, delegate: EnrollmentDelegate(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw OpenWARPError("Cloudflare registration returned HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0).")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private static func save(_ data: Data, to url: URL) throws {
        let temporary = directory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw OpenWARPError("Could not create the private enrollment file.")
        }
        defer { try? FileManager.default.removeItem(at: temporary) }
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.write(contentsOf: data)
        try handle.close()
        try FileManager.default.moveItem(at: temporary, to: url)
    }

    static func loadOrRegister() async throws -> Data {
        let files = FileManager.default
        if files.fileExists(atPath: identity.path) { return try Data(contentsOf: identity) }
        try files.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let pendingFile = directory.appendingPathComponent("registration.json")
        let pending: Pending
        if files.fileExists(atPath: pendingFile.path) {
            pending = try JSONDecoder().decode(Pending.self, from: Data(contentsOf: pendingFile))
        } else {
            let key = P256.Signing.PrivateKey()
            let bootstrap = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
            let serial = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).lowercased()
            let registration: Registration = try await request("POST", url: endpoint, body: [
                "key": bootstrap.base64EncodedString(), "key_type": "curve25519", "tunnel_type": "wireguard",
                "tos": ISO8601DateFormatter().string(from: Date()), "model": "PC", "locale": "en_US",
                "serial_number": serial, "install_id": "", "fcm_token": "", "os_version": ""
            ])
            guard UUID(uuidString: registration.id) != nil, !registration.token.isEmpty else {
                throw OpenWARPError("Cloudflare returned an incomplete registration.")
            }
            pending = Pending(id: registration.id, token: registration.token, key: key.derRepresentation)
            try save(JSONEncoder().encode(pending), to: pendingFile)
        }

        let key = try P256.Signing.PrivateKey(derRepresentation: pending.key)
        let enrolled: Enrolled = try await request("PATCH", url: endpoint.appendingPathComponent(pending.id), body: [
            "key": key.publicKey.derRepresentation.base64EncodedString(), "key_type": "secp256r1",
            "tunnel_type": "masque", "name": "OpenWARP"
        ], token: pending.token)
        guard let peer = enrolled.config.peers.first,
              let v4 = URLComponents(string: "https://" + peer.endpoint.v4)?.host,
              let v6 = URLComponents(string: "https://" + peer.endpoint.v6)?.host else {
            throw OpenWARPError("Cloudflare returned an incomplete MASQUE peer.")
        }
        let normalizedKey = try P256.Signing.PublicKey(pemRepresentation: peer.public_key)
        let identityData = try JSONEncoder().encode([
            "Key": pending.key.base64EncodedString(), "Peer": normalizedKey.derRepresentation.base64EncodedString(),
            "IPv4": enrolled.config.interface.addresses.v4, "IPv6": enrolled.config.interface.addresses.v6,
            "Endpoint4": v4, "Endpoint6": v6.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        ])
        try save(identityData, to: identity)
        try files.removeItem(at: pendingFile)
        return identityData
    }
}

private final class EnrollmentDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
