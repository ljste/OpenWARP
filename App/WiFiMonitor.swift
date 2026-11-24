import Foundation
import SystemConfiguration

final class WiFiMonitor {
    private let changed: (Bool) -> Void
    private var store: SCDynamicStore?
    private var interfaces: [String] = []
    private var network: NSDictionary?
    var joined: Bool { network != nil }

    init(changed: @escaping (Bool) -> Void) { self.changed = changed }

    func start() {
        guard store == nil else { return }
        interfaces = (SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []).compactMap {
            guard SCNetworkInterfaceGetInterfaceType($0) == kSCNetworkInterfaceTypeIEEE80211 else { return nil }
            return SCNetworkInterfaceGetBSDName($0) as String?
        }
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        guard let store = SCDynamicStoreCreate(nil, "OpenWARP Wi-Fi changes" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<WiFiMonitor>.fromOpaque(info).takeUnretainedValue().refresh()
        }, &context) else { return }
        let keys = interfaces.flatMap { name in
            ["Link", "AirPort", "IPv4", "IPv6"].map { "State:/Network/Interface/\(name)/\($0)" }
        }
        guard SCDynamicStoreSetNotificationKeys(store, keys as CFArray, nil),
              SCDynamicStoreSetDispatchQueue(store, .main) else { return }
        self.store = store
        refresh()
    }

    func stop() {
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
        store = nil
        network = nil
    }

    private func refresh() {
        guard let store else { return }
        let current = interfaces.lazy.compactMap { name -> NSDictionary? in
            func entity(_ key: String) -> [String: Any] {
                SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(name)/\(key)" as CFString) as? [String: Any] ?? [:]
            }
            guard entity("Link")["Active"] as? Bool == true else { return nil }
            let v4 = entity("IPv4")["Addresses"] as? [String] ?? []
            let v6 = entity("IPv6")["Addresses"] as? [String] ?? []
            guard let address = v4.first ?? v6.first(where: { !$0.lowercased().hasPrefix("fe80:") }) else { return nil }
            let airport = entity("AirPort")
            return ["interface": name, "join": airport["AutoJoinTimestamp"] ?? airport["ProfileID"] ?? address]
        }.first
        guard current != network else { return }
        network = current
        changed(joined)
    }
}
