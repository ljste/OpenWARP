import AppKit
import ServiceManagement

final class OpenWARPApp: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let heading = NSMenuItem()
    private let detail = NSMenuItem()
    private let toggle = NSMenuItem()
    private let login = NSMenuItem()
    private lazy var session = TunnelSession { [weak self] status in self?.render(status) }
    private var state = "disconnected"
    private var pending: Task<Void, Never>?

    func applicationDidFinishLaunching(_ notification: Notification) {
        menu.autoenablesItems = false
        heading.isEnabled = false
        detail.isEnabled = false
        menu.addItem(heading)
        menu.addItem(detail)
        menu.addItem(.separator())
        toggle.target = self
        toggle.action = #selector(toggleConnection)
        menu.addItem(toggle)
        login.title = "Connect at Login"
        login.target = self
        login.action = #selector(toggleLogin)
        menu.addItem(login)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit OpenWARP", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
        menu.delegate = self
        item.menu = menu
        render(TunnelStatus(state: state, detail: ""))
        if SMAppService.mainApp.status == .enabled || CommandLine.arguments.contains("--connect") { start() }
    }

    func menuWillOpen(_ menu: NSMenu) {
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    func applicationWillTerminate(_ notification: Notification) {
        pending?.cancel()
        session.disconnect()
    }

    @objc private func toggleConnection() {
        if session.active || pending != nil {
            pending?.cancel()
            session.disconnect()
            render(TunnelStatus(state: "disconnected", detail: ""))
        } else { start() }
    }

    private func start() {
        guard pending == nil, !session.active else { return }
        if !FileManager.default.fileExists(atPath: Enrollment.identity.path) {
            let alert = NSAlert()
            alert.messageText = "Register this Mac with Cloudflare?"
            alert.informativeText = "OpenWARP creates a private device key and registers its public key for WARP. Choosing Agree accepts Cloudflare’s application terms."
            alert.addButton(withTitle: "Agree and Connect")
            alert.addButton(withTitle: "Cancel")
            alert.addButton(withTitle: "Read Terms")
            NSApp.activate(ignoringOtherApps: true)
            switch alert.runModal() {
            case .alertFirstButtonReturn: break
            case .alertThirdButtonReturn: NSWorkspace.shared.open(Enrollment.terms); return
            default: return
            }
        }
        render(TunnelStatus(state: "connecting", detail: "Preparing connection"))
        pending = Task { @MainActor in
            defer { pending = nil }
            do {
                let id = try await Enrollment.loadOrRegister()
                try Task.checkCancellation()
                try session.connect(identity: id)
            } catch {
                if !Task.isCancelled { render(TunnelStatus(state: "error", detail: error.localizedDescription)) }
            }
        }
    }

    private func render(_ status: TunnelStatus) {
        state = status.state
        let symbol: String
        let label: String
        switch state {
        case "connected": symbol = "lock.shield.fill"; label = "Connected"
        case "connecting": symbol = "ellipsis.shield"; label = "Connecting"
        case "reconnecting": symbol = "arrow.triangle.2.circlepath"; label = "Reconnecting"
        case "error": symbol = "exclamationmark.shield"; label = "Connection failed"
        default: symbol = "shield"; label = "Disconnected"
        }
        let description = "OpenWARP · " + label
        item.button?.image = NSImage(systemSymbolName: symbol, accessibilityDescription: description)
            ?? NSImage(systemSymbolName: "shield", accessibilityDescription: description)
        item.button?.toolTip = description
        item.button?.setAccessibilityLabel(description)
        heading.title = description
        let text = state == "connected" ? "Traffic and DNS (UDP) · " + status.detail : status.detail
        detail.title = text.count > 64 ? String(text.prefix(61)) + "…" : text
        detail.toolTip = text
        detail.isHidden = text.isEmpty
        toggle.title = state == "connected" || state == "reconnecting" ? "Disconnect" : state == "connecting" ? "Cancel" : "Connect"
        if state == "error" {
            let alert = NSAlert()
            alert.messageText = "OpenWARP could not connect"
            alert.informativeText = status.detail
            alert.runModal()
        }
    }

    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else {
                try SMAppService.mainApp.register()
                if SMAppService.mainApp.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
            }
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

let app = NSApplication.shared
let delegate = OpenWARPApp()
app.setActivationPolicy(.accessory)
app.delegate = delegate
app.run()
