import AppKit
import ServiceManagement

final class OpenWARPApp: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let heading = NSMenuItem()
    private let detail = NSMenuItem()
    private let toggle = NSMenuItem()
    private let login = NSMenuItem()
    private let killSwitch = NSMenuItem()
    private let resumeInternet = NSMenuItem()
    private lazy var session = TunnelSession { [weak self] status in self?.render(status) }
    private var loginProcess: Process?
    private var loginInput: FileHandle?
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
        let settingsMenu = NSMenu(title: "Settings")
        settingsMenu.delegate = self
        let settings = menu.addItem(withTitle: settingsMenu.title, action: nil, keyEquivalent: "")
        settings.submenu = settingsMenu
        login.title = "Connect at Login"
        login.target = self
        login.action = #selector(toggleLogin)
        settingsMenu.addItem(login)
        killSwitch.title = "Kill Switch"
        killSwitch.toolTip = "Block Internet traffic if the tunnel drops. Disconnect or quit from this menu to use your normal connection."
        killSwitch.target = self
        killSwitch.action = #selector(toggleKillSwitch)
        settingsMenu.addItem(killSwitch)
        let wifi = settingsMenu.addItem(withTitle: "Sign In to Wi-Fi…", action: #selector(signInToWifi), keyEquivalent: "")
        wifi.target = self
        resumeInternet.title = "Resume Ordinary Internet"
        resumeInternet.target = self
        resumeInternet.action = #selector(manualDisconnect)
        settingsMenu.addItem(resumeInternet)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit OpenWARP", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item.menu = menu
        render(TunnelStatus(state: state, detail: ""))
        if SMAppService.mainApp.status == .enabled || CommandLine.arguments.contains("--connect") { start() }
    }

    func menuWillOpen(_ menu: NSMenu) {
        let mode = KillSwitch.mode
        killSwitch.state = mode == nil ? .mixed : mode == .off ? .off : .on
        resumeInternet.isHidden = mode != .armed || session.active
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    func applicationWillTerminate(_ notification: Notification) {
        stopWifiLogin()
        pending?.cancel()
        session.disconnect()
    }

    @objc private func toggleConnection() {
        if session.active || pending != nil {
            manualDisconnect()
        } else { start() }
    }

    private func pauseProtection() -> Bool {
        do {
            if KillSwitch.mode != .off { try KillSwitch.apply("pause") }
            return true
        } catch {
            NSAlert(error: error).runModal()
            return false
        }
    }

    @objc private func manualDisconnect() {
        guard pauseProtection() else { return }
        stopWifiLogin()
        pending?.cancel()
        session.disconnect()
        render(TunnelStatus(state: "disconnected", detail: ""))
    }

    @objc private func quitApp() {
        if pauseProtection() { NSApp.terminate(nil) }
    }

    @objc private func toggleKillSwitch() {
        do {
            if KillSwitch.mode == .off {
                try KillSwitch.apply(session.active ? "enable-active" : "enable")
            } else {
                try KillSwitch.apply("disable")
            }
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    private func stopWifiLogin() {
        try? loginInput?.close()
        loginInput = nil
        loginProcess = nil
    }

    @objc private func signInToWifi() {
        if let current = loginProcess, current.isRunning {
            NSRunningApplication(processIdentifier: current.processIdentifier)?.activate(options: [])
            return
        }
        let process = Process()
        let reconnect = state != "disconnected" || KillSwitch.mode == .armed
        process.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/WiFiLogin.app/Contents/MacOS/WiFiLogin")
        let input = Pipe()
        process.standardInput = input
        process.terminationHandler = { [weak self] finished in
            DispatchQueue.main.async {
                guard let self, self.loginProcess === finished else { return }
                self.stopWifiLogin()
                if reconnect && finished.terminationStatus == 0 && self.state != "connected" {
                    self.session.disconnect()
                    self.start()
                }
            }
        }
        do {
            try process.run()
            loginProcess = process
            loginInput = input.fileHandleForWriting
        } catch { NSAlert(error: error).runModal() }
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
                if KillSwitch.mode != .off { try KillSwitch.apply("arm") }
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
        if state == "error" && loginProcess == nil {
            let alert = NSAlert()
            alert.messageText = "OpenWARP could not connect"
            alert.informativeText = status.detail + (KillSwitch.mode == .armed ? "\n\nThe kill switch is armed. Reconnect or choose Settings > Resume Ordinary Internet." : "")
            alert.addButton(withTitle: "OK")
            alert.addButton(withTitle: "Sign In to Wi-Fi…")
            if alert.runModal() == .alertSecondButtonReturn { signInToWifi() }
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
