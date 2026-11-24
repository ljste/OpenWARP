import AppKit
import Darwin
import Network
import WebKit

private let probeURL = URL(string: "http://captive.apple.com/hotspot-detect.html")!

private struct SignInError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

private struct Lease: Decodable {
    let port: UInt16
    let secret: String
    let api: String

    static func open() throws -> (FileHandle, Lease) {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SignInError("Cannot open the Wi-Fi sign-in service.") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: "/var/run/io.github.ljste.openwarp.portal.sock".utf8) }
        let length = socklen_t(address.sun_len)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, length) }
        }
        guard result == 0 else { throw SignInError("Cannot reach the installed OpenWARP Wi-Fi sign-in service.") }
        var timeout = timeval(tv_sec: 8, tv_usec: 0)
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw SignInError("Cannot set up Wi-Fi sign-in.")
        }
        var data = Data()
        var byte: UInt8 = 0
        while data.count < 8192 && Darwin.read(fd, &byte, 1) == 1 {
            if byte == 10 {
                if let message = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String {
                    throw SignInError(message)
                }
                return (file, try JSONDecoder().decode(Self.self, from: data))
            }
            data.append(byte)
        }
        throw SignInError("The Wi-Fi sign-in service did not respond.")
    }
}

private final class ProbeDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private struct Captivity: Decodable {
    let captive: Bool
    let portal: URL?
    enum CodingKeys: String, CodingKey { case captive; case portal = "user-portal-url" }
}

@MainActor private final class LoginWindow: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    private var window: NSWindow?
    private var lease: FileHandle?
    private var checks: Task<Void, Never>?
    private var browser: WKWebView?
    private let origin = NSTextField(labelWithString: "Checking Wi-Fi…")
    private let probeDelegate = ProbeDelegate()

    func applicationDidFinishLaunching(_ notification: Notification) {
        FileHandle.standardInput.readabilityHandler = { _ in DispatchQueue.main.async { exit(1) } }
        do {
            let (socket, config) = try Lease.open()
            lease = socket
            var proxy = ProxyConfiguration(socksv5Proxy: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: config.port)!))
            proxy.applyCredential(username: "openwarp", password: config.secret)
            proxy.allowFailover = false
            let store = WKWebsiteDataStore.nonPersistent()
            store.proxyConfigurations = [proxy]
            let webConfig = WKWebViewConfiguration()
            webConfig.websiteDataStore = store
            let web = WKWebView(frame: .zero, configuration: webConfig)
            web.navigationDelegate = self
            web.uiDelegate = self
            browser = web
            let done = NSButton(title: "Done", target: self, action: #selector(doneClicked))
            origin.lineBreakMode = .byTruncatingTail
            let header = NSStackView(views: [origin, done])
            header.orientation = .horizontal
            header.distribution = .fill
            let content = NSView()
            for view in [header, web] { view.translatesAutoresizingMaskIntoConstraints = false; content.addSubview(view) }
            NSLayoutConstraint.activate([
                header.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 14), header.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -14),
                header.topAnchor.constraint(equalTo: content.topAnchor, constant: 8), web.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 8),
                web.leadingAnchor.constraint(equalTo: content.leadingAnchor), web.trailingAnchor.constraint(equalTo: content.trailingAnchor), web.bottomAnchor.constraint(equalTo: content.bottomAnchor)
            ])
            let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 560), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            panel.title = "OpenWARP Wi-Fi Sign-In"
            panel.contentView = content
            panel.delegate = self
            window = panel
            panel.center()
            panel.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            let configuration = URLSessionConfiguration.ephemeral
            configuration.proxyConfigurations = [proxy]
            configuration.timeoutIntervalForRequest = 5
            configuration.timeoutIntervalForResource = 8
            configuration.urlCache = nil
            configuration.httpShouldSetCookies = false
            let session = URLSession(configuration: configuration, delegate: probeDelegate, delegateQueue: nil)
            checks = Task { await monitor(web, session: session, api: URL(string: config.api)) }
            socket.readabilityHandler = { _ in
                DispatchQueue.main.async { exit(1) }
            }
        } catch {
            NSApp.activate(ignoringOtherApps: true)
            NSAlert(error: error).runModal()
            exit(1)
        }
    }

    private func response(_ request: URLRequest, session: URLSession) async throws -> (HTTPURLResponse, Data) {
        let (bytes, raw) = try await session.bytes(for: request)
        guard let http = raw as? HTTPURLResponse else { throw SignInError("Invalid Wi-Fi response.") }
        var body = Data()
        defer { bytes.task.cancel() }
        for try await byte in bytes {
            if body.count == 32768 { break }
            body.append(byte)
        }
        return (http, body)
    }

    private func monitor(_ web: WKWebView, session: URLSession, api: URL?) async {
        defer { session.invalidateAndCancel() }
        let api = api.flatMap { $0.scheme?.lowercased() == "https" && $0.host != nil ? $0 : nil }
        var loaded = false
        while !Task.isCancelled {
            var loginURL = probeURL
            var advertised = false
            var captive = false
            if let api {
                var request = URLRequest(url: api)
                request.setValue("application/captive+json", forHTTPHeaderField: "Accept")
                if let (http, data) = try? await response(request, session: session), http.statusCode == 200,
                   let state = try? JSONDecoder().decode(Captivity.self, from: data) {
                    if !state.captive { finish() }
                    captive = true
                    if let portal = state.portal, portal.scheme?.lowercased() == "https", Self.webURL(portal) { loginURL = portal; advertised = true }
                }
            }
            if !advertised, let (http, body) = try? await response(URLRequest(url: probeURL), session: session) {
                let page = String(decoding: body, as: UTF8.self).lowercased().filter { !$0.isWhitespace }
                if !captive && http.statusCode == 200 && page == "<html><head><title>success</title></head><body>success</body></html>" { finish() }
                if (300..<400).contains(http.statusCode), let redirect = http.value(forHTTPHeaderField: "Location"),
                   let destination = URL(string: redirect, relativeTo: probeURL)?.absoluteURL, Self.webURL(destination) { loginURL = destination }
            }
            if !loaded { loaded = true; web.load(URLRequest(url: loginURL)) }
            try? await Task.sleep(for: .seconds(5))
        }
    }

    private static func webURL(_ url: URL) -> Bool {
        ["http", "https"].contains(url.scheme?.lowercased() ?? "") && url.host != nil && url.user == nil && url.password == nil
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url, Self.webURL(url), !navigationAction.shouldPerformDownload else { decisionHandler(.cancel); return }
        if navigationAction.targetFrame == nil { webView.load(navigationAction.request); decisionHandler(.cancel); return }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        guard let url = webView.url else { return }
        origin.stringValue = "\(url.scheme ?? "")://\(url.host ?? "")" + (url.port.map { ":\($0)" } ?? "")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code != NSURLErrorCancelled { origin.stringValue = error.localizedDescription }
    }

    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo,
                 type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) { decisionHandler(.deny) }

    @objc private func doneClicked() { finish() }
    private func finish() -> Never { exit(0) }
    func windowWillClose(_ notification: Notification) { exit(1) }
}

let app = NSApplication.shared
private let delegate = MainActor.assumeIsolated { LoginWindow() }
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
