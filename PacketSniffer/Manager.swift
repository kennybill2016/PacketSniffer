//
//  Manager.swift
//  PacketSniffer
//
//  Created by lijinwei on 2016/11/2.
//  Copyright © 2016年 ljw. All rights reserved.
//

import PacketSnifferBase
import NetworkExtension

public enum ManagerError: Error {
    case InvalidProvider
    case VPNStartFail
}

public enum VPNStatus {
    case Off
    case Connecting
    case On
    case Disconnecting
}


public let kDefaultGroupIdentifier = "defaultGroup"
public let kDefaultGroupName = "defaultGroupName"
private let statusIdentifier = "status"
public let kProxyServiceVPNStatusNotification = "kProxyServiceVPNStatusNotification"

public class Manager {
    
    public static let sharedManager = Manager()
    
    public private(set) var vpnStatus = VPNStatus.Off {
        didSet {
            NotificationCenter.default.post(name: NSNotification.Name(rawValue: kProxyServiceVPNStatusNotification), object: nil)
        }
    }
    
    var observerAdded: Bool = false

    private init() {
        loadProviderManager { (manager) -> Void in
            if let manager = manager {
                self.updateVPNStatus(manager: manager)
            }
        }
        addVPNStatusObserver()
    }
    
    func addVPNStatusObserver() {
        guard !observerAdded else{
            return
        }
        loadProviderManager { [unowned self] (manager) -> Void in
            if let manager = manager {
                self.observerAdded = true
                NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object: manager.connection, queue: OperationQueue.main, using: { [unowned self] (notification) -> Void in
                    self.updateVPNStatus(manager: manager)
                })
            }
        }
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    func updateVPNStatus(manager: NEVPNManager) {
        switch manager.connection.status {
        case .connected:
            self.vpnStatus = .On
        case .connecting, .reasserting:
            self.vpnStatus = .Connecting
        case .disconnecting:
            self.vpnStatus = .Disconnecting
        case .disconnected, .invalid:
            self.vpnStatus = .Off
        }
    }

    public func switchVPN(completion: ((NETunnelProviderManager?, Error?) -> Void)? = nil) {
        loadProviderManager { [unowned self] (manager) in
            if let manager = manager {
                self.updateVPNStatus(manager: manager)
            }
            let current = self.vpnStatus
            guard current != .Connecting && current != .Disconnecting else {
                return
            }
            if current == .Off {
                self.startVPN { (manager, error) -> Void in
                    completion?(manager, error)
                }
            }else {
                self.stopVPN()
                completion?(nil, nil)
            }

        }
    }
    
    public func switchVPNFromTodayWidget(context: NSExtensionContext) {
        if let url = NSURL(string: "packetsniffer://switch") {
            context.open(url as URL, completionHandler: nil)
        }
    }
    
    public func setup() throws {
        try regenerateConfigFiles()
        do {
            try copyGEOIPData()
            try copyTemplateData()
        }catch{
            print("copy fail")
        }
    }
    
    func copyGEOIPData() throws {
        for country in ["CN"] {
            guard let fromURL = Bundle.main.url(forResource: "geoip-\(country)", withExtension: "data") else {
                return
            }
            let toURL = PacketSniffer.sharedUrl().appendingPathComponent("httpconf/geoip-\(country).data")
            if FileManager.default.fileExists(atPath: fromURL.path) {
                if FileManager.default.fileExists(atPath: toURL.path) {
                    try FileManager.default.removeItem(at: toURL)
                }
                try FileManager.default.copyItem(at: fromURL, to: toURL)
            }
        }
    }

    func copyTemplateData() throws {
        guard let bundleURL = Bundle.main.url(forResource: "template", withExtension: "bundle") else {
            return
        }
        let fm = FileManager.default
        let toDirectoryURL = PacketSniffer.sharedUrl().appendingPathComponent("httptemplate")
        if !fm.fileExists(atPath: toDirectoryURL.path) {
            try fm.createDirectory(at: toDirectoryURL, withIntermediateDirectories: true, attributes: nil)
        }
        for file in try fm.contentsOfDirectory(atPath: bundleURL.path) {
            let destURL = toDirectoryURL.appendingPathComponent(file)
            let dataURL = bundleURL.appendingPathComponent(file)
            if FileManager.default.fileExists(atPath: dataURL.path) {
                if FileManager.default.fileExists(atPath: destURL.path) {
                    try FileManager.default.removeItem(at: destURL)
                }
                try fm.copyItem(at: dataURL, to: destURL)
            }
        }
    }

    public func regenerateConfigFiles() throws {
        try generateGeneralConfig()
        try generateSocksConfig()
        try generateShadowsocksConfig()
        try generateHttpProxyConfig()
    }

}

extension Manager {
    
    func generateGeneralConfig() throws {
        let confURL = PacketSniffer.sharedGeneralConfUrl()
        let json: NSDictionary = ["dns": ""]
        try json.jsonString()?.write(to: confURL, atomically: true, encoding: String.Encoding.utf8)
    }
    
    func generateSocksConfig() throws {
        guard let bundleURL = Bundle.main.url(forResource: "sockconf", withExtension: "xml") else {
            return
        }
        let confContentData = NSData.init(contentsOfFile: bundleURL.path)
        let content = String.init(data: confContentData as! Data, encoding: String.Encoding.utf8)
        try content?.write(to: PacketSniffer.sharedSocksConfUrl(), atomically: true, encoding: String.Encoding.utf8)
    }
    
    func generateShadowsocksConfig() throws {
        let confURL = PacketSniffer.sharedProxyConfUrl()
        let content = ""
/*        if let upstreamProxy = upstreamProxy, upstreamProxy.type == .Shadowsocks {
            content = ["host": upstreamProxy.host, "port": upstreamProxy.port, "password": upstreamProxy.password ?? "", "authscheme": upstreamProxy.authscheme ?? "", "ota": upstreamProxy.ota].jsonString() ?? ""
        }*/
        try content.write(to: confURL, atomically: true, encoding: String.Encoding.utf8)
    }
    
    func copyActionData() throws {
        guard let fromURL = Bundle.main.url(forResource: "PacketSniffer", withExtension: "action") else {
            return
        }
        let toURL = PacketSniffer.sharedUrl().appendingPathComponent("PacketSniffer.action")
        if FileManager.default.fileExists(atPath: fromURL.path) {
            if FileManager.default.fileExists(atPath: toURL.path) {
                try FileManager.default.removeItem(at: toURL)
            }
            try FileManager.default.copyItem(at: fromURL, to: toURL)
        }
    }
    
    func generateHttpProxyConfig() throws {
        let rootUrl = PacketSniffer.sharedUrl()
        let confDirUrl = rootUrl.appendingPathComponent("httpconf")
        let templateDirPath = rootUrl.appendingPathComponent("httptemplate").path
        let temporaryDirPath = rootUrl.appendingPathComponent("httptemporary").path
        let logDir = rootUrl.appendingPathComponent("log").path
        for p in [confDirUrl.path, templateDirPath, temporaryDirPath, logDir] {
            if !FileManager.default.fileExists(atPath: p) {
                _ = try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true, attributes: nil)
            }
        }
        var mainConf: [String: AnyObject] = [:]
        if let path = Bundle.main.path(forResource: "proxy", ofType: "plist"), let defaultConf = NSDictionary(contentsOfFile: path) as? [String: AnyObject] {
            mainConf = defaultConf
        }
        mainConf["confdir"] = confDirUrl.path as AnyObject?
        mainConf["templdir"] = templateDirPath as AnyObject?
        mainConf["logdir"] = logDir as AnyObject?
        mainConf["global-mode"] = 0 as AnyObject?//defaultToProxy
//        mainConf["debug"] = 1024+65536+1
        mainConf["debug"] = 131071 as AnyObject?

        let mainContent = mainConf.map { "\($0) \($1)"}.joined(separator: "\n")
        try mainContent.write(to: PacketSniffer.sharedHttpProxyConfUrl(), atomically: true, encoding: String.Encoding.utf8)
        
        try copyActionData()
    }
}

extension Manager {
    
    public func isVPNStarted(complete: @escaping (Bool, NETunnelProviderManager?) -> Void) {
        loadProviderManager { (manager) -> Void in
            if let manager = manager {
                complete(manager.connection.status == .connected, manager)
            }else{
                complete(false, nil)
            }
        }
    }
    
    public func startVPN(complete: ((NETunnelProviderManager?, Error?) -> Void)? = nil) {
        startVPNWithOptions(options: nil, complete: complete)
    }
    
    private func startVPNWithOptions(options: [String : NSObject]?, complete: ((NETunnelProviderManager?, Error?) -> Void)? = nil) {
        // regenerate config files
        do {
            try Manager.sharedManager.regenerateConfigFiles()
        }catch {
            complete?(nil, error)
            return
        }
        // Load provider
        loadAndCreateProviderManager { (manager, error) -> Void in
            if let error = error {
                complete?(nil, error)
            }else{
                guard let manager = manager else {
                    complete?(nil, ManagerError.InvalidProvider)
                    return
                }
                if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                    do {
                        try manager.connection.startVPNTunnel(options: options)
                        self.addVPNStatusObserver()
                        complete?(manager, nil)
                    }catch {
                        complete?(nil, error)
                    }
                }else{
                    self.addVPNStatusObserver()
                    complete?(manager, nil)
                }
            }
        }
    }
    
    public func stopVPN() {
        // Stop provider
        loadProviderManager { (manager) -> Void in
            guard let manager = manager else {
                return
            }
            manager.connection.stopVPNTunnel()
        }
    }
    
    public func postMessage() {
        loadProviderManager { (manager) -> Void in
            if let session = manager?.connection as? NETunnelProviderSession,
                let message = "Hello".data(using: String.Encoding.utf8), manager?.connection.status != .invalid
            {
                do {
                    try session.sendProviderMessage(message) { response in
                        
                    }
                } catch {
                    print("Failed to send a message to the provider")
                }
            }
        }
    }
    
    private func loadAndCreateProviderManager(complete: @escaping (NETunnelProviderManager?, Error?) -> Void ) {
        NETunnelProviderManager.loadAllFromPreferences { [unowned self] (managers, error) -> Void in
            if let managers = managers {
                let manager: NETunnelProviderManager
                if managers.count > 0 {
                    manager = managers[0]
                }else{
                    manager = self.createProviderManager()
                }
                manager.isEnabled = true
                manager.localizedDescription = "PacketSniffer"
                manager.protocolConfiguration?.serverAddress = "PacketSniffer"
                manager.isOnDemandEnabled = true
                let quickStartRule = NEOnDemandRuleEvaluateConnection()
                quickStartRule.connectionRules = [NEEvaluateConnectionRule(matchDomains: ["packetsniffer.com"], andAction: NEEvaluateConnectionRuleAction.connectIfNeeded)]
                manager.onDemandRules = [quickStartRule]
                manager.saveToPreferences(completionHandler: { (error) -> Void in
                    if let error = error {
                        complete(nil, error)
                    }else{
                        manager.loadFromPreferences(completionHandler: { (error) -> Void in
                            if let error = error {
                                complete(nil, error)
                            }else{
                                complete(manager, nil)
                            }
                        })
                    }
                })
            }else{
                complete(nil, error)
            }
        }
    }
    
    public func loadProviderManager(complete: @escaping (NETunnelProviderManager?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) -> Void in
            if let managers = managers {
                if managers.count > 0 {
                    let manager = managers[0]
                    complete(manager)
                    return
                }
            }
            complete(nil)
        }
    }
    
    private func createProviderManager() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        manager.protocolConfiguration = NETunnelProviderProtocol()
        return manager
    }
}

