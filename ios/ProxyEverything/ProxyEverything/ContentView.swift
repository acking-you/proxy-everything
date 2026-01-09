//
//  ContentView.swift
//  ProxyEverything
//

import SwiftUI

struct ContentView: View {
    @State private var serverHost = ""
    @State private var serverPort = "1081"
    @State private var localPort = "1080"
    @State private var sessionKey = ""
    @State private var isRunning = false
    @State private var statusMessage = "Proxy stopped"
    @State private var showingInstructions = false
    @State private var autoProxy = true
    @State private var reverseGeo = false

    private let proxyCore = ProxyCore()

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Server Configuration")) {
                    TextField("Server Host", text: $serverHost)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .disabled(isRunning)

                    TextField("Server Port", text: $serverPort)
                        .keyboardType(.numberPad)
                        .disabled(isRunning)

                    TextField("Local Port", text: $localPort)
                        .keyboardType(.numberPad)
                        .disabled(isRunning)

                    SecureField("Session Key", text: $sessionKey)
                        .disabled(isRunning)
                }

                Section(header: Text("Proxy Mode")) {
                    Toggle("Auto Proxy (Geo-based)", isOn: $autoProxy)
                        .disabled(isRunning)

                    if autoProxy {
                        Toggle("Reverse Geo", isOn: $reverseGeo)
                            .disabled(isRunning)
                        Text(reverseGeo ? "CN → Proxy, Others → Direct" : "CN → Direct, Others → Proxy")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Section(header: Text("Status")) {
                    HStack {
                        Circle()
                            .fill(isRunning ? Color.green : Color.red)
                            .frame(width: 12, height: 12)
                        Text(statusMessage)
                    }
                }

                Section {
                    Button(action: toggleProxy) {
                        HStack {
                            Spacer()
                            Text(isRunning ? "Stop Proxy" : "Start Proxy")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .foregroundColor(isRunning ? .red : .blue)
                }

                if isRunning {
                    Section(header: Text("Setup Instructions")) {
                        Button("How to configure iOS proxy") {
                            showingInstructions = true
                        }
                    }
                }
            }
            .navigationTitle("Proxy")
            .sheet(isPresented: $showingInstructions) {
                ProxyInstructionsView(port: localPort)
            }
        }
    }

    private func toggleProxy() {
        if isRunning {
            if proxyCore.stop() {
                isRunning = false
                statusMessage = "Proxy stopped"
            } else {
                statusMessage = "Failed to stop proxy"
            }
        } else {
            guard !serverHost.isEmpty else {
                statusMessage = "Please enter server host"
                return
            }
            guard !sessionKey.isEmpty else {
                statusMessage = "Please enter session key"
                return
            }
            guard let sPort = UInt16(serverPort), let lPort = UInt16(localPort) else {
                statusMessage = "Invalid port number"
                return
            }

            if proxyCore.start(serverHost: serverHost, serverPort: sPort, localPort: lPort, sessionKey: sessionKey, autoProxy: autoProxy, reverseGeo: reverseGeo) {
                isRunning = true
                let modeDesc = autoProxy ? (reverseGeo ? "reverse-geo" : "auto-proxy") : "all-proxy"
                statusMessage = "Running on 127.0.0.1:\(localPort) (\(modeDesc))"
            } else {
                statusMessage = "Failed to start proxy"
            }
        }
    }
}

struct ProxyInstructionsView: View {
    let port: String
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("WiFi Proxy Setup")) {
                    Text("1. Open Settings app")
                    Text("2. Tap Wi-Fi")
                    Text("3. Tap the (i) next to your network")
                    Text("4. Scroll down, tap Configure Proxy")
                    Text("5. Select Manual")
                    Text("6. Server: 127.0.0.1")
                    Text("7. Port: \(port)")
                    Text("8. Tap Save")
                }

                Section(header: Text("Note")) {
                    Text("This only proxies WiFi traffic. Cellular data will not go through the proxy.")
                        .foregroundColor(.secondary)
                    Text("Remember to set proxy back to Off when done.")
                        .foregroundColor(.orange)
                }
            }
            .navigationTitle("Setup Guide")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

#Preview {
    ContentView()
}
