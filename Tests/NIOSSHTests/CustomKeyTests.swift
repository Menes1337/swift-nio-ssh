//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// A key type NIOSSH does not implement: Ed25519 under another name, so its signatures are real.
private struct TestPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "test-key@example.com"

    var key: Curve25519.Signing.PublicKey

    var rawRepresentation: Data { self.key.rawRepresentation }

    func isValidSignature<D: DataProtocol>(_ signature: any NIOSSHSignatureProtocol, for data: D) -> Bool {
        guard let signature = signature as? TestSignature else {
            return false
        }
        return self.key.isValidSignature(signature.rawRepresentation, for: Data(data))
    }

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.key.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> TestPublicKey {
        guard let bytes = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "truncated test key")
        }
        return TestPublicKey(key: try .init(rawRepresentation: bytes.readableBytesView))
    }
}

private struct TestSignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "test-key@example.com"

    var rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> TestSignature {
        guard let bytes = buffer.readSSHString() else {
            throw NIOSSHError.invalidSSHMessage(reason: "truncated test signature")
        }
        return TestSignature(rawRepresentation: Data(bytes.readableBytesView))
    }
}

private struct TestPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = "test-key@example.com"

    var key = Curve25519.Signing.PrivateKey()

    var publicKey: any NIOSSHPublicKeyProtocol { TestPublicKey(key: self.key.publicKey) }

    func signature<D: DataProtocol>(for data: D) throws -> any NIOSSHSignatureProtocol {
        TestSignature(rawRepresentation: try self.key.signature(for: Data(data)))
    }
}

private final class RecordingHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
    private(set) var hostKeys: [NIOSSHPublicKey] = []

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        self.hostKeys.append(hostKey)
        validationCompletePromise.succeed(())
    }
}

final class CustomKeyTests: XCTestCase {
    override func setUp() {
        NIOSSHAlgorithms._unregisterAll()
    }

    override func tearDown() {
        NIOSSHAlgorithms._unregisterAll()
    }

    func testRegisteredCustomKeysWorkAsHostKeyAndUserKey() throws {
        NIOSSHAlgorithms.register(publicKey: TestPublicKey.self, signature: TestSignature.self)

        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        let hostKey = NIOSSHPrivateKey(custom: TestPrivateKey())
        let userKey = NIOSSHPrivateKey(custom: TestPrivateKey())
        let hostKeyDelegate = RecordingHostKeyDelegate()
        var harness = TestHarness()
        harness.serverHostKeys = [hostKey]
        harness.clientServerAuthDelegate = hostKeyDelegate
        harness.clientAuthDelegate = PrivateKeyClientAuth(userKey)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(userKey.publicKey)

        // The server holds only the custom host key, so the client must offer it, verify the exchange hash
        // signature with it, and then authenticate with the custom user key.
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(hostKeyDelegate.hostKeys, [hostKey.publicKey])

        _ = try channel.createNewChannel()
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)

        let openSSHKey = String(openSSHPublicKey: hostKey.publicKey)
        XCTAssertTrue(openSSHKey.hasPrefix("test-key@example.com "))
        XCTAssertEqual(try NIOSSHPublicKey(openSSHPublicKey: openSSHKey), hostKey.publicKey)
    }

    func testUnregisteredCustomHostKeyIsNotOffered() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        var harness = TestHarness()
        harness.serverHostKeys = [NIOSSHPrivateKey(custom: TestPrivateKey())]

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertThrowsError(try channel.interactInMemory()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyExchangeNegotiationFailure)
        }
    }
}
