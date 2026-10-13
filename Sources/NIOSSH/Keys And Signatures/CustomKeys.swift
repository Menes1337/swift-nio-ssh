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

import NIOConcurrencyHelpers
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A signature made by a key type implemented outside NIOSSH.
///
/// NIOSSH reads signatures of this type off the wire once the type is registered with
/// ``NIOSSHAlgorithms/register(publicKey:signature:)``.
public protocol NIOSSHSignatureProtocol: Sendable {
    /// The SSH name of the signature algorithm, such as `rsa-sha2-512`.
    ///
    /// The name must be unique among registered signature types, and must not be the name of an algorithm
    /// NIOSSH implements.
    static var signaturePrefix: String { get }

    /// The raw bytes of the signature. NIOSSH compares and hashes signatures by these bytes.
    var rawRepresentation: Data { get }

    /// Writes the signature blob that follows the algorithm name on the wire.
    ///
    /// - Returns: The number of bytes written.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads a signature blob written by ``write(to:)``.
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

/// A public key of a type implemented outside NIOSSH.
///
/// NIOSSH reads keys of this type off the wire, and clients offer it as a host key algorithm, once the type is
/// registered with ``NIOSSHAlgorithms/register(publicKey:signature:)``.
public protocol NIOSSHPublicKeyProtocol: Sendable {
    /// The SSH name of the key type, such as `ssh-rsa`.
    ///
    /// The name must be unique among registered key types, and must not be the name of a key type NIOSSH
    /// implements.
    static var publicKeyPrefix: String { get }

    /// The raw bytes of the key. NIOSSH compares and hashes keys by these bytes.
    var rawRepresentation: Data { get }

    /// Returns whether `signature` is a signature over `data` made by the private key behind this public key.
    func isValidSignature<D: DataProtocol>(_ signature: any NIOSSHSignatureProtocol, for data: D) -> Bool

    /// Writes the key blob that follows the key type name on the wire.
    ///
    /// - Returns: The number of bytes written.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads a key blob written by ``write(to:)``.
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

/// A private key of a type implemented outside NIOSSH.
///
/// Wrap it with ``NIOSSHPrivateKey/init(custom:)`` to use it as a host key or a user authentication key.
public protocol NIOSSHPrivateKeyProtocol: Sendable {
    /// The SSH name of the key type, such as `ssh-rsa`.
    static var keyPrefix: String { get }

    /// The public key that verifies this key's signatures.
    var publicKey: any NIOSSHPublicKeyProtocol { get }

    /// Signs `data` with this key's default signature algorithm.
    func signature<D: DataProtocol>(for data: D) throws -> any NIOSSHSignatureProtocol
}

extension NIOSSHSignatureProtocol {
    var signaturePrefix: String { Self.signaturePrefix }
}

extension NIOSSHPublicKeyProtocol {
    var publicKeyPrefix: String { Self.publicKeyPrefix }
}

extension NIOSSHPrivateKeyProtocol {
    var keyPrefix: String { Self.keyPrefix }
}

/// The process-wide registry of key and signature types implemented outside NIOSSH.
public enum NIOSSHAlgorithms: Sendable {
    /// Registers a public key type and a signature type implemented outside NIOSSH.
    ///
    /// Once registered, every connection in the process reads keys of type `PublicKey` and signatures of type
    /// `Signature` off the wire, and every client offers `PublicKey.publicKeyPrefix` as a host key algorithm,
    /// after the algorithms NIOSSH implements. Registration lasts for the life of the process, and registering a
    /// type again has no effect. Register the types before starting the connections that need them.
    public static func register<PublicKey: NIOSSHPublicKeyProtocol, Signature: NIOSSHSignatureProtocol>(
        publicKey: PublicKey.Type,
        signature: Signature.Type
    ) {
        Self.registry.withLockedValue { registry in
            if !registry.publicKeys.contains(where: { $0 == publicKey }) {
                registry.publicKeys.append(publicKey)
            }
            if !registry.signatures.contains(where: { $0 == signature }) {
                registry.signatures.append(signature)
            }
        }
    }

    /// The registered public key types, in registration order.
    static var publicKeys: [any NIOSSHPublicKeyProtocol.Type] {
        Self.registry.withLockedValue { $0.publicKeys }
    }

    /// The registered signature types, in registration order.
    static var signatures: [any NIOSSHSignatureProtocol.Type] {
        Self.registry.withLockedValue { $0.signatures }
    }

    /// Removes every registration. Tests share the process-wide registry, so they use this to start from empty.
    static func _unregisterAll() {
        Self.registry.withLockedValue { $0 = Registry() }
    }

    private struct Registry: Sendable {
        var publicKeys: [any NIOSSHPublicKeyProtocol.Type] = []
        var signatures: [any NIOSSHSignatureProtocol.Type] = []
    }

    private static let registry = NIOLockedValueBox(Registry())
}
