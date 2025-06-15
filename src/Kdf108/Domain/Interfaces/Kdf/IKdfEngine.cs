// -----------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// -----------------------------------------------------------------------------

#region

using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Interfaces.Kdf;

/// <summary>
/// Represents a key derivation function (KDF) engine interface for generating
/// cryptographic keys from an established key derivation key (KDK).
/// </summary>
public interface IKdfEngine
{
    /// <summary>
    /// Derives a key based on the input key derivation key (KDK) and the specified options.
    /// </summary>
    /// <param name="mode">The key derivation function (KDF) mode to be used.</param>
    /// <param name="kdk">The key derivation key (KDK) as a byte array.</param>
    /// <param name="label">A string label used in the derivation process.</param.
    /// <param name="context">A byte array representing the context information for the derivation process.</param>
    /// <param name="outputLengthInBits">The desired output length in bits for the derived key.</param>
    /// <param name="options">The options that dictate specific behaviors or configurations of the KDF.</param>
    /// <returns>A byte array representing the derived key.</returns>
    byte[] Derive(
        KdfMode mode,
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthInBits,
        KdfOptions options);
}
