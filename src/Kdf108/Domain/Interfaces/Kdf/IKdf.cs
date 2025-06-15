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

using System;
using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Interfaces.Kdf;

/// <summary>
///     Interface for key derivation functions that generate keying material from a key-derivation key.
/// </summary>
public interface IKdf
{
    /// <summary>
    ///     Derives a key using the key-derivation function.
    /// </summary>
    /// <param name="kdk">The key-derivation key.</param>
    /// <param name="label">A string that identifies the purpose for the derived keying material.</param>
    /// <param name="context">Context information related to the derived keying material.</param>
    /// <param name="outputLengthInBits">The length of the derived keying material in bits.</param>
    /// <param name="options">Options for configuring the key derivation function.</param>
    /// <returns>The derived keying material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when a parameter has an invalid value.</exception>
    /// <exception cref="FluentValidation.ValidationException">Thrown when validation fails.</exception>
    byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options);
}
