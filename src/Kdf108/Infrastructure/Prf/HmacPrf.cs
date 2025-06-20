﻿// -----------------------------------------------------------------------------
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
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    /// <summary>
    /// Provides an implementation of a Pseudorandom Function (PRF) using HMAC (Hashed Message Authentication Code).
    /// </summary>
    public sealed class HmacPrf : IPrf
    {
        /// <summary>
        /// Delegate function responsible for producing instances of <see cref="IDigest"/>.
        /// Used to create hash function implementations required by the HMAC algorithm.
        /// </summary>
        private readonly Func<IDigest> _digestFactory;

        /// <summary>
        /// A pseudorandom function (PRF) implementation based on HMAC (Hash-based Message Authentication Code).
        /// </summary>
        public HmacPrf(Func<IDigest> digestFactory) =>
            _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));

        /// <summary>
        /// Gets the output size of the pseudorandom function in bits.
        /// </summary>
        /// <remarks>
        /// For HMAC-based implementations, the output size is determined by the size
        /// of the underlying hash function used. For example, for SHA-256, the output
        /// size will be 256 bits.
        /// </remarks>
        public int OutputSizeBits => _digestFactory().GetDigestSize() * 8;

        /// <summary>
        /// Computes a pseudorandom value using the specified key and data, based on the provided HMAC digest algorithm.
        /// </summary>
        /// <param name="key">The cryptographic key used for the HMAC computation.</param>
        /// <param name="data">The input data to be processed with the key.</param>
        /// <returns>A byte array containing the computed pseudorandom value.</returns>
        public byte[] Compute(byte[] key, byte[] data) =>
            CreateHmacInstance(key)
                .ApplyData(data)
                .GetResult();

        /// <summary>
        /// Creates an instance of the HMac class configured with the provided key.
        /// </summary>
        /// <param name="key">The secret key to initialize the HMAC instance.</param>
        /// <returns>An initialized HMac instance using the specified key.</returns>
        private HMac CreateHmacInstance(byte[] key)
        {
            IDigest? digest = _digestFactory();
            HMac hmac = new(digest);
            hmac.Init(new KeyParameter(key));
            return hmac;
        }
    }
}
