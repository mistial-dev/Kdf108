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
using System.Collections.Generic;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    /// <summary>
    /// Provides the functionality to create instances of pseudorandom functions (PRFs)
    /// based on the specified <see cref="PrfType"/>.
    /// </summary>
    /// <remarks>
    /// The <see cref="PrfFactory"/> supports a variety of PRF types that are
    /// registered through the factory. Attempting to create an unsupported PRF type
    /// will result in a <see cref="NotSupportedException"/> being thrown.
    /// </remarks>
    /// <example>
    /// To create a PRF instance, use the <see cref="Create"/> method with a
    /// valid <see cref="PrfType"/>. This allows integration of the PRF with
    /// various KDF (Key Derivation Function) modes.
    /// </example>
    public static class PrfFactory
    {
        /// <summary>
        /// A static dictionary that maps pseudorandom function (PRF) types to factory methods for creating their corresponding implementations.
        /// </summary>
        /// <remarks>
        /// This dictionary is used to centralize the instantiation of PRF implementations.
        /// Each key is a value from the <see cref="PrfType"/> enumeration, and the associated value is a factory method
        /// that produces an instance of the <see cref="IPrf"/> interface. Implementations support HMAC-based and CMAC-based PRFs.
        /// </remarks>
        private static readonly Dictionary<PrfType, Func<IPrf>> s_prfFactories =
            new()
            {
                // HMAC PRFs
                [PrfType.HmacSha1] = static () => new HmacPrf(static () => new Sha1Digest()),
                [PrfType.HmacSha224] = static () => new HmacPrf(static () => new Sha224Digest()),
                [PrfType.HmacSha256] = static () => new HmacPrf(static () => new Sha256Digest()),
                [PrfType.HmacSha384] = static () => new HmacPrf(static () => new Sha384Digest()),
                [PrfType.HmacSha512] = static () => new HmacPrf(static () => new Sha512Digest()),

                // CMAC PRFs
                [PrfType.CmacAes128] = static () => new CmacPrf(static () => new AesEngine(), 128),
                [PrfType.CmacAes192] = static () => new CmacPrf(static () => new AesEngine(), 128),
                [PrfType.CmacAes256] = static () => new CmacPrf(static () => new AesEngine(), 128),
                [PrfType.CmacTdes3] = static () => new CmacPrf(static () => new DesEdeEngine(), 64)
            };

        /// <summary>
        /// Creates an instance of an implementation of the IPrf interface based on the specified PRF type.
        /// </summary>
        /// <param name="type">The PRF type to create.</param>
        /// <returns>An instance of IPrf corresponding to the specified PRF type.</returns>
        /// <exception cref="NotSupportedException">Thrown if the specified PRF type is not supported.</exception>
        public static IPrf Create(PrfType type) =>
            s_prfFactories.TryGetValue(type, out Func<IPrf>? factory)
                ? factory()
                : throw new NotSupportedException($"PRF type '{type}' is not supported.");
    }
}
