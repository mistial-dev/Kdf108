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
using System.Collections.Generic;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

#endregion

namespace Kdf108.Infrastructure.Prf;

public static class PrfFactory
{
    private static readonly Dictionary<PrfType, Func<IPrf>> s_prfFactories =
        new()
        {
            // HMAC PRFs
            [PrfType.HmacSha1] = () => new HmacPrf(() => new Sha1Digest()),
            [PrfType.HmacSha224] = () => new HmacPrf(() => new Sha224Digest()),
            [PrfType.HmacSha256] = () => new HmacPrf(() => new Sha256Digest()),
            [PrfType.HmacSha384] = () => new HmacPrf(() => new Sha384Digest()),
            [PrfType.HmacSha512] = () => new HmacPrf(() => new Sha512Digest()),

            // CMAC PRFs
            [PrfType.CmacAes128] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacAes192] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacAes256] = () => new CmacPrf(() => new AesEngine(), 128),
            [PrfType.CmacTdes3] = () => new CmacPrf(() => new DesEdeEngine(), 64)
        };

    public static IPrf Create(PrfType type) =>
        s_prfFactories.TryGetValue(type, out Func<IPrf>? factory)
            ? factory()
            : throw new NotSupportedException($"PRF type '{type}' is not supported.");
}
