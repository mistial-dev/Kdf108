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
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf;

public sealed class HmacPrf : IPrf
{
    private readonly Func<IDigest> _digestFactory;

    public HmacPrf(Func<IDigest> digestFactory) =>
        _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));

    public int OutputSizeBits => _digestFactory().GetDigestSize() * 8;

    public byte[] Compute(byte[] key, byte[] data) =>
        CreateHmacInstance(key)
            .ApplyData(data)
            .GetResult();

    private HMac CreateHmacInstance(byte[] key)
    {
        IDigest? digest = _digestFactory();
        HMac hmac = new(digest);
        hmac.Init(new KeyParameter(key));
        return hmac;
    }
}
