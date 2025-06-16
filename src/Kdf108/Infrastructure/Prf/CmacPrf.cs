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
using Kdf108.Domain.Kdf.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf
{
    public sealed class CmacPrf : IPrf
    {
        private readonly Func<IBlockCipher> _cipherFactory;

        public CmacPrf(Func<IBlockCipher> cipherFactory, int outputSizeBits)
        {
            _cipherFactory = cipherFactory ?? throw new ArgumentNullException(nameof(cipherFactory));
            OutputSizeBits = outputSizeBits;
        }

        public int OutputSizeBits { get; }

        public byte[] Compute(byte[] key, byte[] data) =>
            CreateCmacInstance(key)
                .ApplyData(data)
                .GetResult();

        private CMac CreateCmacInstance(byte[] key)
        {
            // Create a new block cipher instance
            IBlockCipher? cipher = _cipherFactory();

            // Ensure key is appropriate for the cipher
            byte[] adjustedKey = AdjustKeyForCipher(key, cipher);

            // Create and initialize CMAC
            CMac cmac = new(cipher);
            cmac.Init(new KeyParameter(adjustedKey));

            return cmac;
        }

        private static byte[] AdjustKeyForCipher(byte[] key, IBlockCipher cipher)
        {
            // Special handling for TDES, which needs exactly 24 bytes
            if (cipher is DesEdeEngine && key.Length != 24)
            {
                byte[] adjustedKey = new byte[24];
                int copyLength = Math.Min(key.Length, 24);
                Buffer.BlockCopy(key, 0, adjustedKey, 0, copyLength);
                return adjustedKey;
            }

            return key;
        }
    }
}
