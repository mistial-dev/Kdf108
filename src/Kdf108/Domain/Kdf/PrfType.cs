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

namespace Kdf108.Domain.Kdf;

/// <summary>
///     Enumeration of supported pseudorandom function types for key derivation
/// </summary>
public enum PrfType
{
    // HMAC PRFs
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,

    // CMAC PRFs
    CmacAes128,
    CmacAes192,
    CmacAes256,
    CmacTdes3
}
