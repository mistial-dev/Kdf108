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

using Org.BouncyCastle.Utilities.Encoders;

#endregion

namespace Kdf108.Internal;

/// <summary>
///     Provides utility methods for converting data between hexadecimal string
///     representations and byte arrays.
/// </summary>
/// <remarks>
///     This utility class offers two static methods:
///     <c>FromHexString</c> and <c>ToHexString</c>. These methods specifically
///     facilitate encoding and decoding operations that convert between byte arrays
///     and their corresponding hexadecimal representations. The class leverages
///     third-party utilities to handle the conversions with precision.
///     Purpose-built for scenarios requiring the manipulation of cryptographic
///     and binary data in hexadecimal format, the methods ensure efficient and
///     reliable data transformations.
/// </remarks>
#if NET5_0_OR_GREATER
    using System;
#endif

public static class ConvertCompat
{
#if NET5_0_OR_GREATER

    public static byte[] FromHexString(string hex) => Convert.FromHexString(hex);
    public static string ToHexString(byte[] data) => Convert.ToHexString(data);
#else
    public static byte[] FromHexString(string hex) => Hex.Decode(hex);

    public static string ToHexString(byte[] data) => Hex.ToHexString(data);
#endif
}
