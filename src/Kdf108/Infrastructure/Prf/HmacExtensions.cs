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

using Org.BouncyCastle.Crypto.Macs;

#endregion

namespace Kdf108.Infrastructure.Prf;

/// <summary>
/// Provides extension methods for working with HMac instances from the BouncyCastle library.
/// </summary>
public static class HmacExtensions
{
    /// <summary>
    /// Updates the provided HMAC instance with the specified data and returns the updated instance.
    /// </summary>
    /// <param name="hmac">The HMAC instance to which the data will be applied.</param>
    /// <param name="data">The byte array data to update the HMAC with.</param>
    /// <returns>The updated HMAC instance after applying the data.</returns>
    public static HMac ApplyData(this HMac hmac, byte[] data)
    {
        hmac.BlockUpdate(data, 0, data.Length);
        return hmac;
    }

    /// <summary>
    /// Finalizes the HMAC computation and retrieves the generated MAC (Message Authentication Code) as a byte array.
    /// </summary>
    /// <param name="hmac">The HMac instance on which the final computation is performed.</param>
    /// <returns>A byte array containing the generated MAC value.</returns>
    public static byte[] GetResult(this HMac hmac)
    {
        byte[] output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }
}
