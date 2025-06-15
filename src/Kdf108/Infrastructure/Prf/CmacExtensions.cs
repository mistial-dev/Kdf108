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
///     Provides extension methods for the CMac class from the BouncyCastle encryption library.
/// </summary>
public static class CmacExtensions
{
    /// <summary>
    ///     Adds the specified data to the CMAC instance for calculation.
    /// </summary>
    /// <param name="cmac">The CMAC instance to which the data will be applied.</param>
    /// <param name="data">The data to be processed by the CMAC instance.</param>
    /// <returns>The updated CMAC instance.</returns>
    public static CMac ApplyData(this CMac cmac, byte[] data)
    {
        cmac.BlockUpdate(data, 0, data.Length);
        return cmac;
    }

    /// <summary>
    ///     Computes the final CMAC result and returns the output as a byte array.
    /// </summary>
    /// <param name="cmac">The CMAC instance from which to compute the result.</param>
    /// <returns>The computed CMAC result as a byte array.</returns>
    public static byte[] GetResult(this CMac cmac)
    {
        byte[] output = new byte[cmac.GetMacSize()];
        cmac.DoFinal(output, 0);
        return output;
    }
}
