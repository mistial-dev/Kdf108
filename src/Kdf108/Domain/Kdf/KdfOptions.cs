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

using JetBrains.Annotations;

#endregion

namespace Kdf108.Domain.Kdf
{
    /// <summary>
    ///     Represents configuration options for a Key Derivation Function (KDF).
    /// </summary>
    [PublicAPI]
    public sealed class KdfOptions
    {
        public KdfOptions()
        {
        }

        public KdfOptions(PrfType prfType, int counterLengthBits, bool useCounter, CounterLocation counterLocation)
        {
            PrfType = prfType;
            CounterLengthBits = counterLengthBits;
            UseCounter = useCounter;
            CounterLocation = counterLocation;
        }

        /// <summary>
        ///     Gets the type of pseudorandom function (PRF) used for the key derivation process.
        /// </summary>
        /// <remarks>
        ///     Determines the algorithm used to generate the pseudorandom output for key derivation.
        ///     Available options include HMAC-based algorithms (e.g. HmacSha256) and CMAC-based
        ///     algorithms (e.g. CmacAes128). The default value is <see cref="PrfType.HmacSha256" />.
        /// </remarks>
        public PrfType PrfType { get; set; } = PrfType.HmacSha256;

        /// <summary>
        ///     Specifies the length, in bits, of the counter used in the key derivation function (KDF).
        /// </summary>
        /// <remarks>
        ///     The counter is incorporated into the derivation process to ensure unique keys are generated for each iteration
        ///     of the KDF. Its value directly impacts the size of the counter and, by extension, the structure of the derived key.
        ///     Acceptable values are between 8 and 32 bits, inclusive.
        /// </remarks>
        public int CounterLengthBits { get; set; } = 32;

        /// <summary>
        ///     Gets the Initialization Vector (IV) used in key derivation operations.
        ///     This property supports scenarios that require a feedback mechanism,
        ///     such as specific KDF modes like Feedback Mode, where the IV acts as an
        ///     input to the cryptographic function. The IV, if provided, is used
        ///     alongside other inputs such as the key derivation key (KDK),
        ///     label, and context to produce derived keys. If null, a default value
        ///     (such as an empty byte array in Feedback Mode) is used.
        /// </summary>
        public byte[]? Iv { get; set; }

        /// <summary>
        ///     Gets a value indicating whether a counter is utilised as part of the key derivation process.
        /// </summary>
        /// <remarks>
        ///     When set to <c>true</c>, a counter mechanism is included, typically used in counter-based
        ///     key derivation methods (e.g., counter mode). When set to <c>false</c>, the derivation
        ///     process excludes the counter, often applicable in feedback or pipeline-based modes.
        /// </remarks>
        public bool UseCounter { get; set; } = true;

        /// <summary>
        ///     Gets or sets the position of the counter in the KDF input.
        /// </summary>
        public CounterLocation CounterLocation { get; set; } = CounterLocation.BeforeFixed;

        /// <summary>
        ///     Specifies the maximum number of bits allowed for the derived output length.
        /// </summary>
        /// <remarks>
        ///     This property is used to set an upper limit on the output size (in bits) that can be requested during
        ///     key derivation operations. Any request exceeding this value will be considered invalid.
        /// </remarks>
        /// <value>
        ///     A long representing the maximum permissible number of bits for output. Defaults to 8192 bits.
        /// </value>
        public long MaxBitsAllowed { get; set; } = 8192;

        /// Creates and returns a new instance of the KdfOptionsBuilder, which can be used to configure and build a KdfOptions object.
        /// <return>A KdfOptionsBuilder instance to assist in building a KdfOptions object.</return>
        public static KdfOptionsBuilder CreateBuilder() => new();

        /// Creates and returns a new instance of KdfOptions with the same property values as the current instance.
        /// <return>A new KdfOptions instance that is a copy of the current instance.</return>
        public KdfOptions Clone() => new KdfOptions
        {
            PrfType = PrfType,
            CounterLengthBits = CounterLengthBits,
            Iv = Iv,
            UseCounter = UseCounter,
            CounterLocation = CounterLocation,
            MaxBitsAllowed = MaxBitsAllowed
        };
    }
}
