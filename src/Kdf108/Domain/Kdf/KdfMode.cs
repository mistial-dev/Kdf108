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
///     Defines the supported modes for the Key Derivation Function (KDF) operation, used to generate cryptographic keys.
/// </summary>
/// <remarks>
///     Each mode determines a specific algorithmic approach for deriving keys using the input parameters such as the key
///     derivation key (KDK), label, and context.
///     The choice of mode impacts the security properties and suitability for different cryptographic applications.
/// </remarks>
public enum KdfMode
{
    /// <summary>
    ///     Represents the counter mode for deriving cryptographic keys in a Key Derivation Function (KDF).
    /// </summary>
    /// <remarks>
    ///     Counter mode involves the use of a monotonically increasing counter value, combined with input values
    ///     such as the key derivation key (KDK), label, and context, to generate cryptographic keys.
    ///     This mode is particularly suitable for applications requiring sequential key generation with
    ///     deterministic outputs.
    /// </remarks>
    Counter,

    /// <summary>
    ///     Represents the feedback mode of operation for key derivation functions (KDF).
    /// </summary>
    /// <remarks>
    ///     In Feedback mode, the output of the previous iteration is fed back as an input to the next iteration,
    ///     in combination with the key derivation key (KDK), label, and context. This iterative design facilitates
    ///     the generation of keys with enhanced cryptographic properties while ensuring deterministic outputs.
    ///     Feedback mode is particularly useful in scenarios requiring strong dependency on prior iteration outputs.
    /// </remarks>
    Feedback,

    /// <summary>
    ///     Represents the feedback with counter mode of operation for key derivation functions (KDF).
    /// </summary>
    /// <remarks>
    ///     In Feedback with Counter mode, the output of the previous iteration is combined with the current counter value
    ///     and input parameters such as the key derivation key (KDK), label, and context. This iterative process generates a
    ///     sequence of pseudorandom outputs. The mode is designed to enhance security and ensure deterministic key generation
    ///     while incorporating feedback into the derivation process.
    /// </remarks>
    FeedbackWithCounter,

    /// <summary>
    ///     Represents the double pipeline mode of operation for key derivation functions (KDF).
    /// </summary>
    /// <remarks>
    ///     In Double Pipeline mode, two parallel cryptographic function pipelines are used to process the key derivation key
    ///     (KDK),
    ///     label, and context. This mode enhances security by incorporating multiple rounds of iterations and combining
    ///     outputs
    ///     from two independent pipelines to generate the derived key material.
    /// </remarks>
    DoublePipeline,

    /// <summary>
    ///     Represents the double pipeline mode with counter for key derivation functions (KDF).
    /// </summary>
    /// <remarks>
    ///     In DoublePipelineWithCounter mode, a double pipeline structure is combined with a counter mechanism to derive
    ///     cryptographic keys.
    ///     This mode enhances key generation versatility and security by utilizing iterative processing of the key derivation
    ///     key (KDK),
    ///     label, context, and a counter value to produce a deterministic sequence of outputs.
    ///     It is particularly suited for advanced cryptographic operations where both pipeline and counter features are
    ///     required.
    /// </remarks>
    DoublePipelineWithCounter
}
