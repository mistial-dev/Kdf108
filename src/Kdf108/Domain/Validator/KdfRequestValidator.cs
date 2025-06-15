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

using FluentValidation;
using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Validator;

public sealed class KdfRequestValidator : AbstractValidator<KdfRequest>
{
    public KdfRequestValidator()
    {
        RuleFor(x => x.KeyDerivationKey)
            .NotNull()
            .NotEmpty()
            .WithMessage("Base key must be provided and non-empty.");

        RuleFor(x => x.Label)
            .NotNull()
            .WithMessage("Label must be provided.");

        RuleFor(x => x.Context)
            .NotNull()
            .WithMessage("Context must not be null.");

        RuleFor(x => x.OutputLengthBits)
            .GreaterThan(0)
            .WithMessage("Output length must be greater than 0 bits.")
            .Must((request, length) => length <= request.Options.MaxBitsAllowed)
            .WithMessage(req =>
                $"Requested output length ({req.OutputLengthBits} bits) exceeds configured maximum ({req.Options.MaxBitsAllowed} bits).");

        RuleFor(x => x.Options)
            .NotNull()
            .WithMessage("Options must be provided.");

        RuleFor(x => x.Options.CounterLengthBits)
            .InclusiveBetween(8, 32)
            .WithMessage("Counter length must be between 8 and 32 bits (inclusive).");

        RuleFor(x => x.Options.PrfType)
            .IsInEnum()
            .WithMessage("PRF type must be a valid enumeration value.");
    }
}
