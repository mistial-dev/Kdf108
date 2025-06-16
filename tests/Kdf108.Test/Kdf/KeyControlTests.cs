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

using System.Linq;
using System.Reflection;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Infrastructure.Prf;
using NUnit.Framework;

#endregion

namespace Kdf108.Test.Kdf
{
    [TestFixture]
    public class KeyControlTests
    {
        private static readonly MethodInfo CreatePrfInputMethod =
            typeof(CounterModeKdf).GetMethod("CreatePrfInput", BindingFlags.NonPublic | BindingFlags.Static)!;

        private static readonly MethodInfo CreateCounterMethod =
            typeof(CounterModeKdf).GetMethod("CreateCounter", BindingFlags.NonPublic | BindingFlags.Static)!;

        [Test]
        public void CreatePrfInput_BeforeFixed_IncludesKeyControlBlock()
        {
            byte[] counter = (byte[])CreateCounterMethod.Invoke(null, new object[] { 1u, 8 })!;
            byte[] fixedInput = { 0xAA, 0xBB, 0xCC };
            byte[] k0 = { 0x11, 0x22 };

            byte[] input = (byte[])CreatePrfInputMethod.Invoke(
                null, new object[] { counter, fixedInput, CounterLocation.BeforeFixed, k0 })!;

            byte[] expected = counter.Concat(fixedInput).Concat(k0).ToArray();
            Assert.That(input, Is.EqualTo(expected));
        }

        [Test]
        public void CreatePrfInput_AfterFixed_IncludesKeyControlBlock()
        {
            byte[] counter = (byte[])CreateCounterMethod.Invoke(null, new object[] { 1u, 8 })!;
            byte[] fixedInput = { 0xAA, 0xBB, 0xCC };
            byte[] k0 = { 0x11, 0x22 };

            byte[] input = (byte[])CreatePrfInputMethod.Invoke(
                null, new object[] { counter, fixedInput, CounterLocation.AfterFixed, k0 })!;

            byte[] expected = fixedInput.Concat(k0).Concat(counter).ToArray();
            Assert.That(input, Is.EqualTo(expected));
        }
    }
}
