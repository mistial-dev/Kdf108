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
using System.Collections.Generic;
using System.Linq;

#endregion

namespace Kdf108.Infrastructure;

public static class FunctionalExtensions
{
    // Monadic bind operation - applies a function to a value and returns the result
    public static TResult Bind<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    // Pipeline operation - synonym for Bind, but more expressive for data transformations
    public static TResult Pipe<TSource, TResult>(this TSource source, Func<TSource, TResult> func) => func(source);

    // Apply a side effect function to a value and return the original value
    public static T Tee<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }

    // Map operation for Option<T> pattern (simulated)
    public static TResult? Map<TSource, TResult>(this TSource? source, Func<TSource, TResult> func)
        where TSource : class
        where TResult : class =>
        source != null ? func(source) : null;

    // Safely execute a function that might throw and return a result/default value
    public static TResult? TryExecute<TSource, TResult>(this TSource source, Func<TSource, TResult> func)
        where TResult : class
    {
        try
        {
            return func(source);
        }
        catch
        {
            return null;
        }
    }

    // Transform an enumerable with a function and return the results (eager)
    public static IReadOnlyList<TResult> Transform<TSource, TResult>(
        this IEnumerable<TSource> source,
        Func<TSource, TResult> transform) =>
        source.Select(transform).ToList();
}
