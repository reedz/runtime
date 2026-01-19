// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace System
{
    internal static partial class Marvin
    {
        /// <summary>
        /// Compute a Marvin OrdinalIgnoreCase hash and collapse it into a 32-bit hash.
        /// n.b. <paramref name="count"/> is specified as char count, not byte count.
        /// </summary>
        public static int ComputeHash32OrdinalIgnoreCase(ref char data, int count, uint p0, uint p1)
        {
            if (s_useA5Hash)
            {
                if (count == 0)
                {
                    return ComputeHash32(ref Unsafe.As<char, byte>(ref data), 0, p0, p1);
                }

                return ComputeHash32OrdinalIgnoreCaseA5Hash(ref data, count, p0, p1);
            }

            uint ucount = (uint)count; // in chars
            nuint byteOffset = 0; // in bytes
            uint tempValue;

            // We operate on 32-bit integers (two chars) at a time.

            while (ucount >= 2)
            {
                tempValue = Unsafe.ReadUnaligned<uint>(ref Unsafe.As<char, byte>(ref Unsafe.AddByteOffset(ref data, byteOffset)));
                if (!Utf16Utility.AllCharsInUInt32AreAscii(tempValue))
                {
                    goto NotAscii;
                }
                p0 += Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(tempValue);
                Block(ref p0, ref p1);

                byteOffset += 4;
                ucount -= 2;
            }

            // We have either one char (16 bits) or zero chars left over.
            Debug.Assert(ucount < 2);

            if (ucount > 0)
            {
                tempValue = Unsafe.AddByteOffset(ref data, byteOffset);
                if (tempValue > 0x7Fu)
                {
                    goto NotAscii;
                }

                if (BitConverter.IsLittleEndian)
                {
                    // addition is written with -0x80u to allow fall-through to next statement rather than jmp past it
                    p0 += Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(tempValue) + (0x800000u - 0x80u);
                }
                else
                {
                    // as above, addition is modified to allow fall-through to next statement rather than jmp past it
                    p0 += (Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(tempValue) << 16) + 0x8000u - 0x80000000u;
                }
            }
            if (BitConverter.IsLittleEndian)
            {
                p0 += 0x80u;
            }
            else
            {
                p0 += 0x80000000u;
            }

            Block(ref p0, ref p1);
            Block(ref p0, ref p1);

            return (int)(p1 ^ p0);

        NotAscii:
            Debug.Assert(ucount <= int.MaxValue); // this should fit into a signed int
            return ComputeHash32OrdinalIgnoreCaseSlow(ref Unsafe.AddByteOffset(ref data, byteOffset), (int)ucount, p0, p1);
        }

        [SkipLocalsInit]
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static int ComputeHash32OrdinalIgnoreCaseA5Hash(ref char data, int count, uint p0, uint p1)
        {
            Debug.Assert(count > 0);

            // ASCII-only fast path: hash the virtual UTF-16 bytes of the uppercased string without materializing it.
            // If any non-ASCII data is observed, fall back to the existing slow path (full case-folding).

            uint msgLen = (uint)count * 2; // in bytes
            if (msgLen > int.MaxValue)
            {
                return ComputeHash32OrdinalIgnoreCaseSlow(ref data, count, p0, p1);
            }

            uint val01 = 0x5555_5555u;
            uint val10 = 0xAAAA_AAAAu;

            uint seed1 = 0x243F_6A88u ^ msgLen;
            uint seed2 = 0x85A3_08D3u ^ msgLen;
            uint seed3 = 0xFB0B_D3EAu;
            uint seed4 = 0x0F58_FD47u;

            if ((p0 | p1) == 0)
            {
                if (msgLen == 0)
                {
                    seed1 = 0x5831_0E18u;
                    seed2 = 0x12EC_07F9u;
                }
                else
                {
                    UMul64A5(seed2, seed1, out seed1, out seed2);
                }
            }
            else
            {
                UMul64A5(seed2 ^ (p1 & val10), seed1 ^ (p0 & val01), out seed1, out seed2);
            }

            uint a, b;

            if (msgLen < 17)
            {
                if (msgLen > 3)
                {
                    if (!TryLoadU32UpperAscii(ref data, 0, out a) || !TryLoadU32UpperAscii(ref data, (int)((msgLen - 4) / 2), out b))
                    {
                        goto NotAscii;
                    }

                    if (msgLen >= 9)
                    {
                        if (!TryLoadU32UpperAscii(ref data, 2, out uint c) || !TryLoadU32UpperAscii(ref data, (int)((msgLen - 8) / 2), out uint d))
                        {
                            goto NotAscii;
                        }

                        UMul64A5(c + seed3, d + seed4, out seed3, out seed4);
                    }

                    return (int)FinalizeA5Hash32(a, b, seed1, seed2, seed3, seed4, val01);
                }

                a = 0;
                b = 0;

                if (msgLen != 0)
                {
                    char ch = data;
                    if ((uint)ch > 0x7Fu)
                    {
                        goto NotAscii;
                    }

                    ushort u = (ushort)ch;
                    if ((uint)(u - 'a') <= ('z' - 'a'))
                    {
                        u = (ushort)(u - 0x20);
                    }

                    // msgLen == 2 for UTF-16.
                    a = BitConverter.IsLittleEndian ? u : (uint)u << 16;
                }

                return (int)FinalizeA5Hash32(a, b, seed1, seed2, seed3, seed4, val01);
            }

            val01 ^= seed1;
            val10 ^= seed2;

            int charOffset = 0;
            int remainingBytes = (int)msgLen;

            do
            {
                uint s1 = seed1;
                uint s4 = seed4;

                if (!TryLoadU64UpperAscii(ref data, charOffset, out ulong m01) || !TryLoadU64UpperAscii(ref data, charOffset + 4, out ulong m23))
                {
                    goto NotAscii;
                }

                GetWordsA5(m01, out uint m0, out uint m1);
                GetWordsA5(m23, out uint m2, out uint m3);

                UMul64A5(m0 + seed1, m1 + seed2, out seed1, out seed2);
                UMul64A5(m2 + seed3, m3 + seed4, out seed3, out seed4);

                remainingBytes -= 16;
                charOffset += 8;

                seed1 += val01;
                seed2 += s4;
                seed3 += s1;
                seed4 += val10;
            }
            while (remainingBytes > 16);

            int remainingChars = remainingBytes / 2;

            if (!TryLoadU64UpperAscii(ref data, charOffset + (remainingChars - 4), out ulong ab))
            {
                goto NotAscii;
            }

            GetWordsA5(ab, out a, out b);

            if (remainingBytes >= 9)
            {
                if (!TryLoadU64UpperAscii(ref data, charOffset + (remainingChars - 8), out ulong cd))
                {
                    goto NotAscii;
                }

                GetWordsA5(cd, out uint c, out uint d);
                UMul64A5(c + seed3, d + seed4, out seed3, out seed4);
            }

            return (int)FinalizeA5Hash32(a, b, seed1, seed2, seed3, seed4, val01);

        NotAscii:
            return ComputeHash32OrdinalIgnoreCaseSlow(ref data, count, p0, p1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FinalizeA5Hash32(uint a, uint b, uint seed1, uint seed2, uint seed3, uint seed4, uint val01)
        {
            seed1 ^= seed3;
            seed2 ^= seed4;

            UMul64A5(a + seed1, b + seed2, out seed1, out seed2);
            UMul64A5(val01 ^ seed1, seed2, out a, out b);

            return a ^ b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void UMul64A5(uint u, uint v, out uint rl, out uint rh)
        {
            ulong r = (ulong)u * v;
            rl = (uint)r;
            rh = (uint)(r >> 32);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GetWordsA5(ulong value, out uint w0, out uint w1)
        {
            if (BitConverter.IsLittleEndian)
            {
                w0 = (uint)value;
                w1 = (uint)(value >> 32);
            }
            else
            {
                w0 = (uint)(value >> 32);
                w1 = (uint)value;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool TryLoadU32UpperAscii(ref char msg, int charIndex, out uint value)
        {
            uint tempValue = Unsafe.ReadUnaligned<uint>(ref Unsafe.As<char, byte>(ref Unsafe.Add(ref msg, charIndex)));
            if (!Utf16Utility.AllCharsInUInt32AreAscii(tempValue))
            {
                value = 0;
                return false;
            }

            value = Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(tempValue);
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool TryLoadU64UpperAscii(ref char msg, int charIndex, out ulong value)
        {
            ref byte p = ref Unsafe.As<char, byte>(ref Unsafe.Add(ref msg, charIndex));

            uint lo = Unsafe.ReadUnaligned<uint>(ref p);
            uint hi = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref p, 4));

            if (!Utf16Utility.AllCharsInUInt32AreAscii(lo) || !Utf16Utility.AllCharsInUInt32AreAscii(hi))
            {
                value = 0;
                return false;
            }

            lo = Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(lo);
            hi = Utf16Utility.ConvertAllAsciiCharsInUInt32ToUppercase(hi);

            value = BitConverter.IsLittleEndian ? (ulong)lo | ((ulong)hi << 32) : ((ulong)lo << 32) | hi;
            return true;
        }

        private static int ComputeHash32OrdinalIgnoreCaseSlow(ref char data, int count, uint p0, uint p1)
        {
            Debug.Assert(count > 0);

            char[]? borrowedArr = null;
            Span<char> scratch = (uint)count <= 64 ? stackalloc char[64] : (borrowedArr = ArrayPool<char>.Shared.Rent(count));

            int charsWritten = Globalization.Ordinal.ToUpperOrdinal(new ReadOnlySpan<char>(ref data, count), scratch);
            Debug.Assert(charsWritten == count); // invariant case conversion should involve simple folding; preserve code unit count

            // Slice the array to the size returned by ToUpperInvariant.
            // Multiplication below will not overflow since going from positive Int32 to UInt32.
            int hash = ComputeHash32(ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(scratch)), (uint)charsWritten * 2, p0, p1);

            // Return the borrowed array if necessary.
            if (borrowedArr != null)
            {
                ArrayPool<char>.Shared.Return(borrowedArr);
            }

            return hash;
        }
    }
}
