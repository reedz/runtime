// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.CompilerServices;

namespace System
{
    internal static class A5Hash
    {
        [SkipLocalsInit]
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static uint Hash32(ref byte msg, int msgLen, uint p0, uint p1)
        {
            uint val01 = 0x5555_5555u;
            uint val10 = 0xAAAA_AAAAu;

            uint seed1 = 0x243F_6A88u ^ (uint)msgLen;
            uint seed2 = 0x85A3_08D3u ^ (uint)msgLen;
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
                    UMul64(seed2, seed1, out seed1, out seed2);
                }
            }
            else
            {
                UMul64(seed2 ^ (p1 & val10), seed1 ^ (p0 & val01), out seed1, out seed2);
            }

            uint a, b, c = 0, d = 0;

            if (msgLen < 17)
            {
                if (msgLen > 3)
                {
                    a = LoadU32(ref msg);
                    b = LoadU32(ref Unsafe.Add(ref msg, msgLen - 4));

                    if ((uint)msgLen >= 9u)
                    {
                        c = LoadU32(ref Unsafe.Add(ref msg, 4));
                        d = LoadU32(ref Unsafe.Add(ref msg, msgLen - 8));
                        UMul64(c + seed3, d + seed4, out seed3, out seed4);
                    }

                    return FinalizeHash32(a, b, seed1, seed2, seed3, seed4, val01);
                }

                a = 0;
                b = 0;

                if (msgLen != 0)
                {
                    if (BitConverter.IsLittleEndian)
                    {
                        a = msg;

                        if (msgLen != 1)
                        {
                            a |= (uint)Unsafe.Add(ref msg, 1) << 8;

                            if (msgLen != 2)
                            {
                                a |= (uint)Unsafe.Add(ref msg, 2) << 16;
                            }
                        }
                    }
                    else
                    {
                        a = (uint)msg << 24;

                        if (msgLen != 1)
                        {
                            a |= (uint)Unsafe.Add(ref msg, 1) << 16;

                            if (msgLen != 2)
                            {
                                a |= (uint)Unsafe.Add(ref msg, 2) << 8;
                            }
                        }
                    }
                }

                return FinalizeHash32(a, b, seed1, seed2, seed3, seed4, val01);
            }

            val01 ^= seed1;
            val10 ^= seed2;

            do
            {
                uint s1 = seed1;
                uint s4 = seed4;

                ulong m01 = LoadU64(ref msg);
                ulong m23 = LoadU64(ref Unsafe.Add(ref msg, 8));

                GetWords(m01, out uint m0, out uint m1);
                GetWords(m23, out uint m2, out uint m3);

                UMul64(m0 + seed1, m1 + seed2, out seed1, out seed2);
                UMul64(m2 + seed3, m3 + seed4, out seed3, out seed4);

                msgLen -= 16;
                msg = ref Unsafe.Add(ref msg, 16);

                seed1 += val01;
                seed2 += s4;
                seed3 += s1;
                seed4 += val10;
            }
            while (msgLen > 16);

            ulong ab = LoadU64(ref Unsafe.Add(ref msg, msgLen - 8));
            GetWords(ab, out a, out b);

            if (msgLen >= 9)
            {
                ulong cd = LoadU64(ref Unsafe.Add(ref msg, msgLen - 16));
                GetWords(cd, out c, out d);
                UMul64(c + seed3, d + seed4, out seed3, out seed4);
            }

            return FinalizeHash32(a, b, seed1, seed2, seed3, seed4, val01);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FinalizeHash32(uint a, uint b, uint seed1, uint seed2, uint seed3, uint seed4, uint val01)
        {
            seed1 ^= seed3;
            seed2 ^= seed4;

            UMul64(a + seed1, b + seed2, out seed1, out seed2);
            UMul64(val01 ^ seed1, seed2, out a, out b);

            return a ^ b;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void UMul64(uint u, uint v, out uint rl, out uint rh)
        {
            ulong r = (ulong)u * v;
            rl = (uint)r;
            rh = (uint)(r >> 32);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint LoadU32(ref byte p) => Unsafe.ReadUnaligned<uint>(ref p);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong LoadU64(ref byte p) => Unsafe.ReadUnaligned<ulong>(ref p);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GetWords(ulong value, out uint w0, out uint w1)
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
    }
}
