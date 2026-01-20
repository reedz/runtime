// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Based on GXHash by ogxd (https://github.com/ogxd/gxhash)
// Original implementation licensed under MIT.

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using ArmAes = System.Runtime.Intrinsics.Arm.Aes;
using X86Aes = System.Runtime.Intrinsics.X86.Aes;

namespace System
{
    /// <summary>
    /// GXHash - A fast non-cryptographic hash function leveraging AES hardware instructions.
    /// </summary>
    internal static class GxHash
    {
        private const int VectorSize = 16;
        private const int UnrollFactor = 8;

        /// <summary>
        /// Returns true if GXHash is supported on the current platform.
        /// </summary>
        public static bool IsSupported
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => X86Aes.IsSupported || ArmAes.IsSupported;
        }

        /// <summary>
        /// Gets the default 128-bit seed for hashing, generated randomly per process.
        /// </summary>
        public static UInt128 DefaultSeed { get; } = GenerateSeed();

        private static unsafe UInt128 GenerateSeed()
        {
            UInt128 seed;
            Interop.GetRandomBytes((byte*)&seed, sizeof(UInt128));
            return seed;
        }

        /// <summary>
        /// Compute a GXHash and collapse it into a 32-bit hash.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ComputeHash32(ReadOnlySpan<byte> data, UInt128 seed)
        {
            return Finalize(CompressFast(Compress(ref MemoryMarshal.GetReference(data), data.Length), Unsafe.As<UInt128, Vector128<byte>>(ref seed)))
                .AsInt32().GetElement(0);
        }

        /// <summary>
        /// Compute a GXHash and collapse it into a 32-bit hash.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ComputeHash32(ref byte data, int length, UInt128 seed)
        {
            return Finalize(CompressFast(Compress(ref data, length), Unsafe.As<UInt128, Vector128<byte>>(ref seed)))
                .AsInt32().GetElement(0);
        }

        /// <summary>
        /// Compute a GXHash for OrdinalIgnoreCase comparison and collapse it into a 32-bit hash.
        /// The input is treated as a char span (UTF-16), uppercased, and then hashed.
        /// n.b. <paramref name="count"/> is specified as char count, not byte count.
        /// </summary>
        public static int ComputeHash32OrdinalIgnoreCase(ref char data, int count, UInt128 seed)
        {
            // For the OrdinalIgnoreCase comparison, we need to uppercase and then hash.
            // This ensures that str.ToUpperInvariant().GetHashCode() == str.GetHashCode(OrdinalIgnoreCase)
            char[]? borrowedArr = null;
            Span<char> scratch = (uint)count <= 64 ? stackalloc char[64] : (borrowedArr = ArrayPool<char>.Shared.Rent(count));

            int charsWritten = Globalization.Ordinal.ToUpperOrdinal(new ReadOnlySpan<char>(ref data, count), scratch);

            // Compute hash on the uppercased string
            int hash = ComputeHash32(
                ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(scratch)),
                charsWritten * 2 /* in bytes, not chars */,
                seed);

            // Return the borrowed array if necessary.
            if (borrowedArr is not null)
            {
                ArrayPool<char>.Shared.Return(borrowedArr);
            }

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Finalize(Vector128<byte> input)
        {
            Vector128<byte> keys1 = Vector128.Create(0x713b01d0u, 0x8f2f35dbu, 0xaf163956u, 0x85459f85u).AsByte();
            Vector128<byte> keys2 = Vector128.Create(0x1de09647u, 0x92cfa39cu, 0x3dd99acau, 0xb89c054fu).AsByte();
            Vector128<byte> keys3 = Vector128.Create(0xc78b122bu, 0x5544b1b7u, 0x689d2b7du, 0xd0012e32u).AsByte();

            Vector128<byte> output = input;

            if (ArmAes.IsSupported)
            {
                // ARM Neon AES intrinsics differ from x86, requiring additional operations
                // See https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a
                output = ArmAes.MixColumns(ArmAes.Encrypt(output, Vector128<byte>.Zero)) ^ keys1;
                output = ArmAes.MixColumns(ArmAes.Encrypt(output, Vector128<byte>.Zero)) ^ keys2;
                output = ArmAes.Encrypt(output, Vector128<byte>.Zero) ^ keys3;
            }
            else if (X86Aes.IsSupported)
            {
                output = X86Aes.Encrypt(output, keys1);
                output = X86Aes.Encrypt(output, keys2);
                output = X86Aes.EncryptLast(output, keys3);
            }

            return output;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Compress(ref byte data, int length)
        {
            ref Vector128<byte> ptr = ref Unsafe.As<byte, Vector128<byte>>(ref data);

            if (length <= VectorSize)
            {
                // Input fits on a single SIMD vector
                return GetPartialVector(ref ptr, length);
            }

            Vector128<byte> hashVector;
            int remainingBytes;

            int extraBytesCount = length % VectorSize;
            if (extraBytesCount == 0)
            {
                hashVector = ptr;
                ptr = ref Unsafe.Add(ref ptr, 1);
                remainingBytes = length - VectorSize;
            }
            else
            {
                // Start with the partial vector first for safe read-beyond
                hashVector = GetPartialVectorUnsafe(ref ptr, extraBytesCount);
                ptr = ref Unsafe.AddByteOffset(ref ptr, extraBytesCount);
                remainingBytes = length - extraBytesCount;
            }

            if (length <= VectorSize * 2)
            {
                // Fast path: 17-32 bytes
                hashVector = CompressTwo(hashVector, ptr);
            }
            else if (length <= VectorSize * 3)
            {
                // Fast path: 33-48 bytes
                hashVector = CompressTwo(hashVector, CompressTwo(ptr, Unsafe.Add(ref ptr, 1)));
            }
            else
            {
                // Large input: use high ILP loop
                hashVector = CompressMany(ref ptr, hashVector, remainingBytes);
            }

            return hashVector;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> CompressMany(ref Vector128<byte> start, Vector128<byte> hashVector, int len)
        {
            int unrollableBlocksCount = len / (VectorSize * UnrollFactor) * UnrollFactor;
            ref Vector128<byte> end2 = ref Unsafe.Add(ref start, unrollableBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end2))
            {
                Vector128<byte> blockHash = start;
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 1));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 2));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 3));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 4));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 5));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 6));
                blockHash = CompressFast(blockHash, Unsafe.Add(ref start, 7));
                start = ref Unsafe.Add(ref start, UnrollFactor);

                hashVector = CompressTwo(hashVector, blockHash);
            }

            int remainingBlocksCount = len / VectorSize - unrollableBlocksCount;
            ref Vector128<byte> end = ref Unsafe.Add(ref start, remainingBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end))
            {
                hashVector = CompressTwo(hashVector, start);
                start = ref Unsafe.Add(ref start, 1);
            }

            return hashVector;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector128<byte> GetPartialVector(ref Vector128<byte> start, int remainingBytes)
        {
            // Check if we can safely read beyond the input
            // 4096 bytes is a conservative value for the page size
            const int PageSize = 0x1000;
            nint address = (nint)Unsafe.AsPointer(ref start);
            nint offsetWithinPage = address & (PageSize - 1);

            if (offsetWithinPage < PageSize - VectorSize)
            {
                return GetPartialVectorUnsafe(ref start, remainingBytes);
            }

            return GetPartialVectorSafe(ref start, remainingBytes);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> GetPartialVectorSafe(ref Vector128<byte> start, int remainingBytes)
        {
            Vector128<byte> input = Vector128<byte>.Zero;
            ref byte source = ref Unsafe.As<Vector128<byte>, byte>(ref start);
            ref byte dest = ref Unsafe.As<Vector128<byte>, byte>(ref input);
            Unsafe.CopyBlockUnaligned(ref dest, ref source, (uint)remainingBytes);
            return Vector128.Add(input, Vector128.Create((byte)remainingBytes));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> GetPartialVectorUnsafe(ref Vector128<byte> start, int remainingBytes)
        {
            Vector128<sbyte> indices = Vector128.Create((sbyte)0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)remainingBytes), indices).AsByte();
            Vector128<byte> hashVector = Vector128.BitwiseAnd(mask, start);
            return Vector128.Add(hashVector, Vector128.Create((byte)remainingBytes));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> CompressTwo(Vector128<byte> a, Vector128<byte> b)
        {
            Vector128<byte> keys1 = Vector128.Create(0xFC3BC28Eu, 0x89C222E5u, 0xB09D3E21u, 0xF2784542u).AsByte();
            Vector128<byte> keys2 = Vector128.Create(0x03FCE279u, 0xCB6B2E9Bu, 0xB361DC58u, 0x39136BD9u).AsByte();

            if (ArmAes.IsSupported)
            {
                b = (ArmAes.MixColumns(ArmAes.Encrypt(b, Vector128<byte>.Zero))) ^ keys1;
                b = (ArmAes.MixColumns(ArmAes.Encrypt(b, Vector128<byte>.Zero))) ^ keys2;
                return ArmAes.Encrypt(a, Vector128<byte>.Zero) ^ b;
            }

            if (X86Aes.IsSupported)
            {
                b = X86Aes.Encrypt(b, keys1);
                b = X86Aes.Encrypt(b, keys2);
                return X86Aes.EncryptLast(a, b);
            }

            return default;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> CompressFast(Vector128<byte> a, Vector128<byte> b)
        {
            if (ArmAes.IsSupported)
            {
                return ArmAes.MixColumns(ArmAes.Encrypt(a, Vector128<byte>.Zero)) ^ b;
            }

            if (X86Aes.IsSupported)
            {
                return X86Aes.Encrypt(a, b);
            }

            return default;
        }
    }
}
