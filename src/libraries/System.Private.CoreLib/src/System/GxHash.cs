// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Based on GXHash by ogxd (https://github.com/ogxd/gxhash)
// Original implementation licensed under MIT.

using System.Buffers;
using System.Diagnostics;
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

        // Pre-computed constants to avoid per-call materialization
        private static readonly Vector128<byte> FinalizeKeys1 = Vector128.Create(0x713b01d0u, 0x8f2f35dbu, 0xaf163956u, 0x85459f85u).AsByte();
        private static readonly Vector128<byte> FinalizeKeys2 = Vector128.Create(0x1de09647u, 0x92cfa39cu, 0x3dd99acau, 0xb89c054fu).AsByte();
        private static readonly Vector128<byte> FinalizeKeys3 = Vector128.Create(0xc78b122bu, 0x5544b1b7u, 0x689d2b7du, 0xd0012e32u).AsByte();
        private static readonly Vector128<byte> CompressKeys1 = Vector128.Create(0xFC3BC28Eu, 0x89C222E5u, 0xB09D3E21u, 0xF2784542u).AsByte();
        private static readonly Vector128<byte> CompressKeys2 = Vector128.Create(0x03FCE279u, 0xCB6B2E9Bu, 0xB361DC58u, 0x39136BD9u).AsByte();
        private static readonly Vector128<sbyte> Indices = Vector128.Create((sbyte)0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        private static readonly Vector128<short> CharIndices = Vector128.Create((short)0, 1, 2, 3, 4, 5, 6, 7);

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
            return ComputeHash32(ref MemoryMarshal.GetReference(data), data.Length, seed);
        }

        /// <summary>
        /// Compute a GXHash and collapse it into a 32-bit hash.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ComputeHash32(ref byte data, int length, UInt128 seed)
        {
            if (X86Aes.IsSupported)
            {
                return ComputeHash32X86(ref data, length, seed);
            }

            if (ArmAes.IsSupported)
            {
                return ComputeHash32Arm(ref data, length, seed);
            }

            // Should not reach here if IsSupported was checked
            return 0;
        }

        /// <summary>
        /// Compute a GXHash for OrdinalIgnoreCase comparison and collapse it into a 32-bit hash.
        /// The input is treated as a char span (UTF-16), uppercased, and then hashed.
        /// n.b. <paramref name="count"/> is specified as char count, not byte count.
        /// </summary>
        public static int ComputeHash32OrdinalIgnoreCase(ref char data, int count, UInt128 seed)
        {
            if (X86Aes.IsSupported)
            {
                return ComputeHash32OrdinalIgnoreCaseX86(ref data, count, seed);
            }

            if (ArmAes.IsSupported)
            {
                return ComputeHash32OrdinalIgnoreCaseArm(ref data, count, seed);
            }

            return 0;
        }

        /// <summary>
        /// Check if UTF-16 chars in a vector are all ASCII and uppercase them.
        /// Only checks/uppercases the first 'count' chars (remaining positions may contain garbage).
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool TryUppercaseAsciiVector(Vector128<ushort> chars, int count, out Vector128<ushort> uppercased)
        {
            // Vectorized ASCII check: mask out garbage positions, then check high bits
            // CharIndices = [0,1,2,3,4,5,6,7] as short
            Vector128<ushort> validMask = Vector128.GreaterThan(Vector128.Create((short)count), CharIndices).AsUInt16();
            Vector128<ushort> maskedChars = chars & validMask;

            // Check if any valid char has high bit set (non-ASCII)
            Vector128<ushort> asciiMask = Vector128.Create((ushort)0xFF80);
            if ((maskedChars & asciiMask) != Vector128<ushort>.Zero)
            {
                uppercased = default;
                return false;
            }

            // Branchless uppercase: XOR with 0x20 if char is in [a-z]
            Vector128<ushort> lowerIndicator = chars + Vector128.Create((ushort)(0x0080 - 0x0061));
            Vector128<ushort> upperIndicator = chars + Vector128.Create((ushort)(0x0080 - 0x007B));
            Vector128<ushort> combined = lowerIndicator ^ upperIndicator;
            Vector128<ushort> caseFlipMask = (combined & Vector128.Create((ushort)0x0080)) >> 2;
            uppercased = chars ^ caseFlipMask;
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static int ComputeHash32OrdinalIgnoreCaseX86(ref char data, int count, UInt128 seed)
        {
            Debug.Assert(X86Aes.IsSupported);

            if (count == 0)
            {
                Vector128<byte> empty = Vector128<byte>.Zero;
                Vector128<byte> hash = X86Aes.Encrypt(empty, Unsafe.As<UInt128, Vector128<byte>>(ref seed));
                return FinalizeX86(hash).AsInt32().GetElement(0);
            }

            ref byte bytePtr = ref Unsafe.As<char, byte>(ref data);
            int byteCount = count * 2;

            // For single vector (≤8 chars), inline uppercase + hash
            if (count <= 8)
            {
                Vector128<ushort> chars;
                bool needMask = count < 8;

                // Check page boundary for safe reading
                unsafe
                {
                    nint address = (nint)Unsafe.AsPointer(ref bytePtr);
                    nint offsetWithinPage = address & 0xFFF;
                    if (offsetWithinPage > 0x1000 - 16)
                    {
                        // Near page boundary - use safe copy
                        Span<ushort> temp = stackalloc ushort[8];
                        temp.Clear();
                        Unsafe.CopyBlockUnaligned(ref Unsafe.As<ushort, byte>(ref temp[0]), ref bytePtr, (uint)byteCount);
                        chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref temp[0]));
                    }
                    else
                    {
                        // Safe to read full 16 bytes
                        chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref bytePtr);
                    }
                }

                if (!TryUppercaseAsciiVector(chars, count, out Vector128<ushort> uppercased))
                {
                    goto SlowPath;
                }

                Vector128<byte> hashVector = uppercased.AsByte();
                if (needMask)
                {
                    Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)byteCount), Indices).AsByte();
                    hashVector = Vector128.BitwiseAnd(mask, hashVector);
                }
                hashVector = Vector128.Add(hashVector, Vector128.Create((byte)byteCount));

                Vector128<byte> hash = X86Aes.Encrypt(hashVector, Unsafe.As<UInt128, Vector128<byte>>(ref seed));
                return FinalizeX86(hash).AsInt32().GetElement(0);
            }

            // Multi-vector path: process 8 chars at a time with inline uppercase
            {
                ref ushort ptr = ref Unsafe.As<byte, ushort>(ref bytePtr);
                int fullVectors = count / 8;
                int remainder = count % 8;
                Vector128<byte> hashVector;

                // Process first partial chunk if any
                if (remainder > 0)
                {
                    int remainderBytes = remainder * 2;
                    Vector128<ushort> chars;

                    unsafe
                    {
                        nint address = (nint)Unsafe.AsPointer(ref Unsafe.As<ushort, byte>(ref ptr));
                        nint offsetWithinPage = address & 0xFFF;
                        if (offsetWithinPage > 0x1000 - 16)
                        {
                            Span<ushort> temp = stackalloc ushort[8];
                            temp.Clear();
                            Unsafe.CopyBlockUnaligned(ref Unsafe.As<ushort, byte>(ref temp[0]),
                                ref Unsafe.As<ushort, byte>(ref ptr), (uint)remainderBytes);
                            chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref temp[0]));
                        }
                        else
                        {
                            chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                        }
                    }

                    if (!TryUppercaseAsciiVector(chars, remainder, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }

                    hashVector = uppercased.AsByte();
                    Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)remainderBytes), Indices).AsByte();
                    hashVector = Vector128.BitwiseAnd(mask, hashVector);
                    hashVector = Vector128.Add(hashVector, Vector128.Create((byte)remainderBytes));
                    ptr = ref Unsafe.Add(ref ptr, remainder);
                }
                else
                {
                    Vector128<ushort> chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                    if (!TryUppercaseAsciiVector(chars, 8, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }
                    hashVector = uppercased.AsByte();
                    ptr = ref Unsafe.Add(ref ptr, 8);
                    fullVectors--;
                }

                // Process remaining full vectors
                for (int i = 0; i < fullVectors; i++)
                {
                    Vector128<ushort> chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                    if (!TryUppercaseAsciiVector(chars, 8, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }
                    hashVector = CompressTwoX86(hashVector, uppercased.AsByte());
                    ptr = ref Unsafe.Add(ref ptr, 8);
                }

                Vector128<byte> hash = X86Aes.Encrypt(hashVector, Unsafe.As<UInt128, Vector128<byte>>(ref seed));
                return FinalizeX86(hash).AsInt32().GetElement(0);
            }

        SlowPath:
            return ComputeHash32OrdinalIgnoreCaseSlow(ref data, count, seed);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static int ComputeHash32OrdinalIgnoreCaseArm(ref char data, int count, UInt128 seed)
        {
            Debug.Assert(ArmAes.IsSupported);

            if (count == 0)
            {
                Vector128<byte> empty = Vector128<byte>.Zero;
                Vector128<byte> hash = ArmAes.MixColumns(ArmAes.Encrypt(empty, Vector128<byte>.Zero)) ^ Unsafe.As<UInt128, Vector128<byte>>(ref seed);
                return FinalizeArm(hash).AsInt32().GetElement(0);
            }

            ref byte bytePtr = ref Unsafe.As<char, byte>(ref data);
            int byteCount = count * 2;

            // For single vector (≤8 chars), inline uppercase + hash
            if (count <= 8)
            {
                Vector128<ushort> chars;
                bool needMask = count < 8;

                unsafe
                {
                    nint address = (nint)Unsafe.AsPointer(ref bytePtr);
                    nint offsetWithinPage = address & 0xFFF;
                    if (offsetWithinPage > 0x1000 - 16)
                    {
                        Span<ushort> temp = stackalloc ushort[8];
                        temp.Clear();
                        Unsafe.CopyBlockUnaligned(ref Unsafe.As<ushort, byte>(ref temp[0]), ref bytePtr, (uint)byteCount);
                        chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref temp[0]));
                    }
                    else
                    {
                        chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref bytePtr);
                    }
                }

                if (!TryUppercaseAsciiVector(chars, count, out Vector128<ushort> uppercased))
                {
                    goto SlowPath;
                }

                Vector128<byte> hashVector = uppercased.AsByte();
                if (needMask)
                {
                    Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)byteCount), Indices).AsByte();
                    hashVector = Vector128.BitwiseAnd(mask, hashVector);
                }
                hashVector = Vector128.Add(hashVector, Vector128.Create((byte)byteCount));

                Vector128<byte> hash = ArmAes.MixColumns(ArmAes.Encrypt(hashVector, Vector128<byte>.Zero)) ^ Unsafe.As<UInt128, Vector128<byte>>(ref seed);
                return FinalizeArm(hash).AsInt32().GetElement(0);
            }

            // Multi-vector path
            {
                ref ushort ptr = ref Unsafe.As<byte, ushort>(ref bytePtr);
                int fullVectors = count / 8;
                int remainder = count % 8;
                Vector128<byte> hashVector;

                if (remainder > 0)
                {
                    int remainderBytes = remainder * 2;
                    Vector128<ushort> chars;

                    unsafe
                    {
                        nint address = (nint)Unsafe.AsPointer(ref Unsafe.As<ushort, byte>(ref ptr));
                        nint offsetWithinPage = address & 0xFFF;
                        if (offsetWithinPage > 0x1000 - 16)
                        {
                            Span<ushort> temp = stackalloc ushort[8];
                            temp.Clear();
                            Unsafe.CopyBlockUnaligned(ref Unsafe.As<ushort, byte>(ref temp[0]),
                                ref Unsafe.As<ushort, byte>(ref ptr), (uint)remainderBytes);
                            chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref temp[0]));
                        }
                        else
                        {
                            chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                        }
                    }

                    if (!TryUppercaseAsciiVector(chars, remainder, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }

                    hashVector = uppercased.AsByte();
                    Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)remainderBytes), Indices).AsByte();
                    hashVector = Vector128.BitwiseAnd(mask, hashVector);
                    hashVector = Vector128.Add(hashVector, Vector128.Create((byte)remainderBytes));
                    ptr = ref Unsafe.Add(ref ptr, remainder);
                }
                else
                {
                    Vector128<ushort> chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                    if (!TryUppercaseAsciiVector(chars, 8, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }
                    hashVector = uppercased.AsByte();
                    ptr = ref Unsafe.Add(ref ptr, 8);
                    fullVectors--;
                }

                for (int i = 0; i < fullVectors; i++)
                {
                    Vector128<ushort> chars = Unsafe.ReadUnaligned<Vector128<ushort>>(ref Unsafe.As<ushort, byte>(ref ptr));
                    if (!TryUppercaseAsciiVector(chars, 8, out Vector128<ushort> uppercased))
                    {
                        goto SlowPath;
                    }
                    hashVector = CompressTwoArm(hashVector, uppercased.AsByte());
                    ptr = ref Unsafe.Add(ref ptr, 8);
                }

                Vector128<byte> hash = ArmAes.MixColumns(ArmAes.Encrypt(hashVector, Vector128<byte>.Zero)) ^ Unsafe.As<UInt128, Vector128<byte>>(ref seed);
                return FinalizeArm(hash).AsInt32().GetElement(0);
            }

        SlowPath:
            return ComputeHash32OrdinalIgnoreCaseSlow(ref data, count, seed);
        }

        private static int ComputeHash32OrdinalIgnoreCaseSlow(ref char data, int count, UInt128 seed)
        {
            char[]? borrowedArr = null;
            Span<char> scratch = (uint)count <= 64 ? stackalloc char[64] : (borrowedArr = ArrayPool<char>.Shared.Rent(count));

            int charsWritten = Globalization.Ordinal.ToUpperOrdinal(new ReadOnlySpan<char>(ref data, count), scratch);

            int hash = ComputeHash32(
                ref Unsafe.As<char, byte>(ref MemoryMarshal.GetReference(scratch)),
                charsWritten * 2,
                seed);

            if (borrowedArr is not null)
            {
                ArrayPool<char>.Shared.Return(borrowedArr);
            }

            return hash;
        }

        // ==================== X86 AES Implementation ====================

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static int ComputeHash32X86(ref byte data, int length, UInt128 seed)
        {
            Debug.Assert(X86Aes.IsSupported);

            Vector128<byte> hash = CompressX86(ref data, length);
            hash = X86Aes.Encrypt(hash, Unsafe.As<UInt128, Vector128<byte>>(ref seed));
            return FinalizeX86(hash).AsInt32().GetElement(0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static Vector128<byte> FinalizeX86(Vector128<byte> input)
        {
            Debug.Assert(X86Aes.IsSupported);

            Vector128<byte> output = X86Aes.Encrypt(input, FinalizeKeys1);
            output = X86Aes.Encrypt(output, FinalizeKeys2);
            return X86Aes.EncryptLast(output, FinalizeKeys3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static Vector128<byte> CompressX86(ref byte data, int length)
        {
            Debug.Assert(X86Aes.IsSupported);

            ref Vector128<byte> ptr = ref Unsafe.As<byte, Vector128<byte>>(ref data);

            if (length <= VectorSize)
            {
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
                hashVector = GetPartialVectorUnsafe(ref ptr, extraBytesCount);
                ptr = ref Unsafe.AddByteOffset(ref ptr, extraBytesCount);
                remainingBytes = length - extraBytesCount;
            }

            if (length <= VectorSize * 2)
            {
                return CompressTwoX86(hashVector, ptr);
            }

            if (length <= VectorSize * 3)
            {
                return CompressTwoX86(hashVector, CompressTwoX86(ptr, Unsafe.Add(ref ptr, 1)));
            }

            return CompressManyX86(ref ptr, hashVector, remainingBytes);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static Vector128<byte> CompressManyX86(ref Vector128<byte> start, Vector128<byte> hashVector, int len)
        {
            Debug.Assert(X86Aes.IsSupported);

            int unrollableBlocksCount = len / (VectorSize * UnrollFactor) * UnrollFactor;
            ref Vector128<byte> end2 = ref Unsafe.Add(ref start, unrollableBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end2))
            {
                Vector128<byte> blockHash = start;
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 1));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 2));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 3));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 4));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 5));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 6));
                blockHash = X86Aes.Encrypt(blockHash, Unsafe.Add(ref start, 7));
                start = ref Unsafe.Add(ref start, UnrollFactor);

                hashVector = CompressTwoX86(hashVector, blockHash);
            }

            int remainingBlocksCount = len / VectorSize - unrollableBlocksCount;
            ref Vector128<byte> end = ref Unsafe.Add(ref start, remainingBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end))
            {
                hashVector = CompressTwoX86(hashVector, start);
                start = ref Unsafe.Add(ref start, 1);
            }

            return hashVector;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(X86Aes))]
        private static Vector128<byte> CompressTwoX86(Vector128<byte> a, Vector128<byte> b)
        {
            Debug.Assert(X86Aes.IsSupported);

            b = X86Aes.Encrypt(b, CompressKeys1);
            b = X86Aes.Encrypt(b, CompressKeys2);
            return X86Aes.EncryptLast(a, b);
        }

        // ==================== ARM AES Implementation ====================

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static int ComputeHash32Arm(ref byte data, int length, UInt128 seed)
        {
            Debug.Assert(ArmAes.IsSupported);

            Vector128<byte> hash = CompressArm(ref data, length);
            hash = ArmAes.MixColumns(ArmAes.Encrypt(hash, Vector128<byte>.Zero)) ^ Unsafe.As<UInt128, Vector128<byte>>(ref seed);
            return FinalizeArm(hash).AsInt32().GetElement(0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static Vector128<byte> FinalizeArm(Vector128<byte> input)
        {
            Debug.Assert(ArmAes.IsSupported);

            Vector128<byte> output = ArmAes.MixColumns(ArmAes.Encrypt(input, Vector128<byte>.Zero)) ^ FinalizeKeys1;
            output = ArmAes.MixColumns(ArmAes.Encrypt(output, Vector128<byte>.Zero)) ^ FinalizeKeys2;
            return ArmAes.Encrypt(output, Vector128<byte>.Zero) ^ FinalizeKeys3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static Vector128<byte> CompressArm(ref byte data, int length)
        {
            Debug.Assert(ArmAes.IsSupported);

            ref Vector128<byte> ptr = ref Unsafe.As<byte, Vector128<byte>>(ref data);

            if (length <= VectorSize)
            {
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
                hashVector = GetPartialVectorUnsafe(ref ptr, extraBytesCount);
                ptr = ref Unsafe.AddByteOffset(ref ptr, extraBytesCount);
                remainingBytes = length - extraBytesCount;
            }

            if (length <= VectorSize * 2)
            {
                return CompressTwoArm(hashVector, ptr);
            }

            if (length <= VectorSize * 3)
            {
                return CompressTwoArm(hashVector, CompressTwoArm(ptr, Unsafe.Add(ref ptr, 1)));
            }

            return CompressManyArm(ref ptr, hashVector, remainingBytes);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static Vector128<byte> CompressManyArm(ref Vector128<byte> start, Vector128<byte> hashVector, int len)
        {
            Debug.Assert(ArmAes.IsSupported);

            int unrollableBlocksCount = len / (VectorSize * UnrollFactor) * UnrollFactor;
            ref Vector128<byte> end2 = ref Unsafe.Add(ref start, unrollableBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end2))
            {
                Vector128<byte> blockHash = start;
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 1);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 2);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 3);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 4);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 5);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 6);
                blockHash = ArmAes.MixColumns(ArmAes.Encrypt(blockHash, Vector128<byte>.Zero)) ^ Unsafe.Add(ref start, 7);
                start = ref Unsafe.Add(ref start, UnrollFactor);

                hashVector = CompressTwoArm(hashVector, blockHash);
            }

            int remainingBlocksCount = len / VectorSize - unrollableBlocksCount;
            ref Vector128<byte> end = ref Unsafe.Add(ref start, remainingBlocksCount);

            while (Unsafe.IsAddressLessThan(ref start, ref end))
            {
                hashVector = CompressTwoArm(hashVector, start);
                start = ref Unsafe.Add(ref start, 1);
            }

            return hashVector;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [CompExactlyDependsOn(typeof(ArmAes))]
        private static Vector128<byte> CompressTwoArm(Vector128<byte> a, Vector128<byte> b)
        {
            Debug.Assert(ArmAes.IsSupported);

            b = ArmAes.MixColumns(ArmAes.Encrypt(b, Vector128<byte>.Zero)) ^ CompressKeys1;
            b = ArmAes.MixColumns(ArmAes.Encrypt(b, Vector128<byte>.Zero)) ^ CompressKeys2;
            return ArmAes.Encrypt(a, Vector128<byte>.Zero) ^ b;
        }

        // ==================== Shared Helper Methods ====================

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector128<byte> GetPartialVector(ref Vector128<byte> start, int remainingBytes)
        {
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
            Vector128<byte> mask = Vector128.GreaterThan(Vector128.Create((sbyte)remainingBytes), Indices).AsByte();
            Vector128<byte> hashVector = Vector128.BitwiseAnd(mask, start);
            return Vector128.Add(hashVector, Vector128.Create((byte)remainingBytes));
        }
    }
}
