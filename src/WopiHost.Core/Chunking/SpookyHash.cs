using System.Buffers.Binary;

namespace WopiHost.Core.Chunking;

/// <summary>
/// Streaming SpookyHash V2 (128-bit) — Bob Jenkins' public-domain non-cryptographic
/// hash. Feed bytes with <see cref="Update(byte[], int, int)"/> (any number of calls,
/// any fragment sizes) and read the 16-byte result with <see cref="Digest"/>. The
/// output is identical to the reference SpookyV2 implementation on little-endian hosts.
/// </summary>
/// <remarks>
/// This is the hashing primitive required by the WOPI incremental-file-transfer
/// spec (the per-chunk identifier is the Base64 encoding of this 16-byte digest).
/// </remarks>
public sealed class SpookyHash
{
    private const int NumVars = 12;
    private const int BlockSize = NumVars * 8;   // 96
    private const int BufSize = 2 * BlockSize;   // 192
    private const ulong ScConst = 0xdeadbeefdeadbeefUL;

    private readonly byte[] _data = new byte[BufSize];
    private readonly ulong[] _state = new ulong[NumVars];
    private ulong _length;
    private int _remainder;

    /// <summary>
    /// Initializes a new <see cref="SpookyHash"/> with the given 128-bit seed
    /// (defaults to zero, which is what the WOPI file-transfer chunk hashes use).
    /// </summary>
    /// <param name="seed1">Low 64 bits of the seed.</param>
    /// <param name="seed2">High 64 bits of the seed.</param>
    public SpookyHash(ulong seed1 = 0, ulong seed2 = 0)
    {
        _length = 0;
        _remainder = 0;
        _state[0] = seed1;
        _state[1] = seed2;
    }

    /// <summary>Feeds an entire buffer into the hash.</summary>
    /// <param name="buffer">The bytes to hash.</param>
    public void Update(byte[] buffer)
    {
        System.ArgumentNullException.ThrowIfNull(buffer);
        Update(buffer, 0, buffer.Length);
    }

    /// <summary>Feeds a range of a buffer into the hash.</summary>
    /// <param name="buffer">The source buffer.</param>
    /// <param name="offset">Start index within <paramref name="buffer"/>.</param>
    /// <param name="count">Number of bytes to hash.</param>
    public void Update(byte[] buffer, int offset, int count)
    {
        System.ArgumentNullException.ThrowIfNull(buffer);
        unchecked
        {
            ulong[] h = new ulong[12];
            long newLength = (long)count + _remainder;
            int pos;

            if (newLength < BufSize)
            {
                System.Array.Copy(buffer, offset, _data, _remainder, count);
                _length += (ulong)count;
                _remainder = (int)newLength;
                return;
            }

            if (_length < (ulong)BufSize)
            {
                h[0] = h[3] = h[6] = h[9] = _state[0];
                h[1] = h[4] = h[7] = h[10] = _state[1];
                h[2] = h[5] = h[8] = h[11] = ScConst;
            }
            else
            {
                for (int i = 0; i < 12; i++) h[i] = _state[i];
            }
            _length += (ulong)count;

            if (_remainder != 0)
            {
                int prefix = BufSize - _remainder;
                System.Array.Copy(buffer, offset, _data, _remainder, prefix);
                Mix(h, _data, 0);
                Mix(h, _data, BlockSize);
                pos = offset + prefix;
                count -= prefix;
            }
            else
            {
                pos = offset;
            }

            int endPos = pos + (count / BlockSize) * BlockSize;
            int rem = count - (endPos - pos);
            while (pos < endPos)
            {
                Mix(h, buffer, pos);
                pos += BlockSize;
            }

            _remainder = rem;
            System.Array.Copy(buffer, pos, _data, 0, rem);

            for (int i = 0; i < 12; i++) _state[i] = h[i];
        }
    }

    /// <summary>
    /// Produces the 16-byte SpookyHash digest of everything fed so far
    /// (low 64 bits then high 64 bits, little-endian).
    /// </summary>
    /// <returns>The 16-byte hash.</returns>
    public byte[] Digest()
    {
        ulong hash1, hash2;
        unchecked
        {
            if (_length < (ulong)BufSize)
            {
                hash1 = _state[0];
                hash2 = _state[1];
                Short(_data, 0, (int)_length, ref hash1, ref hash2);
            }
            else
            {
                ulong[] h = new ulong[12];
                for (int i = 0; i < 12; i++) h[i] = _state[i];
                int remainder = _remainder;
                int dataOff = 0;

                if (remainder >= BlockSize)
                {
                    Mix(h, _data, dataOff);
                    dataOff += BlockSize;
                    remainder -= BlockSize;
                }

                System.Array.Clear(_data, dataOff + remainder, BlockSize - remainder);
                _data[dataOff + BlockSize - 1] = (byte)remainder;

                End(h, _data, dataOff);
                hash1 = h[0];
                hash2 = h[1];
            }
        }

        byte[] digest = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(digest.AsSpan(0), hash1);
        BinaryPrimitives.WriteUInt64LittleEndian(digest.AsSpan(8), hash2);
        return digest;
    }

    private static ulong Rot64(ulong x, int k) => (x << k) | (x >> (64 - k));
    private static ulong R64(byte[] b, int off) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(off, 8));
    private static uint R32(byte[] b, int off) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off, 4));

    private static void Mix(ulong[] s, byte[] data, int o)
    {
        unchecked
        {
            s[0] += R64(data, o + 0 * 8);  s[2] ^= s[10]; s[11] ^= s[0];  s[0] = Rot64(s[0], 11);  s[11] += s[1];
            s[1] += R64(data, o + 1 * 8);  s[3] ^= s[11]; s[0] ^= s[1];   s[1] = Rot64(s[1], 32);  s[0] += s[2];
            s[2] += R64(data, o + 2 * 8);  s[4] ^= s[0];  s[1] ^= s[2];   s[2] = Rot64(s[2], 43);  s[1] += s[3];
            s[3] += R64(data, o + 3 * 8);  s[5] ^= s[1];  s[2] ^= s[3];   s[3] = Rot64(s[3], 31);  s[2] += s[4];
            s[4] += R64(data, o + 4 * 8);  s[6] ^= s[2];  s[3] ^= s[4];   s[4] = Rot64(s[4], 17);  s[3] += s[5];
            s[5] += R64(data, o + 5 * 8);  s[7] ^= s[3];  s[4] ^= s[5];   s[5] = Rot64(s[5], 28);  s[4] += s[6];
            s[6] += R64(data, o + 6 * 8);  s[8] ^= s[4];  s[5] ^= s[6];   s[6] = Rot64(s[6], 39);  s[5] += s[7];
            s[7] += R64(data, o + 7 * 8);  s[9] ^= s[5];  s[6] ^= s[7];   s[7] = Rot64(s[7], 57);  s[6] += s[8];
            s[8] += R64(data, o + 8 * 8);  s[10] ^= s[6]; s[7] ^= s[8];   s[8] = Rot64(s[8], 55);  s[7] += s[9];
            s[9] += R64(data, o + 9 * 8);  s[11] ^= s[7]; s[8] ^= s[9];   s[9] = Rot64(s[9], 54);  s[8] += s[10];
            s[10] += R64(data, o + 10 * 8); s[0] ^= s[8]; s[9] ^= s[10];  s[10] = Rot64(s[10], 22); s[9] += s[11];
            s[11] += R64(data, o + 11 * 8); s[1] ^= s[9]; s[10] ^= s[11]; s[11] = Rot64(s[11], 46); s[10] += s[0];
        }
    }

    private static void EndPartial(ulong[] h)
    {
        unchecked
        {
            h[11] += h[1];  h[2] ^= h[11];  h[1] = Rot64(h[1], 44);
            h[0] += h[2];   h[3] ^= h[0];   h[2] = Rot64(h[2], 15);
            h[1] += h[3];   h[4] ^= h[1];   h[3] = Rot64(h[3], 34);
            h[2] += h[4];   h[5] ^= h[2];   h[4] = Rot64(h[4], 21);
            h[3] += h[5];   h[6] ^= h[3];   h[5] = Rot64(h[5], 38);
            h[4] += h[6];   h[7] ^= h[4];   h[6] = Rot64(h[6], 33);
            h[5] += h[7];   h[8] ^= h[5];   h[7] = Rot64(h[7], 10);
            h[6] += h[8];   h[9] ^= h[6];   h[8] = Rot64(h[8], 13);
            h[7] += h[9];   h[10] ^= h[7];  h[9] = Rot64(h[9], 38);
            h[8] += h[10];  h[11] ^= h[8];  h[10] = Rot64(h[10], 53);
            h[9] += h[11];  h[0] ^= h[9];   h[11] = Rot64(h[11], 42);
            h[10] += h[0];  h[1] ^= h[10];  h[0] = Rot64(h[0], 54);
        }
    }

    private static void End(ulong[] h, byte[] data, int o)
    {
        unchecked
        {
            for (int i = 0; i < 12; i++) h[i] += R64(data, o + i * 8);
            EndPartial(h);
            EndPartial(h);
            EndPartial(h);
        }
    }

    private static void ShortMix(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3)
    {
        unchecked
        {
            h2 = Rot64(h2, 50); h2 += h3; h0 ^= h2;
            h3 = Rot64(h3, 52); h3 += h0; h1 ^= h3;
            h0 = Rot64(h0, 30); h0 += h1; h2 ^= h0;
            h1 = Rot64(h1, 41); h1 += h2; h3 ^= h1;
            h2 = Rot64(h2, 54); h2 += h3; h0 ^= h2;
            h3 = Rot64(h3, 48); h3 += h0; h1 ^= h3;
            h0 = Rot64(h0, 38); h0 += h1; h2 ^= h0;
            h1 = Rot64(h1, 37); h1 += h2; h3 ^= h1;
            h2 = Rot64(h2, 62); h2 += h3; h0 ^= h2;
            h3 = Rot64(h3, 34); h3 += h0; h1 ^= h3;
            h0 = Rot64(h0, 5);  h0 += h1; h2 ^= h0;
            h1 = Rot64(h1, 36); h1 += h2; h3 ^= h1;
        }
    }

    private static void ShortEnd(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3)
    {
        unchecked
        {
            h3 ^= h2; h2 = Rot64(h2, 15); h3 += h2;
            h0 ^= h3; h3 = Rot64(h3, 52); h0 += h3;
            h1 ^= h0; h0 = Rot64(h0, 26); h1 += h0;
            h2 ^= h1; h1 = Rot64(h1, 51); h2 += h1;
            h3 ^= h2; h2 = Rot64(h2, 28); h3 += h2;
            h0 ^= h3; h3 = Rot64(h3, 9);  h0 += h3;
            h1 ^= h0; h0 = Rot64(h0, 47); h1 += h0;
            h2 ^= h1; h1 = Rot64(h1, 54); h2 += h1;
            h3 ^= h2; h2 = Rot64(h2, 32); h3 += h2;
            h0 ^= h3; h3 = Rot64(h3, 25); h0 += h3;
            h1 ^= h0; h0 = Rot64(h0, 63); h1 += h0;
        }
    }

    private static void Short(byte[] message, int msgOff, int length, ref ulong hash1, ref ulong hash2)
    {
        unchecked
        {
            int pos = msgOff;
            int remainder = length % 32;
            ulong a = hash1, b = hash2, c = ScConst, d = ScConst;

            if (length > 15)
            {
                int endPos = msgOff + (length / 32) * 32;
                for (; pos < endPos; pos += 32)
                {
                    c += R64(message, pos + 0);
                    d += R64(message, pos + 8);
                    ShortMix(ref a, ref b, ref c, ref d);
                    a += R64(message, pos + 16);
                    b += R64(message, pos + 24);
                }
                if (remainder >= 16)
                {
                    c += R64(message, pos + 0);
                    d += R64(message, pos + 8);
                    ShortMix(ref a, ref b, ref c, ref d);
                    pos += 16;
                    remainder -= 16;
                }
            }

            d += ((ulong)length) << 56;
            switch (remainder)
            {
                case 15: d += ((ulong)message[pos + 14]) << 48; goto case 14;
                case 14: d += ((ulong)message[pos + 13]) << 40; goto case 13;
                case 13: d += ((ulong)message[pos + 12]) << 32; goto case 12;
                case 12: d += R32(message, pos + 8); c += R64(message, pos + 0); break;
                case 11: d += ((ulong)message[pos + 10]) << 16; goto case 10;
                case 10: d += ((ulong)message[pos + 9]) << 8; goto case 9;
                case 9:  d += (ulong)message[pos + 8]; goto case 8;
                case 8:  c += R64(message, pos + 0); break;
                case 7:  c += ((ulong)message[pos + 6]) << 48; goto case 6;
                case 6:  c += ((ulong)message[pos + 5]) << 40; goto case 5;
                case 5:  c += ((ulong)message[pos + 4]) << 32; goto case 4;
                case 4:  c += R32(message, pos + 0); break;
                case 3:  c += ((ulong)message[pos + 2]) << 16; goto case 2;
                case 2:  c += ((ulong)message[pos + 1]) << 8; goto case 1;
                case 1:  c += (ulong)message[pos + 0]; break;
                case 0:  c += ScConst; d += ScConst; break;
            }
            ShortEnd(ref a, ref b, ref c, ref d);
            hash1 = a;
            hash2 = b;
        }
    }
}
