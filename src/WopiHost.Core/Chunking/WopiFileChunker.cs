using System.Buffers.Binary;

namespace WopiHost.Core.Chunking;

/// <summary>
/// Splits an office document (a ZIP container) into chunks along its ZIP
/// boundaries for WOPI incremental file transfer. The file is processed as a
/// stream — neither the whole file nor a whole chunk is held in memory — and
/// each chunk is hashed incrementally with <see cref="SpookyHash"/>.
///
/// For each internal ZIP entry two chunks are emitted: the local file header
/// (the 30-byte fixed header plus the variable file-name/extra fields) and the
/// entry's compressed data. The central directory (from its first signature to
/// end-of-file) forms a final single chunk. An office file with n internal
/// entries therefore yields 2n+1 chunks.
/// </summary>
public sealed class WopiFileChunker
{
    private const uint LocalFileHeaderSignature = 0x04034b50;
    private const uint CentralDirectorySignature = 0x02014b50;
    private const int KnownHeaderSize = 30;
    private const int CompressedSizeOffset = 18;
    private const int FileNameLengthOffset = 26;
    private const int ExtraFieldLengthOffset = 28;
    private const int ReadBufferSize = 64 * 1024;

    /// <summary>
    /// Splits the office document at <paramref name="filePath"/> into its WOPI
    /// incremental-file-transfer chunks.
    /// </summary>
    /// <param name="filePath">Path to the office (ZIP-container) document.</param>
    /// <returns>The ordered list of <see cref="WopiFileChunk"/> for the file.</returns>
    public List<WopiFileChunk> getChunkData(string filePath)
    {
        using FileStream stream = new(
            filePath, FileMode.Open, FileAccess.Read, FileShare.Read, ReadBufferSize, FileOptions.SequentialScan);
        return getChunkData(stream);
    }

    /// <summary>
    /// Splits the office document read from <paramref name="stream"/> into its
    /// WOPI incremental-file-transfer chunks. The stream is read sequentially and
    /// is not buffered in full.
    /// </summary>
    /// <param name="stream">A readable, sequential stream over the document.</param>
    /// <returns>The ordered list of <see cref="WopiFileChunk"/> for the file.</returns>
    public List<WopiFileChunk> getChunkData(Stream stream)
    {
        System.ArgumentNullException.ThrowIfNull(stream);

        var chunks = new List<WopiFileChunk>();
        long offset = 0;
        byte[] header = new byte[KnownHeaderSize];
        byte[] signature = new byte[4];

        while (true)
        {
            int read = ReadUpTo(stream, signature, 0, 4);
            if (read == 0)
            {
                break; // clean end of stream
            }
            if (read < 4)
            {
                throw new InvalidDataException("Truncated ZIP: incomplete record signature.");
            }

            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(signature);

            if (sig == LocalFileHeaderSignature)
            {
                // Complete the 30-byte known header (the signature is its first 4 bytes).
                System.Array.Copy(signature, 0, header, 0, 4);
                ReadExactly(stream, header, 4, KnownHeaderSize - 4);

                uint compressedSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(CompressedSizeOffset));
                ushort fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(FileNameLengthOffset));
                ushort extraFieldLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(ExtraFieldLengthOffset));
                int variableHeaderLength = fileNameLength + extraFieldLength;

                // Chunk: known header (30 bytes) + variable header (name + extra field).
                var headerHash = new SpookyHash();
                headerHash.Update(header, 0, KnownHeaderSize);
                HashExactly(stream, variableHeaderLength, headerHash);
                long headerChunkLength = KnownHeaderSize + variableHeaderLength;
                chunks.Add(new WopiFileChunk(offset, headerChunkLength, System.Convert.ToBase64String(headerHash.Digest())));
                offset += headerChunkLength;

                // Chunk: the entry's compressed data.
                var dataHash = new SpookyHash();
                HashExactly(stream, compressedSize, dataHash);
                chunks.Add(new WopiFileChunk(offset, compressedSize, System.Convert.ToBase64String(dataHash.Digest())));
                offset += compressedSize;
            }
            else if (sig == CentralDirectorySignature)
            {
                // The central directory (signature + everything to EOF) is one chunk.
                var cdHash = new SpookyHash();
                cdHash.Update(signature, 0, 4);
                long rest = HashToEnd(stream, cdHash);
                long cdLength = 4 + rest;
                chunks.Add(new WopiFileChunk(offset, cdLength, System.Convert.ToBase64String(cdHash.Digest())));
                offset += cdLength;
                break;
            }
            else
            {
                throw new InvalidDataException("Not a ZIP-formatted (office) document.");
            }
        }

        return chunks;
    }

    private static void HashExactly(Stream stream, long count, SpookyHash hash)
    {
        byte[] buffer = new byte[ReadBufferSize];
        long remaining = count;
        while (remaining > 0)
        {
            int toRead = (int)System.Math.Min(buffer.Length, remaining);
            int r = stream.Read(buffer, 0, toRead);
            if (r <= 0)
            {
                throw new InvalidDataException("Truncated ZIP: unexpected end of stream.");
            }
            hash.Update(buffer, 0, r);
            remaining -= r;
        }
    }

    private static long HashToEnd(Stream stream, SpookyHash hash)
    {
        byte[] buffer = new byte[ReadBufferSize];
        long total = 0;
        int r;
        while ((r = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.Update(buffer, 0, r);
            total += r;
        }
        return total;
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        int got = 0;
        while (got < count)
        {
            int r = stream.Read(buffer, offset + got, count - got);
            if (r <= 0)
            {
                throw new InvalidDataException("Truncated ZIP header.");
            }
            got += r;
        }
    }

    private static int ReadUpTo(Stream stream, byte[] buffer, int offset, int count)
    {
        int got = 0;
        while (got < count)
        {
            int r = stream.Read(buffer, offset + got, count - got);
            if (r <= 0)
            {
                break;
            }
            got += r;
        }
        return got;
    }
}
