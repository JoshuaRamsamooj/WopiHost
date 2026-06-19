namespace WopiHost.Core.Chunking;

/// <summary>
/// One chunk of an office document produced for WOPI incremental file transfer:
/// its byte <see cref="Offset"/> within the file, its <see cref="Length"/> in
/// bytes, and the Base64-encoded 16-byte SpookyHash of the chunk's bytes.
/// </summary>
public sealed class WopiFileChunk
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WopiFileChunk"/> class.
    /// </summary>
    /// <param name="offset">The chunk's byte offset within the file.</param>
    /// <param name="length">The chunk's length in bytes.</param>
    /// <param name="hash">The Base64-encoded 16-byte SpookyHash of the chunk.</param>
    public WopiFileChunk(long offset, long length, string hash)
    {
        Offset = offset;
        Length = length;
        Hash = hash;
    }

    /// <summary>Gets the chunk's byte offset within the file.</summary>
    public long Offset { get; }

    /// <summary>Gets the chunk's length in bytes.</summary>
    public long Length { get; }

    /// <summary>Gets the Base64-encoded 16-byte SpookyHash of the chunk's bytes.</summary>
    public string Hash { get; }
}
