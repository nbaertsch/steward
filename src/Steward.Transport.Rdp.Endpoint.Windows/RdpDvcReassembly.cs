using System.Buffers.Binary;

namespace Steward.Transport.Rdp.Windows;

public sealed class BoundedDvcMessageReassembler
{
    private readonly int _maximumPayloadBytes;
    private readonly List<byte> _buffer = [];

    public BoundedDvcMessageReassembler(
        int maximumPayloadBytes = StewardRdpDvc.MaximumPayloadBytes)
    {
        if (maximumPayloadBytes is <= 0 or >
            StewardRdpDvc.MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(
                nameof(maximumPayloadBytes));
        _maximumPayloadBytes = maximumPayloadBytes;
    }

    public IReadOnlyList<byte[]> Push(ReadOnlySpan<byte> fragment)
    {
        if (fragment.IsEmpty)
            return [];
        var maximumEncoded =
            RdpDvcMessageCodec.MinimumEncodedSize + _maximumPayloadBytes;
        if (_buffer.Count + fragment.Length > maximumEncoded)
        {
            Reset();
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The fragmented Steward DVC message exceeds its bound.");
        }
        foreach (var value in fragment)
            _buffer.Add(value);

        var completed = new List<byte[]>();
        while (_buffer.Count >= RdpDvcMessageCodec.HeaderSize)
        {
            var header = _buffer
                .Take(RdpDvcMessageCodec.HeaderSize)
                .ToArray();
            var length = RdpDvcMessageCodec.GetEncodedLength(
                header,
                _maximumPayloadBytes);
            if (_buffer.Count < length)
                break;
            completed.Add(_buffer.Take(length).ToArray());
            _buffer.RemoveRange(0, length);
            if (_buffer.Count > maximumEncoded)
            {
                Reset();
                throw new RdpDvcProtocolException(
                    RdpDvcProtocolError.BoundsExceeded,
                    "Buffered Steward DVC messages exceed their bound.");
            }
        }
        return completed;
    }

    public void Reset() =>
        _buffer.Clear();
}

public sealed class BoundedChannelPduReassembler
{
    public const uint First = 0x01;
    public const uint Last = 0x02;
    private readonly int _maximumBytes;
    private readonly List<byte> _buffer = [];
    private bool _started;

    public BoundedChannelPduReassembler(int maximumBytes)
    {
        if (maximumBytes <
                RdpDvcMessageCodec.MinimumEncodedSize ||
            maximumBytes >
                RdpDvcMessageCodec.MinimumEncodedSize +
                StewardRdpDvc.MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        _maximumBytes = maximumBytes;
    }

    public byte[]? PushReadBuffer(
        ReadOnlySpan<byte> readBuffer)
    {
        if (readBuffer.Length < 8)
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The WTS channel PDU header is truncated.");
        var declaredLength =
            BinaryPrimitives.ReadUInt32LittleEndian(readBuffer[..4]);
        var flags =
            BinaryPrimitives.ReadUInt32LittleEndian(readBuffer.Slice(4, 4));
        if (declaredLength > _maximumBytes)
        {
            Reset();
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The WTS channel PDU declaration exceeds its bound.");
        }
        return Push(readBuffer[8..], flags);
    }

    public byte[]? Push(ReadOnlySpan<byte> payload, uint flags)
    {
        if ((flags & ~(First | Last)) != 0)
        {
            Reset();
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "The WTS channel PDU flags are invalid.");
        }
        if ((flags & First) != 0)
        {
            _buffer.Clear();
            _started = true;
        }
        else if (!_started)
        {
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.Malformed,
                "A WTS channel fragment arrived before FIRST.");
        }
        if (_buffer.Count + payload.Length > _maximumBytes)
        {
            Reset();
            throw new RdpDvcProtocolException(
                RdpDvcProtocolError.BoundsExceeded,
                "The reassembled WTS channel PDU exceeds its bound.");
        }
        foreach (var value in payload)
            _buffer.Add(value);
        if ((flags & Last) == 0)
            return null;
        var result = _buffer.ToArray();
        Reset();
        return result;
    }

    public void Reset()
    {
        _buffer.Clear();
        _started = false;
    }
}
