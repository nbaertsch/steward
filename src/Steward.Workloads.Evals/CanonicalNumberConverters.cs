using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Workloads.Evals;

internal sealed class CanonicalInt32Converter : JsonConverter<int>
{
    public override int Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetDecimal();
        if (value != decimal.Truncate(value) || value is < int.MinValue or > int.MaxValue)
            throw new JsonException("Expected a 32-bit integer.");
        return (int)value;
    }

    public override void Write(Utf8JsonWriter writer, int value, JsonSerializerOptions options) =>
        writer.WriteNumberValue(value);
}

internal sealed class CanonicalInt64Converter : JsonConverter<long>
{
    public override long Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetDecimal();
        if (value != decimal.Truncate(value) || value is < long.MinValue or > long.MaxValue)
            throw new JsonException("Expected a 64-bit integer.");
        return (long)value;
    }

    public override void Write(Utf8JsonWriter writer, long value, JsonSerializerOptions options) =>
        writer.WriteNumberValue(value);
}
