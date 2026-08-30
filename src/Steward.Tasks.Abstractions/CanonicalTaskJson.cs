using System.Text.Json;
using System.Text.Json.Serialization;

namespace Steward.Tasks.Abstractions;

public static class CanonicalTaskJson
{
    public static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new CanonicalInt32Converter());
        options.Converters.Add(new CanonicalInt64Converter());
        return options;
    }

    private sealed class CanonicalInt32Converter : JsonConverter<int>
    {
        public override int Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            var value = ReadIntegralDecimal(ref reader);
            if (value is < int.MinValue or > int.MaxValue)
                throw new JsonException("Canonical integer exceeds Int32.");
            return decimal.ToInt32(value);
        }

        public override void Write(
            Utf8JsonWriter writer,
            int value,
            JsonSerializerOptions options) =>
            writer.WriteNumberValue(value);
    }

    private sealed class CanonicalInt64Converter : JsonConverter<long>
    {
        public override long Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            var value = ReadIntegralDecimal(ref reader);
            if (value is < long.MinValue or > long.MaxValue)
                throw new JsonException("Canonical integer exceeds Int64.");
            return decimal.ToInt64(value);
        }

        public override void Write(
            Utf8JsonWriter writer,
            long value,
            JsonSerializerOptions options) =>
            writer.WriteNumberValue(value);
    }

    private static decimal ReadIntegralDecimal(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.Number ||
            !reader.TryGetDecimal(out var value) ||
            decimal.Truncate(value) != value)
            throw new JsonException("Canonical integer is invalid.");
        return value;
    }
}
