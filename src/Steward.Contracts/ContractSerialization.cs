using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Steward.Domain;

namespace Steward.Contracts;

public static class StewardJson
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = false,
            WriteIndented = false
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        options.Converters.Add(new StewardIdJsonConverterFactory());
        return options;
    }
}

public sealed class StewardIdJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsValueType && typeof(IStewardId).IsAssignableFrom(typeToConvert);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var converterType = typeof(StewardIdJsonConverter<>).MakeGenericType(typeToConvert);
        return (JsonConverter)Activator.CreateInstance(converterType)!;
    }

    private sealed class StewardIdJsonConverter<T> : JsonConverter<T> where T : struct, IStewardId
    {
        private static readonly ConstructorInfo Constructor =
            typeof(T).GetConstructor([typeof(Guid)])
            ?? throw new InvalidOperationException($"{typeof(T).Name} must expose a Guid constructor.");

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? text;
            if (reader.TokenType == JsonTokenType.String)
            {
                text = reader.GetString();
            }
            else if (reader.TokenType == JsonTokenType.StartObject)
            {
                using var document = JsonDocument.ParseValue(ref reader);
                text = document.RootElement.TryGetProperty("value", out var value)
                    ? value.GetString()
                    : null;
            }
            else
            {
                text = null;
            }
            if (!Guid.TryParseExact(text, "D", out var guid) ||
                guid == Guid.Empty)
                throw new JsonException($"{typeof(T).Name} must be a non-empty GUID in D format.");
            return (T)Constructor.Invoke([guid]);
        }

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.Value.ToString("D"));
    }
}

public sealed class ContractValidationException : InvalidOperationException
{
    public ProblemDto Problem { get; }
    public ContractValidationException(ProblemDto problem) : base(problem.Detail) => Problem = problem;
}

public sealed class ContractCompatibility
{
    private readonly IReadOnlyDictionary<string, Version> _supportedSchemas;
    private readonly HashSet<string> _supportedFeatures;

    public ContractCompatibility(
        IReadOnlyDictionary<string, Version> supportedSchemas,
        IEnumerable<string> supportedFeatures)
    {
        _supportedSchemas = supportedSchemas;
        _supportedFeatures = supportedFeatures.ToHashSet(StringComparer.Ordinal);
    }

    public void Validate<T>(ContractEnvelope<T> envelope)
    {
        if (!_supportedSchemas.TryGetValue(envelope.SchemaName, out var supported) ||
            !Version.TryParse(envelope.SchemaVersion, out var requested) ||
            requested.Major != supported.Major ||
            requested > supported)
        {
            throw Unsupported($"Schema '{envelope.SchemaName}' version '{envelope.SchemaVersion}' is unsupported.");
        }

        var unknown = envelope.RequiredFeatures
            .Where(x => !_supportedFeatures.Contains(x))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (unknown.Length > 0)
            throw Unsupported($"Unsupported required features: {string.Join(", ", unknown)}.");
    }

    private static ContractValidationException Unsupported(string detail) =>
        new(new ProblemDto(
            ProblemCodes.UnsupportedRequiredFeature,
            "Unsupported contract requirement",
            detail,
            ProblemDisposition.Terminal,
            false));
}
