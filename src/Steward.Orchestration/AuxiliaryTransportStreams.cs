using Steward.Transport;

namespace Steward.Orchestration;

public interface IAuxiliaryTransportStreamHandler
{
    StreamKind Stream { get; }

    ValueTask HandleAsync(
        ITransportConnection connection,
        TransportFrame frame,
        CancellationToken cancellationToken);
}

internal static class AuxiliaryTransportStreamHandlers
{
    public static IReadOnlyDictionary<StreamKind, IAuxiliaryTransportStreamHandler>
        Index(IEnumerable<IAuxiliaryTransportStreamHandler>? handlers)
    {
        var values = handlers?.ToArray() ?? [];
        if (values.Select(x => x.Stream).Distinct().Count() != values.Length)
            throw new ArgumentException(
                "Auxiliary transport streams must have one handler each.",
                nameof(handlers));
        return values.ToDictionary(x => x.Stream);
    }
}
