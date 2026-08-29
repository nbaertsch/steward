using Steward.Domain;
using Steward.Transport;

namespace Steward.Node.Host;

/// <summary>
/// Validates that a negotiated transport session matches the expected
/// DVC endpoint identity (session, host, incarnation).
/// </summary>
public static class DvcSessionValidator
{
    /// <summary>
    /// Throws <see cref="TransportProtocolException"/> if the negotiated session
    /// does not match the expected endpoint identity.
    /// </summary>
    public static void ValidateSessionBinding(
        NegotiatedSession session,
        Guid expectedSessionId,
        NodeIncarnationId expectedIncarnationId,
        string expectedLocalIdentity,
        string expectedRemoteIdentity)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedLocalIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedRemoteIdentity);
        if (!session.Security.IsSecure ||
            !string.Equals(
                session.Security.LocalIdentity,
                expectedLocalIdentity,
                StringComparison.Ordinal) ||
            !string.Equals(
                session.Security.RemoteIdentity,
                expectedRemoteIdentity,
                StringComparison.Ordinal))
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The negotiated transport identities do not match the DVC endpoint.");
        if (session.SessionId != expectedSessionId)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The negotiated session ID does not match the DVC endpoint session.");
        if (session.NodeIncarnationId != expectedIncarnationId)
            throw new TransportProtocolException(
                TransportError.SessionBindingMismatch,
                "The negotiated incarnation ID does not match the DVC endpoint incarnation.");
    }
}
