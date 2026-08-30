using System.Net;
using System.Text;
using Azure.Core;
using Steward.Rdp.Windows;

namespace Steward.Rdp.Windows.Tests;

public sealed class RdpContentFetcherTests
{
    private static readonly AccessToken Token =
        new("SECRET_TOKEN_SENTINEL", DateTimeOffset.UtcNow.AddHours(1));

    [Fact]
    public async Task FollowsBoundedSameOriginRedirect()
    {
        var handler = new QueueHandler(
            Redirect("https://rdp.example/profile"),
            Content("rdp"));
        var fetcher = new RdpContentFetcher(new HttpMessageInvoker(handler));

        var result = await fetcher.FetchAsync(
            new("https://rdp.example/start"),
            new("https://devcenter.example/"),
            Token,
            CancellationToken.None);

        Assert.Equal("rdp", Encoding.UTF8.GetString(result));
        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, request => Assert.Null(request.Authorization));
    }

    [Fact]
    public async Task RejectsCrossOriginRedirect()
    {
        var handler = new QueueHandler(Redirect("https://other.example/profile"));
        var fetcher = new RdpContentFetcher(new HttpMessageInvoker(handler));

        await Assert.ThrowsAsync<InvalidDataException>(() => fetcher.FetchAsync(
            new("https://rdp.example/start"),
            new("https://devcenter.example/"),
            Token,
            CancellationToken.None));
    }

    [Fact]
    public async Task RejectsTooManyRedirects()
    {
        var handler = new QueueHandler(
            Redirect("/one"),
            Redirect("/two"),
            Redirect("/three"),
            Redirect("/four"));
        var fetcher = new RdpContentFetcher(new HttpMessageInvoker(handler));

        await Assert.ThrowsAsync<InvalidDataException>(() => fetcher.FetchAsync(
            new("https://rdp.example/start"),
            new("https://devcenter.example/"),
            Token,
            CancellationToken.None));
    }

    [Fact]
    public async Task SendsWamTokenOnlyToExactDevCenterOrigin()
    {
        var handler = new QueueHandler(Content("rdp"));
        var fetcher = new RdpContentFetcher(new HttpMessageInvoker(handler));

        await fetcher.FetchAsync(
            new("https://devcenter.example/profile"),
            new("https://devcenter.example/"),
            Token,
            CancellationToken.None);

        Assert.Equal("Bearer SECRET_TOKEN_SENTINEL", handler.Requests[0].Authorization);
    }

    [Fact]
    public async Task OversizeFailureDoesNotLogOrDiscloseToken()
    {
        var handler = new QueueHandler(
            Content(new byte[RdpFileParser.MaximumBytes + 1]));
        var fetcher = new RdpContentFetcher(new HttpMessageInvoker(handler));

        var error = await Assert.ThrowsAsync<InvalidDataException>(
            () => fetcher.FetchAsync(
                new("https://devcenter.example/profile"),
                new("https://devcenter.example/"),
                Token,
                CancellationToken.None));

        Assert.DoesNotContain(Token.Token, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Token.Token, handler.DiagnosticOutput, StringComparison.Ordinal);
    }

    private static HttpResponseMessage Redirect(string location) =>
        new(HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri(location, UriKind.RelativeOrAbsolute) }
        };

    private static HttpResponseMessage Content(string value) =>
        Content(Encoding.UTF8.GetBytes(value));

    private static HttpResponseMessage Content(byte[] value) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(value) };

    private sealed record CapturedRequest(Uri Uri, string? Authorization);

    private sealed class QueueHandler(params HttpResponseMessage[] responses)
        : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses = new(responses);

        public List<CapturedRequest> Requests { get; } = [];
        public string DiagnosticOutput { get; private set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(new(
                request.RequestUri!,
                request.Headers.Authorization?.ToString()));
            DiagnosticOutput += $"GET {request.RequestUri!.GetLeftPart(UriPartial.Path)}";
            return Task.FromResult(_responses.Dequeue());
        }
    }
}
