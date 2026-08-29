using System.Text.Json;
using Azure.Core;
using Steward.Providers.DevBox;

namespace Steward.DevBox.Tests;

public sealed class DevBoxCustomizationTests
{
    private static readonly Uri Endpoint =
        new("https://center.westus.devcenter.azure.com/");

    [Fact]
    public async Task ApplyUsesBoundedTypedSystemTaskAndExactDeveloperPath()
    {
        var transport = new FakeTransport
        {
            Response = GroupResponse()
        };
        var client = new DevBoxCustomizationClient(
            Endpoint,
            transport);
        var result = await client.ApplyAsync(
            "project",
            "me",
            "box-name",
            "steward-bootstrap",
            [
                new(
                    "~/powershell",
                    "Install Steward Node",
                    new Dictionary<string, string>
                    {
                        ["command"] = "Write-Output STEWARD"
                    },
                    DevBoxCustomizationExecutionAccount.System,
                    1_800)
            ],
            default);

        Assert.Equal(RequestMethod.Put, transport.Method);
        Assert.Equal(
            "https://center.westus.devcenter.azure.com/" +
            "projects/project/users/me/devboxes/box-name/" +
            "customizationGroups/steward-bootstrap?" +
            "api-version=2025-02-01",
            transport.Uri!.AbsoluteUri);
        using var payload = JsonDocument.Parse(
            transport.Content!.ToMemory());
        var task = payload.RootElement
            .GetProperty("tasks")[0];
        Assert.Equal("System", task.GetProperty("runAs").GetString());
        Assert.Equal(1_800, task.GetProperty(
            "timeoutInSeconds").GetInt32());
        Assert.Equal("Succeeded", result.Status);
        Assert.Single(result.Tasks);
    }

    [Fact]
    public async Task LogRetrievalAcceptsOnlyBoundedSameOriginServiceUri()
    {
        var transport = new FakeTransport
        {
            Response = new(
                200,
                BinaryData.FromObjectAsJson("encoded-log"))
        };
        var client = new DevBoxCustomizationClient(
            Endpoint,
            transport);

        var log = await client.GetTaskLogAsync(
            new(
                Endpoint,
                "projects/project/users/me/devboxes/box-name/" +
                "customizationGroups/group/logs/" +
                "11111111-1111-1111-1111-111111111111"),
            default);

        Assert.Equal("encoded-log", log);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.GetTaskLogAsync(
                new(
                    "https://attacker.example/projects/project/" +
                    "users/me/devboxes/box/customizationGroups/g/" +
                    "logs/11111111-1111-1111-1111-111111111111"),
                default));
    }

    [Fact]
    public async Task InvalidOrOversizedTasksFailBeforeTransport()
    {
        var transport = new FakeTransport
        {
            Response = GroupResponse()
        };
        var client = new DevBoxCustomizationClient(
            Endpoint,
            transport);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ApplyAsync(
                "project",
                "me",
                "box-name",
                "group",
                [
                    new(
                        "~/powershell",
                        "oversized",
                        new Dictionary<string, string>
                        {
                            ["command"] = new('x', 65 * 1024)
                        },
                        DevBoxCustomizationExecutionAccount.System,
                        1_800)
                ],
                default));
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task ListUsesBoundedDeveloperPathAndReturnsQueueState()
    {
        var transport = new FakeTransport
        {
            Response = new(
                200,
                BinaryData.FromString(
                    """
                    {
                      "value": [
                        {
                          "name": "steward-bootstrap",
                          "uri": "https://center.westus.devcenter.azure.com/projects/project/users/me/devboxes/box-name/customizationGroups/steward-bootstrap",
                          "status": "NotStarted"
                        }
                      ]
                    }
                    """))
        };
        var client = new DevBoxCustomizationClient(Endpoint, transport);

        var groups = await client.ListAsync(
            "project",
            "me",
            "box-name",
            default);

        var group = Assert.Single(groups);
        Assert.Equal("steward-bootstrap", group.Name);
        Assert.Equal("NotStarted", group.Status);
        Assert.Equal(RequestMethod.Get, transport.Method);
        Assert.Equal(
            "https://center.westus.devcenter.azure.com/" +
            "projects/project/users/me/devboxes/box-name/" +
            "customizationGroups?api-version=2025-02-01",
            transport.Uri!.AbsoluteUri);
    }

    private static DevBoxCustomizationHttpResponse GroupResponse() =>
        new(
            200,
            BinaryData.FromString(
                """
                {
                  "name": "steward-bootstrap",
                  "uri": "https://center.westus.devcenter.azure.com/projects/project/users/me/devboxes/box-name/customizationGroups/steward-bootstrap",
                  "status": "Succeeded",
                  "tasks": [
                    {
                      "id": "11111111-1111-1111-1111-111111111111",
                      "name": "~/powershell",
                      "displayName": "Install Steward Node",
                      "status": "Succeeded",
                      "logUri": "https://center.westus.devcenter.azure.com/projects/project/users/me/devboxes/box-name/customizationGroups/steward-bootstrap/logs/11111111-1111-1111-1111-111111111111"
                    }
                  ]
                }
                """));

    private sealed class FakeTransport :
        IDevBoxCustomizationTransport
    {
        public int Calls { get; private set; }
        public RequestMethod? Method { get; private set; }
        public Uri? Uri { get; private set; }
        public BinaryData? Content { get; private set; }
        public required DevBoxCustomizationHttpResponse Response
        {
            get;
            init;
        }

        public Task<DevBoxCustomizationHttpResponse> SendAsync(
            RequestMethod method,
            Uri uri,
            BinaryData? content,
            CancellationToken cancellationToken)
        {
            Calls++;
            Method = method;
            Uri = uri;
            Content = content;
            return Task.FromResult(Response);
        }
    }
}
