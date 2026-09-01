using System.Threading.Channels;

namespace Steward.ConnectionHost.Windows;

internal interface IConnectionWorkItem
{
    Task RunAsync();

    void Reject(Exception exception);
}

internal sealed class ConnectionWorkQueue
{
    private readonly Channel<IConnectionWorkItem> channel;

    public ConnectionWorkQueue(int capacity)
    {
        channel = Channel.CreateBounded<IConnectionWorkItem>(
            new BoundedChannelOptions(capacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });
        Completion = RunAsync();
    }

    public Task Completion { get; }

    public async ValueTask EnqueueAsync(
        IConnectionWorkItem work,
        CancellationToken cancellationToken)
    {
        try
        {
            await channel.Writer.WriteAsync(work, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ChannelClosedException exception)
        {
            work.Reject(exception);
            throw;
        }
        catch (OperationCanceledException exception)
        {
            work.Reject(exception);
            throw;
        }
    }

    public void Complete() => channel.Writer.TryComplete();

    private async Task RunAsync()
    {
        await foreach (var work in channel.Reader.ReadAllAsync()
                           .ConfigureAwait(false))
            await work.RunAsync().ConfigureAwait(false);
    }
}
