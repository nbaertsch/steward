using System.Runtime.Versioning;
using System.Windows.Forms;

namespace Steward.DevBox.Windows;

[SupportedOSPlatform("windows")]
public sealed class DevBoxCommandService : IDevBoxCommandService
{
    private readonly DevBoxIdentityService _identity;
    private readonly DevBoxDiscoveryService _discovery;

    public DevBoxCommandService(HttpClient? httpClient = null, string? identityDirectory = null)
    {
        _identity = new DevBoxIdentityService(new DevBoxIdentityStore(identityDirectory));
        _discovery = new(
            _identity,
            new HttpDevBoxTenantDiscoveryTransport(httpClient ?? new HttpClient()),
            new AzureDevBoxProjectInventoryClientFactory());
    }

    public Task<DevBoxIdentityStatus> LoginAsync(
        CancellationToken cancellationToken) =>
        RunStaAsync(
            handle => _identity.LoginAsync(
                handle,
                cancellationToken),
            cancellationToken);

    public Task<DevBoxIdentityStatus> StatusAsync(CancellationToken cancellationToken) =>
        _identity.StatusAsync(cancellationToken);

    public Task<DevBoxIdentityStatus> LogoutAsync(CancellationToken cancellationToken) =>
        _identity.LogoutAsync(cancellationToken);

    public Task<DevBoxInventory> DiscoverAsync(CancellationToken cancellationToken) =>
        _discovery.DiscoverAsync(cancellationToken);

    internal static Task<T> RunStaAsync<T>(
        Func<IntPtr, Task<T>> action,
        CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<T>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                using var window = new Form
                {
                    Text = "Steward Dev Box Sign-In",
                    Width = 520,
                    Height = 180,
                    StartPosition = FormStartPosition.CenterScreen
                };
                window.Controls.Add(new Label
                {
                    AutoSize = false,
                    Dock = DockStyle.Fill,
                    TextAlign =
                        System.Drawing.ContentAlignment.MiddleCenter,
                    Text = "Complete sign-in in the Windows account picker."
                });
                var completed = false;
                window.Shown += async (_, _) =>
                {
                    try
                    {
                        completion.TrySetResult(
                            await action(window.Handle));
                    }

                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        completion.TrySetCanceled(cancellationToken);
                    }
                    catch (Exception exception)
                    {
                        completion.TrySetException(exception);
                    }
                    finally
                    {
                        completed = true;
                        if (!window.IsDisposed)
                            window.Close();
                    }
                };
                window.FormClosing += (_, eventArgs) =>
                {
                    if (completed)
                        return;
                    completed = true;
                    completion.TrySetException(
                        new OperationCanceledException(
                            "Dev Box sign-in is still in progress."));
                };
                Application.Run(window);
            }
            catch (Exception exception)
            {
                completion.TrySetException(exception);
            }
        })
        {
            IsBackground = true,
            Name = "Steward Dev Box WAM login"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }
}

[SupportedOSPlatform("windows")]
public sealed class DevBoxConnectionCommandService
{
    private readonly DevBoxConnectionIdentityService identity = new(
        new DevBoxIdentityStore(),
        new DevBoxConnectionIdentityStore());

    public Task<DevBoxConnectionIdentityStatus> EnrollAsync(
        CancellationToken cancellationToken) =>
        DevBoxCommandService.RunStaAsync(
            handle => identity.EnrollAsync(
                handle,
                cancellationToken),
            cancellationToken);

    public Task<DevBoxConnectionIdentityStatus> StatusAsync(
        CancellationToken cancellationToken) =>
        identity.StatusAsync(cancellationToken);

    public Task<DevBoxConnectionIdentityStatus> LogoutAsync(
        CancellationToken cancellationToken) =>
        identity.ClearAsync(cancellationToken);
}
