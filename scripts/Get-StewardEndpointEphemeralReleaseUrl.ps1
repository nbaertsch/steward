param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $Version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'Repository or release version is invalid.'
}
$tag = "steward-endpoint-v$Version"
$assetName = "Steward.Endpoint.Catalog.$Version.zip"
$private = & gh api "repos/$Repository" --jq '.private'
if ($LASTEXITCODE -ne 0 -or $private -ne 'false') {
    throw 'Steward endpoint releases require the approved public GitHub repository.'
}
$release = & gh api "repos/$Repository/releases/tags/$tag"
if ($LASTEXITCODE -ne 0) {
    throw 'The private Steward endpoint release is unavailable.'
}
$releaseJson = $release | ConvertFrom-Json
$asset = @($releaseJson.assets |
    Where-Object name -EQ $assetName)
if ($asset.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace($asset[0].url)) {
    throw 'The private Steward endpoint release asset is unavailable.'
}
$token = & gh auth token
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
    throw 'GitHub authentication is unavailable.'
}
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler)
try {
    $client.DefaultRequestHeaders.Authorization =
        [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bearer',
            $token.Trim())
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        'Steward-Endpoint-Release/1.0')
    $client.DefaultRequestHeaders.Accept.ParseAdd(
        'application/octet-stream')
    $response = $client.GetAsync($asset[0].url).GetAwaiter().GetResult()
    if ($response.StatusCode -notin 301, 302, 303, 307, 308 -or
        $null -eq $response.Headers.Location) {
        throw 'GitHub did not issue an ephemeral release asset link.'
    }
    $location = $response.Headers.Location
    if (-not $location.IsAbsoluteUri) {
        $location = [uri]::new([uri]$asset[0].url, $location)
    }
    if ($location.Scheme -ne 'https' -or
        $location.Host -ne 'release-assets.githubusercontent.com' -or
        [string]::IsNullOrWhiteSpace($location.Query) -or
        $location.AbsoluteUri -notmatch
            '^https://release-assets\.githubusercontent\.com/[A-Za-z0-9._~:/?&=%+-]+$') {
        throw 'GitHub returned an invalid release asset link.'
    }
    Write-Output $location.AbsoluteUri
} finally {
    $token = $null
    $client.Dispose()
    $handler.Dispose()
}
