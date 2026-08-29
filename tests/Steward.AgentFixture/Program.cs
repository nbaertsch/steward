using System.Text.Json;

var line = await Console.In.ReadLineAsync();
if (line is null) return 2;
using var document = JsonDocument.Parse(line);
var text = document.RootElement.GetProperty("text").GetString() ?? string.Empty;
Console.WriteLine(JsonSerializer.Serialize(new { type = "activity", text = "fixture-started" }));
Console.WriteLine(JsonSerializer.Serialize(new { type = "final", text = $"fixture:{text}" }));
return 0;
