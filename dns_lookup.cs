// dns_lookup.cs — C# версия

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

class DNSResult
{
    public string Domain { get; set; }
    public string Timestamp { get; set; }
    public List<string> AAAA { get; set; } = new List<string>();
    public List<string> PTR { get; set; } = new List<string>();
}

class DNSLookupIPv6
{
    private int timeout = 5000;
    private int threads = 20;
    private List<DNSResult> results = new List<DNSResult>();
    private object locker = new object();

    public async Task<List<DNSResult>> LookupBatchAsync(List<string> domains)
    {
        Console.WriteLine($"🔍 Выполняем lookup для {domains.Count} доменов...");
        var start = DateTime.Now;

        var tasks = new List<Task>();
        var semaphore = new SemaphoreSlim(threads);

        foreach (var domain in domains.Where(d => !string.IsNullOrWhiteSpace(d)))
        {
            await semaphore.WaitAsync();
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = await LookupDomainAsync(domain.Trim());
                    if (result != null)
                    {
                        lock (locker)
                        {
                            results.Add(result);
                        }
                        Console.WriteLine($"✅ {domain.Trim()} — выполнено");
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }));
        }

        await Task.WhenAll(tasks);
        Console.WriteLine($"⏱️ Время выполнения: {(DateTime.Now - start).TotalSeconds:F2} сек.");
        return results;
    }

    private async Task<DNSResult> LookupDomainAsync(string domain)
    {
        var result = new DNSResult
        {
            Domain = domain,
            Timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        };

        try
        {
            // Проверяем, является ли строка IPv6-адресом
            if (IPAddress.TryParse(domain, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var ptr = await GetPTRAsync(domain);
                result.PTR = ptr.Any() ? ptr : new List<string> { "не найден" };
                return result;
            }

            var entries = await Dns.GetHostEntryAsync(domain);
            var ipv6Addresses = entries.AddressList.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6).ToList();

            result.AAAA = ipv6Addresses.Select(a => a.ToString()).ToList();

            if (ipv6Addresses.Any())
            {
                foreach (var addr in ipv6Addresses)
                {
                    var ptr = await GetPTRAsync(addr.ToString());
                    result.PTR.AddRange(ptr);
                }
            }
            if (!result.PTR.Any())
            {
                result.PTR.Add("не найден");
            }
        }
        catch
        {
            result.PTR.Add("не найден");
        }

        return result;
    }

    private async Task<List<string>> GetPTRAsync(string ip)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            return new List<string> { entry.HostName };
        }
        catch
        {
            return new List<string>();
        }
    }

    public void PrintTable()
    {
        if (results.Count == 0)
        {
            Console.WriteLine("Нет результатов.");
            return;
        }

        Console.WriteLine("\n" + new string('=', 90));
        Console.WriteLine($"{"Домен/IP",-25} {"AAAA",-35} {"PTR",-25}");
        Console.WriteLine(new string('-', 90));
        foreach (var r in results)
        {
            var aaaa = string.Join("; ", r.AAAA);
            if (string.IsNullOrEmpty(aaaa)) aaaa = "—";
            if (aaaa.Length > 35) aaaa = aaaa.Substring(0, 35) + "...";
            var ptr = string.Join("; ", r.PTR);
            if (ptr.Length > 25) ptr = ptr.Substring(0, 25) + "...";
            Console.WriteLine($"{r.Domain,-25} {aaaa,-35} {ptr,-25}");
        }
        Console.WriteLine(new string('=', 90));
    }

    public void SaveJSON(string filename)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(results, options);
        File.WriteAllText(filename, json);
        Console.WriteLine($"💾 Сохранено JSON: {filename}");
    }

    public void SaveCSV(string filename)
    {
        if (results.Count == 0) return;
        var lines = new List<string>();
        lines.Add("Domain,Timestamp,AAAA,PTR");
        foreach (var r in results)
        {
            lines.Add($"{r.Domain},{r.Timestamp},{string.Join("; ", r.AAAA)},{string.Join("; ", r.PTR)}");
        }
        File.WriteAllLines(filename, lines);
        Console.WriteLine($"💾 Сохранено CSV: {filename}");
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: dotnet run <domains.txt>");
            Console.WriteLine("   или: dotnet run domain1.com domain2.com");
            return;
        }

        List<string> domains = new List<string>();

        if (args.Length == 1 && File.Exists(args[0]))
        {
            domains = File.ReadAllLines(args[0])
                          .Where(line => !string.IsNullOrWhiteSpace(line))
                          .Select(line => line.Trim())
                          .ToList();
        }
        else
        {
            domains = args.ToList();
        }

        if (domains.Count == 0)
        {
            Console.WriteLine("❌ Нет доменов для проверки.");
            return;
        }

        Console.WriteLine("🌐 DNS Lookup IPv6 Pro (C#)");
        Console.WriteLine($"📂 Загружено {domains.Count} доменов.");

        var lookup = new DNSLookupIPv6();
        var results = await lookup.LookupBatchAsync(domains);

        if (results.Count > 0)
        {
            lookup.PrintTable();
            lookup.SaveJSON("dns_results.json");
            lookup.SaveCSV("dns_results.csv");
        }
        else
        {
            Console.WriteLine("❌ Не удалось выполнить lookup.");
        }
    }
}
