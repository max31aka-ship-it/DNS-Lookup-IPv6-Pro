<?php
// dns_lookup.php — PHP версия

class DNSLookupIPv6 {
    private $timeout;
    private $threads;
    private $results = [];

    public function __construct($timeout = 5, $threads = 20) {
        $this->timeout = $timeout;
        $this->threads = $threads;
    }

    private function isIPv6($addr) {
        return filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    private function lookupAAAA($domain) {
        $records = @dns_get_record($domain, DNS_AAAA);
        if ($records === false) return [];
        return array_column($records, 'ipv6');
    }

    private function lookupPTR($ip) {
        $ptr = @gethostbyaddr($ip);
        if ($ptr === false || $ptr === $ip) return [];
        return [$ptr];
    }

    private function lookupDomain($domain) {
        $domain = trim($domain);
        if (empty($domain)) return null;

        if ($this->isIPv6($domain)) {
            $ptr = $this->lookupPTR($domain);
            return [
                'domain' => $domain,
                'timestamp' => date('c'),
                'AAAA' => [],
                'PTR' => $ptr ?: ['не найден']
            ];
        }

        $aaaa = $this->lookupAAAA($domain);
        $ptr = [];
        if (!empty($aaaa)) {
            foreach ($aaaa as $ip) {
                $names = $this->lookupPTR($ip);
                $ptr = array_merge($ptr, $names);
            }
        }
        if (empty($ptr)) {
            $ptr = ['не найден'];
        }

        return [
            'domain' => $domain,
            'timestamp' => date('c'),
            'AAAA' => $aaaa,
            'PTR' => $ptr
        ];
    }

    public function lookupBatch($domains) {
        echo "🔍 Выполняем lookup для " . count($domains) . " доменов...\n";
        $start = microtime(true);

        foreach ($domains as $domain) {
            $result = $this->lookupDomain($domain);
            if ($result) {
                $this->results[] = $result;
                echo "✅ $domain — выполнено\n";
            }
        }

        $elapsed = microtime(true) - $start;
        echo "⏱️ Время выполнения: " . number_format($elapsed, 2) . " сек.\n";
        return $this->results;
    }

    public function saveJSON($filename) {
        file_put_contents($filename, json_encode($this->results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        echo "💾 Сохранено JSON: $filename\n";
    }

    public function saveCSV($filename) {
        if (empty($this->results)) return;
        $fp = fopen($filename, 'w');
        fputcsv($fp, ['Domain', 'Timestamp', 'AAAA', 'PTR']);
        foreach ($this->results as $r) {
            fputcsv($fp, [
                $r['domain'],
                $r['timestamp'],
                implode('; ', $r['AAAA']),
                implode('; ', $r['PTR'])
            ]);
        }
        fclose($fp);
        echo "💾 Сохранено CSV: $filename\n";
    }

    public function printTable() {
        if (empty($this->results)) {
            echo "Нет результатов.\n";
            return;
        }

        echo "\n" . str_repeat('=', 90) . "\n";
        printf("%-25s %-35s %-25s\n", "Домен/IP", "AAAA", "PTR");
        echo str_repeat('-', 90) . "\n";
        foreach ($this->results as $r) {
            $aaaa = implode('; ', $r['AAAA']);
            $aaaa = empty($aaaa) ? '—' : $aaaa;
            if (strlen($aaaa) > 35) $aaaa = substr($aaaa, 0, 35) . '...';
            $ptr = implode('; ', $r['PTR']);
            if (strlen($ptr) > 25) $ptr = substr($ptr, 0, 25) . '...';
            printf("%-25s %-35s %-25s\n", $r['domain'], $aaaa, $ptr);
        }
        echo str_repeat('=', 90) . "\n";
    }
}

function main($argv) {
    if ($argc < 2) {
        echo "Usage: php dns_lookup.php <domains.txt>\n";
        echo "   или: php dns_lookup.php domain1.com domain2.com\n";
        exit(1);
    }

    $domains = [];

    if ($argc == 2 && file_exists($argv[1])) {
        $domains = array_filter(array_map('trim', file($argv[1])), function($d) {
            return !empty($d);
        });
    } else {
        $domains = array_slice($argv, 1);
    }

    if (empty($domains)) {
        echo "❌ Нет доменов для проверки.\n";
        exit(1);
    }

    echo "🌐 DNS Lookup IPv6 Pro (PHP)\n";
    echo "📂 Загружено " . count($domains) . " доменов.\n";

    $lookup = new DNSLookupIPv6(5, 20);
    $lookup->lookupBatch($domains);

    if (!empty($lookup->results)) {
        $lookup->printTable();
        $lookup->saveJSON('dns_results.json');
        $lookup->saveCSV('dns_results.csv');
    } else {
        echo "❌ Не удалось выполнить lookup.\n";
    }
}

$argc = $_SERVER['argc'] ?? 0;
$argv = $_SERVER['argv'] ?? [];
main($argv);
?>
