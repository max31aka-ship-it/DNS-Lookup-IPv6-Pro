

### 1. `dns_lookup.py` (Python)

```python
# dns_lookup.py — Python версия

import dns.resolver
import dns.reversename
import json
import csv
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
import ipaddress

class DNSLookupIPv6:
    def __init__(self, timeout=5, threads=20):
        self.timeout = timeout
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.results = []

    def lookup_aaaa(self, domain):
        """Выполняет lookup AAAA записи для домена."""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return []
        except Exception:
            return []

    def lookup_ptr(self, ipv6_addr):
        """Выполняет reverse lookup для IPv6-адреса."""
        try:
            rev = dns.reversename.from_address(ipv6_addr)
            answers = self.resolver.resolve(rev, 'PTR')
            return [str(r) for r in answers]
        except:
            return []

    def is_ipv6(self, addr):
        """Проверяет, является ли строка IPv6-адресом."""
        try:
            ipaddress.IPv6Address(addr)
            return True
        except:
            return False

    def lookup_domain(self, domain):
        """Выполняет полный lookup для домена или IP."""
        domain = domain.strip()
        if not domain:
            return None

        # Проверяем, является ли домен IPv6-адресом
        if self.is_ipv6(domain):
            # Для IP-адреса делаем reverse lookup
            ptr = self.lookup_ptr(domain)
            result = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'AAAA': [],
                'PTR': ptr if ptr else ['не найден']
            }
            return result

        # Для домена делаем AAAA lookup
        aaaa = self.lookup_aaaa(domain)
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'AAAA': aaaa,
            'PTR': []
        }

        # Reverse lookup для каждого AAAA адреса
        if aaaa:
            for ip in aaaa:
                ptr = self.lookup_ptr(ip)
                result['PTR'].extend(ptr if ptr else ['не найден'])
        else:
            result['PTR'] = ['не найден']

        return result

    def lookup_batch(self, domains):
        """Пакетная проверка с многопоточностью."""
        print(f"🔍 Выполняем lookup для {len(domains)} доменов...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {executor.submit(self.lookup_domain, d): d for d in domains if d.strip()}
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        print(f"✅ {domain} — выполнено")
                    else:
                        print(f"⚠️ {domain} — ошибка")
                except Exception as e:
                    print(f"❌ {domain} — {e}")

        elapsed = time.time() - start_time
        print(f"⏱️ Время выполнения: {elapsed:.2f} сек.")
        return self.results

    def save_json(self, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"💾 Сохранено JSON: {filename}")

    def save_csv(self, filename):
        if not self.results:
            print("⚠️ Нет данных для сохранения.")
            return
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Timestamp", "AAAA", "PTR"])
            for r in self.results:
                writer.writerow([
                    r['domain'],
                    r['timestamp'],
                    '; '.join(r['AAAA']) if r['AAAA'] else '—',
                    '; '.join(r['PTR']) if r['PTR'] else 'не найден'
                ])
        print(f"💾 Сохранено CSV: {filename}")

    def print_table(self):
        if not self.results:
            print("Нет результатов.")
            return

        print("\n" + "=" * 90)
        print(f"{'Домен/IP':<25} {'AAAA':<35} {'PTR':<25}")
        print("-" * 90)
        for r in self.results:
            aaaa = '; '.join(r['AAAA']) if r['AAAA'] else '—'
            ptr = '; '.join(r['PTR']) if r['PTR'] else 'не найден'
            # Обрезаем длинные строки
            if len(aaaa) > 35:
                aaaa = aaaa[:35] + '...'
            if len(ptr) > 25:
                ptr = ptr[:25] + '...'
            print(f"{r['domain']:<25} {aaaa:<35} {ptr:<25}")
        print("=" * 90)

def main():
    parser = argparse.ArgumentParser(description='DNS Lookup IPv6 Pro')
    parser.add_argument('input', help='Файл с доменами/IP (по одному на строку)')
    parser.add_argument('-o', '--output', default='dns_results', help='Базовое имя файлов для сохранения')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Количество потоков')
    parser.add_argument('--timeout', type=int, default=5, help='Таймаут запроса (сек)')
    parser.add_argument('--no-save', action='store_true', help='Не сохранять результаты')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ Файл {args.input} не найден.")
        sys.exit(1)

    print("🌐 DNS Lookup IPv6 Pro (Python)")
    with open(args.input, 'r', encoding='utf-8') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        print("❌ Нет доменов для проверки.")
        sys.exit(1)

    print(f"📂 Загружено {len(domains)} доменов/IP.")

    lookup = DNSLookupIPv6(timeout=args.timeout, threads=args.threads)
    results = lookup.lookup_batch(domains)

    if results:
        lookup.print_table()
        if not args.no_save:
            lookup.save_json(args.output + '.json')
            lookup.save_csv(args.output + '.csv')
    else:
        print("❌ Не удалось выполнить lookup ни для одного домена.")

if __name__ == "__main__":
    main()
