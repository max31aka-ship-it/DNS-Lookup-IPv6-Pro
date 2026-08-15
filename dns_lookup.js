// dns_lookup.js — JavaScript версия

const dns = require('dns');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolvePtr = promisify(dns.resolvePtr);
const lookup = promisify(dns.lookup);

class DNSLookupIPv6 {
    constructor(options = {}) {
        this.timeout = options.timeout || 5000;
        this.threads = options.threads || 20;
        this.results = [];
    }

    isIPv6(addr) {
        return /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^fe80::/.test(addr);
    }

    async lookupAAAA(domain) {
        try {
            const ips = await resolve6(domain);
            return ips;
        } catch (err) {
            return [];
        }
    }

    async lookupPTR(ip) {
        try {
            const names = await resolvePtr(ip);
            return names;
        } catch (err) {
            return [];
        }
    }

    async lookupDomain(domain) {
        domain = domain.trim();
        if (!domain) return null;

        // Проверяем, является ли строка IPv6-адресом
        if (this.isIPv6(domain)) {
            const ptr = await this.lookupPTR(domain);
            return {
                domain: domain,
                timestamp: new Date().toISOString(),
                AAAA: [],
                PTR: ptr.length ? ptr : ['не найден']
            };
        }

        const aaaa = await this.lookupAAAA(domain);
        let ptr = [];
        if (aaaa.length > 0) {
            for (const ip of aaaa) {
                const names = await this.lookupPTR(ip);
                ptr = ptr.concat(names);
            }
        }
        if (ptr.length === 0) {
            ptr = ['не найден'];
        }

        return {
            domain: domain,
            timestamp: new Date().toISOString(),
            AAAA: aaaa,
            PTR: ptr
        };
    }

    async lookupBatch(domains) {
        console.log(`🔍 Выполняем lookup для ${domains.length} доменов...`);
        const start = Date.now();

        const chunks = [];
        for (let i = 0; i < domains.length; i += this.threads) {
            chunks.push(domains.slice(i, i + this.threads));
        }

        for (const chunk of chunks) {
            const promises = chunk.map(async domain => {
                const result = await this.lookupDomain(domain);
                if (result) {
                    this.results.push(result);
                    console.log(`✅ ${domain} — выполнено`);
                }
            });
            await Promise.all(promises);
        }

        console.log(`⏱️ Время выполнения: ${(Date.now() - start) / 1000} сек.`);
    }

    saveJSON(filename) {
        fs.writeFileSync(filename, JSON.stringify(this.results, null, 2));
        console.log(`💾 Сохранено JSON: ${filename}`);
    }

    saveCSV(filename) {
        if (this.results.length === 0) {
            console.log('⚠️ Нет данных для сохранения.');
            return;
        }
        const headers = ['Domain', 'Timestamp', 'AAAA', 'PTR'];
        const rows = this.results.map(r => [
            r.domain,
            r.timestamp,
            r.AAAA.join('; ') || '—',
            r.PTR.join('; ') || 'не найден'
        ]);
        const csv = [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
        fs.writeFileSync(filename, csv);
        console.log(`💾 Сохранено CSV: ${filename}`);
    }

    printTable() {
        if (this.results.length === 0) {
            console.log('Нет результатов.');
            return;
        }
        console.log('\n' + '='.repeat(90));
        console.log(`${'Домен/IP'.padEnd(25)} ${'AAAA'.padEnd(35)} ${'PTR'.padEnd(25)}`);
        console.log('-'.repeat(90));
        for (const r of this.results) {
            let aaaa = r.AAAA.join('; ') || '—';
            let ptr = r.PTR.join('; ') || 'не найден';
            if (aaaa.length > 35) aaaa = aaaa.slice(0, 35) + '...';
            if (ptr.length > 25) ptr = ptr.slice(0, 25) + '...';
            console.log(`${r.domain.padEnd(25)} ${aaaa.padEnd(35)} ${ptr.padEnd(25)}`);
        }
        console.log('='.repeat(90));
    }
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        console.log('Usage: node dns_lookup.js <domains.txt>');
        console.log('   или: node dns_lookup.js domain1.com domain2.com');
        process.exit(1);
    }

    let domains = [];

    if (args.length === 1 && fs.existsSync(args[0])) {
        const content = fs.readFileSync(args[0], 'utf-8');
        domains = content.split('\n').map(l => l.trim()).filter(l => l);
    } else {
        domains = args;
    }

    if (domains.length === 0) {
        console.log('❌ Нет доменов для проверки.');
        process.exit(1);
    }

    console.log('🌐 DNS Lookup IPv6 Pro (JavaScript)');
    console.log(`📂 Загружено ${domains.length} доменов.`);

    const lookup = new DNSLookupIPv6({ timeout: 5000, threads: 20 });
    await lookup.lookupBatch(domains);

    if (lookup.results.length > 0) {
        lookup.printTable();
        lookup.saveJSON('dns_results.json');
        lookup.saveCSV('dns_results.csv');
    } else {
        console.log('❌ Не удалось выполнить lookup.');
    }
}

main().catch(console.error);
