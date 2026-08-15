// dns_lookup.go — Go версия

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type DNSResult struct {
	Domain    string   `json:"domain"`
	Timestamp string   `json:"timestamp"`
	AAAA      []string `json:"AAAA"`
	PTR       []string `json:"PTR"`
}

type DNSLookup struct {
	timeout time.Duration
	threads int
	results []DNSResult
	mu      sync.Mutex
}

func NewDNSLookup(timeout int, threads int) *DNSLookup {
	return &DNSLookup{
		timeout: time.Duration(timeout) * time.Second,
		threads: threads,
		results: []DNSResult{},
	}
}

func (d *DNSLookup) lookupAAAA(domain string) []string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return []string{}
	}
	var result []string
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			result = append(result, ip.String())
		}
	}
	return result
}

func (d *DNSLookup) lookupPTR(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return []string{}
	}
	return names
}

func (d *DNSLookup) lookupDomain(domain string) DNSResult {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return DNSResult{}
	}

	// Проверяем, является ли строка IPv6-адресом
	if ip := net.ParseIP(domain); ip != nil && ip.To4() == nil && ip.To16() != nil {
		ptr := d.lookupPTR(domain)
		return DNSResult{
			Domain:    domain,
			Timestamp: time.Now().Format(time.RFC3339),
			AAAA:      []string{},
			PTR:       ptr,
		}
	}

	aaaa := d.lookupAAAA(domain)
	var ptr []string
	if len(aaaa) > 0 {
		for _, ip := range aaaa {
			names := d.lookupPTR(ip)
			ptr = append(ptr, names...)
		}
	}
	if len(ptr) == 0 {
		ptr = []string{"не найден"}
	}

	return DNSResult{
		Domain:    domain,
		Timestamp: time.Now().Format(time.RFC3339),
		AAAA:      aaaa,
		PTR:       ptr,
	}
}

func (d *DNSLookup) lookupBatch(domains []string) {
	fmt.Printf("🔍 Выполняем lookup для %d доменов...\n", len(domains))
	start := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, d.threads)

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		wg.Add(1)
		go func(dmn string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := d.lookupDomain(dmn)
			d.mu.Lock()
			d.results = append(d.results, result)
			d.mu.Unlock()
			fmt.Printf("✅ %s — выполнено\n", dmn)
		}(domain)
	}

	wg.Wait()
	fmt.Printf("⏱️ Время выполнения: %.2f сек.\n", time.Since(start).Seconds())
}

func (d *DNSLookup) saveJSON(filename string) error {
	data, err := json.MarshalIndent(d.results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (d *DNSLookup) saveCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Domain", "Timestamp", "AAAA", "PTR"})
	for _, r := range d.results {
		writer.Write([]string{
			r.Domain,
			r.Timestamp,
			strings.Join(r.AAAA, "; "),
			strings.Join(r.PTR, "; "),
		})
	}
	return nil
}

func (d *DNSLookup) printTable() {
	if len(d.results) == 0 {
		fmt.Println("Нет результатов.")
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Printf("%-25s %-35s %-25s\n", "Домен/IP", "AAAA", "PTR")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range d.results {
		aaaa := strings.Join(r.AAAA, "; ")
		if len(aaaa) > 35 {
			aaaa = aaaa[:35] + "..."
		}
		ptr := strings.Join(r.PTR, "; ")
		if len(ptr) > 25 {
			ptr = ptr[:25] + "..."
		}
		fmt.Printf("%-25s %-35s %-25s\n", r.Domain, aaaa, ptr)
	}
	fmt.Println(strings.Repeat("=", 90))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run dns_lookup.go <domains.txt>")
		fmt.Println("   или: go run dns_lookup.go domain1.com domain2.com")
		os.Exit(1)
	}

	var domains []string

	if len(os.Args) == 2 && !strings.Contains(os.Args[1], ".") {
		file, err := os.Open(os.Args[1])
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					domains = append(domains, line)
				}
			}
		}
	} else {
		for _, arg := range os.Args[1:] {
			domains = append(domains, arg)
		}
	}

	if len(domains) == 0 {
		fmt.Println("❌ Нет доменов для проверки.")
		os.Exit(1)
	}

	fmt.Println("🌐 DNS Lookup IPv6 Pro (Go)")
	fmt.Printf("📂 Загружено %d доменов.\n", len(domains))

	lookup := NewDNSLookup(5, 20)
	lookup.lookupBatch(domains)

	if len(lookup.results) > 0 {
		lookup.printTable()
		lookup.saveJSON("dns_results.json")
		lookup.saveCSV("dns_results.csv")
		fmt.Println("💾 Сохранено: dns_results.json, dns_results.csv")
	} else {
		fmt.Println("❌ Не удалось выполнить lookup.")
	}
}
