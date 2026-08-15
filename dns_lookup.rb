# dns_lookup.rb — Ruby версия

require 'resolv'
require 'json'
require 'csv'
require 'time'
require 'ipaddr'
require 'concurrent'

class DNSLookupIPv6
  attr_reader :results

  def initialize(timeout: 5, threads: 20)
    @timeout = timeout
    @threads = threads
    @results = []
    @resolver = Resolv::DNS.new
    @resolver.timeouts = timeout
  end

  def is_ipv6?(addr)
    begin
      IPAddr.new(addr).ipv6?
    rescue
      false
    end
  end

  def lookup_aaaa(domain)
    begin
      @resolver.getresources(domain, Resolv::DNS::Resource::IN::AAAA)
               .map { |r| r.address.to_s }
    rescue Resolv::ResolvError, Resolv::ResolvTimeout
      []
    end
  end

  def lookup_ptr(ip)
    begin
      @resolver.getnames(ip).map(&:to_s)
    rescue
      []
    end
  end

  def lookup_domain(domain)
    domain = domain.strip
    return nil if domain.empty?

    # Проверяем, является ли строка IPv6-адресом
    if is_ipv6?(domain)
      ptr = lookup_ptr(domain)
      return {
        domain: domain,
        timestamp: Time.now.iso8601,
        AAAA: [],
        PTR: ptr.empty? ? ['не найден'] : ptr
      }
    end

    aaaa = lookup_aaaa(domain)
    ptr = []
    if aaaa.any?
      aaaa.each do |ip|
        ptr.concat(lookup_ptr(ip))
      end
    end
    ptr = ['не найден'] if ptr.empty?

    {
      domain: domain,
      timestamp: Time.now.iso8601,
      AAAA: aaaa,
      PTR: ptr
    }
  end

  def lookup_batch(domains)
    puts "🔍 Выполняем lookup для #{domains.size} доменов..."
    start = Time.now

    pool = Concurrent::FixedThreadPool.new(@threads)
    futures = domains.map do |domain|
      Concurrent::Future.execute(executor: pool) do
        result = lookup_domain(domain)
        if result
          @results << result
          puts "✅ #{domain} — выполнено"
        end
      end
    end
    futures.each(&:wait)

    elapsed = Time.now - start
    puts "⏱️ Время выполнения: #{elapsed.round(2)} сек."
    @results
  end

  def save_json(filename)
    File.write(filename, JSON.pretty_generate(@results))
    puts "💾 Сохранено JSON: #{filename}"
  end

  def save_csv(filename)
    return if @results.empty?
    CSV.open(filename, 'w') do |csv|
      csv << ['Domain', 'Timestamp', 'AAAA', 'PTR']
      @results.each do |r|
        csv << [
          r[:domain],
          r[:timestamp],
          r[:AAAA].join('; '),
          r[:PTR].join('; ')
        ]
      end
    end
    puts "💾 Сохранено CSV: #{filename}"
  end

  def print_table
    return if @results.empty?

    puts "\n" + "=" * 90
    printf "%-25s %-35s %-25s\n", "Домен/IP", "AAAA", "PTR"
    puts "-" * 90
    @results.each do |r|
      aaaa = r[:AAAA].join('; ')
      aaaa = '—' if aaaa.empty?
      aaaa = aaaa[0...35] + '...' if aaaa.length > 35
      ptr = r[:PTR].join('; ')
      ptr = ptr[0...25] + '...' if ptr.length > 25
      printf "%-25s %-35s %-25s\n", r[:domain], aaaa, ptr
    end
    puts "=" * 90
  end
end

def main
  if ARGV.empty?
    puts "Usage: ruby dns_lookup.rb <domains.txt>"
    puts "   или: ruby dns_lookup.rb domain1.com domain2.com"
    exit 1
  end

  domains = []

  if ARGV.size == 1 && File.exist?(ARGV[0])
    domains = File.readlines(ARGV[0]).map(&:strip).reject(&:empty?)
  else
    domains = ARGV
  end

  if domains.empty?
    puts "❌ Нет доменов для проверки."
    exit 1
  end

  puts "🌐 DNS Lookup IPv6 Pro (Ruby)"
  puts "📂 Загружено #{domains.size} доменов."

  lookup = DNSLookupIPv6.new(timeout: 5, threads: 20)
  lookup.lookup_batch(domains)

  unless lookup.results.empty?
    lookup.print_table
    lookup.save_json('dns_results.json')
    lookup.save_csv('dns_results.csv')
  else
    puts "❌ Не удалось выполнить lookup."
  end
end

main if __FILE__ == $0
