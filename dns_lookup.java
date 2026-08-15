// dns_lookup.java — Java версия

import java.io.*;
import java.nio.file.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.time.*;
import org.xbill.DNS.*;

public class dns_lookup {
    private static final int TIMEOUT = 5000;
    private static final int THREADS = 20;
    private static List<Map<String, Object>> results = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java -cp .:dnsjava.jar dns_lookup <domains.txt>");
            System.out.println("   или: java -cp .:dnsjava.jar dns_lookup domain1.com domain2.com");
            System.exit(1);
        }

        List<String> domains = new ArrayList<>();

        if (args.length == 1 && new File(args[0]).exists()) {
            domains = Files.readAllLines(Paths.get(args[0]));
            domains.removeIf(String::isBlank);
        } else {
            domains = Arrays.asList(args);
        }

        if (domains.isEmpty()) {
            System.out.println("❌ Нет доменов для проверки.");
            System.exit(1);
        }

        System.out.println("🌐 DNS Lookup IPv6 Pro (Java)");
        System.out.println("📂 Загружено " + domains.size() + " доменов.");

        ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        List<Future<Map<String, Object>>> futures = new ArrayList<>();

        long start = System.currentTimeMillis();

        for (String domain : domains) {
            futures.add(executor.submit(() -> lookupDomain(domain.trim())));
        }

        for (Future<Map<String, Object>> future : futures) {
            try {
                Map<String, Object> result = future.get();
                if (result != null && !result.isEmpty()) {
                    results.add(result);
                    System.out.println("✅ " + result.get("domain") + " — выполнено");
                }
            } catch (Exception e) {
                System.out.println("❌ Ошибка: " + e.getMessage());
            }
        }

        executor.shutdown();
        executor.awaitTermination(30, TimeUnit.SECONDS);

        double elapsed = (System.currentTimeMillis() - start) / 1000.0;
        System.out.printf("⏱️ Время выполнения: %.2f сек.\n", elapsed);

        if (!results.isEmpty()) {
            printTable();
            saveJSON("dns_results.json");
            saveCSV("dns_results.csv");
        } else {
            System.out.println("❌ Не удалось выполнить lookup.");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> lookupDomain(String domain) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", domain);
        result.put("timestamp", Instant.now().toString());

        try {
            // Проверяем, является ли строка IPv6-адресом
            try {
                InetAddress addr = InetAddress.getByName(domain);
                if (addr instanceof Inet6Address) {
                    // Reverse lookup для IPv6
                    Name rev = ReverseMap.fromAddress(addr.getHostAddress());
                    Record[] ptrRecords = new Lookup(rev, Type.PTR).run();
                    List<String> ptr = new ArrayList<>();
                    if (ptrRecords != null) {
                        for (Record rec : ptrRecords) {
                            ptr.add(rec.rdataToString());
                        }
                    }
                    result.put("AAAA", new ArrayList<>());
                    result.put("PTR", ptr.isEmpty() ? Arrays.asList("не найден") : ptr);
                    return result;
                }
            } catch (UnknownHostException e) {
                // Не IP-адрес, продолжаем как домен
            }

            // AAAA записи
            Lookup lookup = new Lookup(domain, Type.AAAA);
            Record[] records = lookup.run();
            List<String> aaaa = new ArrayList<>();
            if (records != null) {
                for (Record rec : records) {
                    if (rec instanceof AAAARecord) {
                        aaaa.add(((AAAARecord) rec).getAddress().getHostAddress());
                    }
                }
            }
            result.put("AAAA", aaaa);

            // PTR для каждого AAAA адреса
            List<String> ptr = new ArrayList<>();
            if (!aaaa.isEmpty()) {
                for (String ip : aaaa) {
                    Name rev = ReverseMap.fromAddress(ip);
                    Record[] ptrRecords = new Lookup(rev, Type.PTR).run();
                    if (ptrRecords != null) {
                        for (Record rec : ptrRecords) {
                            ptr.add(rec.rdataToString());
                        }
                    }
                }
            }
            result.put("PTR", ptr.isEmpty() ? Arrays.asList("не найден") : ptr);

        } catch (Exception e) {
            result.put("AAAA", new ArrayList<>());
            result.put("PTR", Arrays.asList("не найден"));
        }

        return result;
    }

    @SuppressWarnings("unchecked")
    private static void printTable() {
        System.out.println("\n" + "=".repeat(90));
        System.out.printf("%-25s %-35s %-25s\n", "Домен/IP", "AAAA", "PTR");
        System.out.println("-".repeat(90));
        for (Map<String, Object> r : results) {
            String aaaa = String.join("; ", (List<String>) r.get("AAAA"));
            if (aaaa.isEmpty()) aaaa = "—";
            if (aaaa.length() > 35) aaaa = aaaa.substring(0, 35) + "...";
            String ptr = String.join("; ", (List<String>) r.get("PTR"));
            if (ptr.length() > 25) ptr = ptr.substring(0, 25) + "...";
            System.out.printf("%-25s %-35s %-25s\n", r.get("domain"), aaaa, ptr);
        }
        System.out.println("=".repeat(90));
    }

    @SuppressWarnings("unchecked")
    private static void saveJSON(String filename) throws IOException {
        String json = new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(results);
        Files.write(Paths.get(filename), json.getBytes());
        System.out.println("💾 Сохранено JSON: " + filename);
    }

    @SuppressWarnings("unchecked")
    private static void saveCSV(String filename) throws IOException {
        if (results.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        sb.append("Domain,Timestamp,AAAA,PTR\n");
        for (Map<String, Object> r : results) {
            sb.append(r.get("domain")).append(",");
            sb.append(r.get("timestamp")).append(",");
            sb.append(String.join("; ", (List<String>) r.get("AAAA"))).append(",");
            sb.append(String.join("; ", (List<String>) r.get("PTR"))).append("\n");
        }
        Files.write(Paths.get(filename), sb.toString().getBytes());
        System.out.println("💾 Сохранено CSV: " + filename);
    }
}
