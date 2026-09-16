package org.fordes.adg.rule;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public final class DnsCache {

    private final Path path;
    private final long ttlSeconds;
    private final Map<String, Long> validatedAt = new ConcurrentHashMap<>();

    private DnsCache(Path path, long ttlSeconds) {
        this.path = path;
        this.ttlSeconds = ttlSeconds;
    }

    public static DnsCache load(Path path, int ttlHours) {
        DnsCache cache = new DnsCache(path, ttlHours * 3600L);
        if (path == null || !Files.exists(path)) {
            return cache;
        }
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (String line : lines) {
                int tab = line.indexOf('\t');
                if (tab <= 0) {
                    continue;
                }
                String domain = line.substring(0, tab);
                try {
                    long timestamp = Long.parseLong(line.substring(tab + 1).trim());
                    cache.validatedAt.put(domain, timestamp);
                } catch (NumberFormatException ignored) {
                }
            }
            log.info("已加载 DNS 校验缓存 {} 条记录 <= {}", cache.validatedAt.size(), path);
        } catch (IOException e) {
            log.warn("读取 DNS 校验缓存失败，本次将重新校验全部域名: {}", e.getMessage());
        }
        return cache;
    }

    public boolean isFresh(String domain) {
        Long timestamp = validatedAt.get(domain);
        return timestamp != null && (System.currentTimeMillis() / 1000 - timestamp) < ttlSeconds;
    }

    public void markValid(String domain) {
        validatedAt.put(domain, System.currentTimeMillis() / 1000);
    }

    public void evict(String domain) {
        validatedAt.remove(domain);
    }

    public void retainAll(Set<String> domains) {
        validatedAt.keySet().retainAll(domains);
    }

    public int size() {
        return validatedAt.size();
    }

    public synchronized void save() {
        if (path == null) {
            return;
        }
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            StringBuilder content = new StringBuilder();
            for (Map.Entry<String, Long> entry : validatedAt.entrySet()) {
                content.append(entry.getKey()).append('\t').append(entry.getValue()).append('\n');
            }
            Files.write(path, content.toString().getBytes(StandardCharsets.UTF_8));
            log.info("已写入 DNS 校验缓存 {} 条记录 => {}", validatedAt.size(), path);
        } catch (IOException e) {
            log.warn("写入 DNS 校验缓存失败（不影响本次规则输出）: {}", e.getMessage());
        }
    }
}
