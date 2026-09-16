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

/**
 * DNS 校验结果的磁盘缓存。
 * <p>
 * 同时缓存「已确认有效」和「已确认失效」两类结论，各自使用独立的过期时间：
 * 有效结论一般可以缓存得久一些（域名很少突然失效），失效结论缓存时间较短
 * （避免域名下线一段时间后又恢复解析，却因为负缓存一直没被重新校验）。
 * <p>
 * 兼容旧版本只缓存「有效」域名的两列格式（domain\ttimestamp），
 * 读取到旧格式的行会被当作有效结论处理。
 */
@Slf4j
public final class DnsCache {

    private final Path path;
    private final long validTtlSeconds;
    private final long invalidTtlSeconds;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    private DnsCache(Path path, long validTtlSeconds, long invalidTtlSeconds) {
        this.path = path;
        this.validTtlSeconds = validTtlSeconds;
        this.invalidTtlSeconds = invalidTtlSeconds;
    }

    public static DnsCache load(Path path, int validTtlHours, int invalidTtlHours) {
        DnsCache cache = new DnsCache(path, validTtlHours * 3600L, invalidTtlHours * 3600L);
        if (path == null || !Files.exists(path)) {
            return cache;
        }
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (String line : lines) {
                String[] parts = line.split("\t", -1);
                if (parts.length < 2 || parts[0].isEmpty()) {
                    continue;
                }
                try {
                    long timestamp = Long.parseLong(parts[1].trim());
                    // 兼容旧格式：只有两列(domain\ttimestamp)时，一律当作「有效」处理
                    boolean valid = parts.length < 3 || "1".equals(parts[2].trim());
                    cache.entries.put(parts[0], new Entry(timestamp, valid));
                } catch (NumberFormatException ignored) {
                }
            }
            log.info("已加载 DNS 校验缓存 {} 条记录 <= {}", cache.entries.size(), path);
        } catch (IOException e) {
            log.warn("读取 DNS 校验缓存失败，本次将重新校验全部域名: {}", e.getMessage());
        }
        return cache;
    }

    /**
     * 是否命中「新鲜」缓存（不区分有效/失效），命中则本轮跳过真实查询，直接沿用缓存结论
     */
    public boolean isFresh(String domain) {
        Entry entry = entries.get(domain);
        if (entry == null) {
            return false;
        }
        long ttl = entry.valid ? validTtlSeconds : invalidTtlSeconds;
        return (System.currentTimeMillis() / 1000 - entry.timestamp) < ttl;
    }

    /**
     * 缓存中该域名的历史结论；只有在 {@link #isFresh(String)} 为 true 时调用才有意义
     */
    public boolean cachedValid(String domain) {
        Entry entry = entries.get(domain);
        return entry != null && entry.valid;
    }

    public void markValid(String domain) {
        entries.put(domain, new Entry(System.currentTimeMillis() / 1000, true));
    }

    public void markInvalid(String domain) {
        entries.put(domain, new Entry(System.currentTimeMillis() / 1000, false));
    }

    public void retainAll(Set<String> domains) {
        entries.keySet().retainAll(domains);
    }

    public int size() {
        return entries.size();
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
            for (Map.Entry<String, Entry> entry : entries.entrySet()) {
                content.append(entry.getKey()).append('\t')
                        .append(entry.getValue().timestamp).append('\t')
                        .append(entry.getValue().valid ? '1' : '0').append('\n');
            }
            Files.write(path, content.toString().getBytes(StandardCharsets.UTF_8));
            log.info("已写入 DNS 校验缓存 {} 条记录 => {}", entries.size(), path);
        } catch (IOException e) {
            log.warn("写入 DNS 校验缓存失败（不影响本次规则输出）: {}", e.getMessage());
        }
    }

    private static final class Entry {
        final long timestamp;
        final boolean valid;

        Entry(long timestamp, boolean valid) {
            this.timestamp = timestamp;
            this.valid = valid;
        }
    }
}
