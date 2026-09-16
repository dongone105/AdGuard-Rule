package org.fordes.adg.rule;

import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.DnsConfig;
import org.fordes.adg.rule.enums.RuleType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 对 {@link RuleType#DNS_FILTER} 规则（即 {@code ||domain^} 形式的规范域名拦截规则）
 * 做 DNS 有效性校验，剔除已经无法解析的域名。
 * <p>
 * 不处理 DNS_EXCEPTION（放行规则，保留不影响正确性）、REGEX、MODIFY（非完整域名，无法直接解析）。
 */
@Slf4j
public final class DnsRuleFilter {

    /**
     * 从 ||domain^ 或 ||domain^$modifier 形式的规则中提取域名部分
     */
    private static final Pattern DOMAIN_EXTRACT = Pattern.compile("^\\|\\|([^\\^$]+)");

    private DnsRuleFilter() {
    }

    public static void apply(RuleAggregator aggregator, DnsConfig config) {
        Set<String> ruleKeys = aggregator.keys(RuleType.DNS_FILTER);
        if (ruleKeys.isEmpty()) {
            return;
        }

        // 域名 -> 命中该域名的规则原文（通常 1:1，*.domain 通配符按基础域名归并校验）
        Map<String, List<String>> domainToKeys = new HashMap<>();
        for (String key : ruleKeys) {
            String domain = extractDomain(key);
            if (domain != null) {
                domainToKeys.computeIfAbsent(domain, d -> new ArrayList<>()).add(key);
            }
        }
        if (domainToKeys.isEmpty()) {
            return;
        }

        int threads = Math.max(1, config.getThreads());
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger checked = new AtomicInteger();
        Map<String, Future<Boolean>> futures = new HashMap<>();

        try {
            for (String domain : domainToKeys.keySet()) {
                futures.put(domain, pool.submit(() -> DnsValidator.isResolvable(domain, config)));
            }

            Set<String> deadKeys = new HashSet<>();
            int failed = 0;
            long perDomainTimeout = (long) Math.max(1, config.getRetries())
                    * config.getServers().size() * config.getTimeout() + 5;

            for (Map.Entry<String, Future<Boolean>> entry : futures.entrySet()) {
                checked.incrementAndGet();
                boolean alive;
                try {
                    alive = entry.getValue().get(perDomainTimeout, TimeUnit.SECONDS);
                } catch (Exception e) {
                    // 查询本身异常/超时，出于安全考虑按“有效”处理，不参与剔除统计
                    alive = true;
                }
                if (!alive) {
                    failed++;
                    deadKeys.addAll(domainToKeys.get(entry.getKey()));
                }
            }

            double failureRatio = domainToKeys.isEmpty() ? 0 : (double) failed / domainToKeys.size();
            if (failureRatio > config.getMaxFailureRatio()) {
                log.warn("DNS 校验失败率过高 => {} / {} ({}%)，疑似 DNS 环境异常，本次跳过剔除以避免误杀",
                        failed, domainToKeys.size(), Math.round(failureRatio * 100));
                return;
            }

            aggregator.removeIf(RuleType.DNS_FILTER, deadKeys::contains);
            log.info("DNS 校验完成 => 校验域名 {} 个，剔除失效规则 {} 条", domainToKeys.size(), deadKeys.size());
        } finally {
            pool.shutdown();
        }
    }

    static String extractDomain(String rule) {
        Matcher matcher = DOMAIN_EXTRACT.matcher(rule);
        if (!matcher.find()) {
            return null;
        }
        String raw = matcher.group(1);
        if (raw.startsWith("*.")) {
            raw = raw.substring(2);
        }
        // 域名中间仍带通配符的（如 ad*.example.com）无法直接解析，跳过校验、保留规则
        if (raw.isEmpty() || raw.contains("*")) {
            return null;
        }
        return raw;
    }
}
