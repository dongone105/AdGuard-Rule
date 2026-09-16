package org.fordes.adg.rule;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.TimeInterval;
import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.DnsConfig;
import org.fordes.adg.rule.enums.RuleType;

import java.net.IDN;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public final class DnsRuleFilter {

    private static final Set<RuleType> VALIDATED_TYPES =
            new HashSet<>(Arrays.asList(RuleType.DNS_FILTER, RuleType.DNS_EXCEPTION));

    private DnsRuleFilter() {
    }

    public static void apply(RuleAggregator aggregator, DnsConfig config) {
        if (config == null || !config.isEnabled()) {
            return;
        }
        if (config.getServers() == null || config.getServers().isEmpty()) {
            log.warn("DNS 校验已启用，但未配置任何 DNS 服务器，跳过本次校验");
            return;
        }

        TimeInterval interval = DateUtil.timer();

        Map<String, List<RuleRef>> keysByDomain = new HashMap<>();
        for (RuleType type : VALIDATED_TYPES) {
            for (String key : aggregator.keys(type)) {
                String domain = extractValidatableDomain(key);
                if (domain == null) {
                    continue;
                }
                keysByDomain.computeIfAbsent(domain, d -> new ArrayList<>()).add(new RuleRef(type, key));
            }
        }

        if (keysByDomain.isEmpty()) {
            log.info("DNS 校验：没有可校验的规范域名规则，跳过");
            return;
        }

        Path cachePath = config.isCacheEnabled() ? Util.resolvePath(config.getCachePath()) : null;
        DnsCache cache = DnsCache.load(cachePath, config.getCacheTtlHours());

        List<String> toCheck = new ArrayList<>();
        int cacheHit = 0;
        for (String domain : keysByDomain.keySet()) {
            if (config.isCacheEnabled() && cache.isFresh(domain)) {
                cacheHit++;
            } else {
                toCheck.add(domain);
            }
        }
        log.info("DNS 校验：涉及域名 {} 个，其中 {} 个命中缓存跳过查询，{} 个需要实际查询",
                keysByDomain.size(), cacheHit, toCheck.size());

        Result result = validate(toCheck, config);

        int evaluated = result.confirmedValid.size() + result.confirmedInvalid.size();
        double failureRatio = evaluated == 0 ? 0 : (double) result.confirmedInvalid.size() / evaluated;

        log.info("DNS 校验完成 => 总域名 {} 缓存命中 {} 实际查询 {} 确认有效 {} 确认失效 {} 未完成(按保留处理) {} "
                        + "失败率 {} 耗时 {} ms",
                keysByDomain.size(), cacheHit, toCheck.size(), result.confirmedValid.size(),
                result.confirmedInvalid.size(), result.notCompleted.size(),
                String.format("%.2f%%", failureRatio * 100), interval.intervalMs());

        if (failureRatio > config.getMaxFailureRatio()) {
            log.warn("DNS 校验失败率 {} 超过阈值 {}，判定为 DNS 环境异常（例如 CI 出网受限、DNS 服务器不可达），"
                            + "本次跳过剔除，规则集保持不变",
                    String.format("%.2f%%", failureRatio * 100),
                    String.format("%.2f%%", config.getMaxFailureRatio() * 100));
            if (config.isCacheEnabled()) {
                result.confirmedValid.forEach(cache::markValid);
                cache.retainAll(keysByDomain.keySet());
                cache.save();
            }
            return;
        }

        Map<RuleType, Set<String>> keysToRemove = new EnumMap<>(RuleType.class);
        for (String domain : result.confirmedInvalid) {
            for (RuleRef ref : keysByDomain.get(domain)) {
                keysToRemove.computeIfAbsent(ref.type, t -> new HashSet<>()).add(ref.key);
            }
        }
        int removedRules = keysToRemove.values().stream().mapToInt(Set::size).sum();
        for (Map.Entry<RuleType, Set<String>> entry : keysToRemove.entrySet()) {
            aggregator.removeIf(entry.getKey(), entry.getValue()::contains);
        }
        log.info("DNS 校验剔除 {} 条失效规则（对应 {} 个失效域名）", removedRules, result.confirmedInvalid.size());

        if (config.isCacheEnabled()) {
            result.confirmedValid.forEach(cache::markValid);
            result.confirmedInvalid.forEach(cache::evict);
            cache.retainAll(keysByDomain.keySet());
            cache.save();
        }
    }

    private static Result validate(List<String> toCheck, DnsConfig config) {
        Result result = new Result();
        if (toCheck.isEmpty()) {
            return result;
        }

        ExecutorService pool = createPool(config.getThreads());
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dns-validator-progress");
            t.setDaemon(true);
            return t;
        });

        long deadline = System.currentTimeMillis() + config.getMaxDurationMinutes() * 60_000L;
        int totalToCheck = toCheck.size();
        AtomicInteger totalChecked = new AtomicInteger(0);

        ScheduledFuture<?> progressTask = scheduler.scheduleAtFixedRate(
                () -> log.info("DNS 校验进行中 => 已完成 {}/{}", totalChecked.get(), totalToCheck),
                config.getProgressLogIntervalSeconds(), config.getProgressLogIntervalSeconds(), TimeUnit.SECONDS);

        try {
            List<String> round = toCheck;
            int roundsLeft = Math.max(0, config.getRetries()) + 1;

            for (int attempt = 0; attempt < roundsLeft && !round.isEmpty(); attempt++) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    result.notCompleted.addAll(round);
                    round = new ArrayList<>();
                    break;
                }
                if (attempt > 0) {
                    log.info("DNS 校验：对上一轮 {} 个未解析域名进行第 {} 次重试", round.size(), attempt);
                }

                Map<String, CompletableFuture<Boolean>> futures = new HashMap<>();
                for (String domain : round) {
                    futures.put(domain, DnsValidator.isResolvableAsync(domain, config, pool)
                            .whenComplete((resolvable, error) -> totalChecked.incrementAndGet()));
                }

                try {
                    CompletableFuture.allOf(futures.values().toArray(new CompletableFuture[0]))
                            .get(remaining, TimeUnit.MILLISECONDS);
                } catch (TimeoutException timeout) {
                    long pending = futures.values().stream().filter(f -> !f.isDone()).count();
                    log.warn("DNS 校验达到总体时间上限（{} 分钟），仍有 {} 个域名未完成校验，按保留处理",
                            config.getMaxDurationMinutes(), pending);
                } catch (Exception e) {
                    log.warn("DNS 校验等待过程中出现异常: {}", e.getMessage());
                }

                List<String> nextRound = new ArrayList<>();
                for (Map.Entry<String, CompletableFuture<Boolean>> entry : futures.entrySet()) {
                    CompletableFuture<Boolean> future = entry.getValue();
                    if (!future.isDone()) {
                        result.notCompleted.add(entry.getKey());
                    } else if (Boolean.TRUE.equals(future.getNow(false))) {
                        result.confirmedValid.add(entry.getKey());
                    } else {
                        nextRound.add(entry.getKey());
                    }
                }
                round = nextRound;
            }
            result.confirmedInvalid.addAll(round);
        } finally {
            progressTask.cancel(false);
            scheduler.shutdownNow();
            pool.shutdownNow();
        }

        return result;
    }

    private static ExecutorService createPool(int threads) {
        int size = Math.max(8, threads);
        AtomicInteger threadNumber = new AtomicInteger();
        return Executors.newFixedThreadPool(size, runnable -> {
            Thread thread = new Thread(runnable, "dns-validator-" + threadNumber.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    private static String extractValidatableDomain(String ruleText) {
        String candidate = ruleText.startsWith("@@") ? ruleText.substring(2) : ruleText;
        int dollar = candidate.indexOf('$');
        String pattern = dollar >= 0 ? candidate.substring(0, dollar) : candidate;

        if (pattern.startsWith("||")) {
            pattern = pattern.substring(2);
        } else if (pattern.startsWith("|")) {
            pattern = pattern.substring(1);
        }
        if (pattern.endsWith("|")) {
            pattern = pattern.substring(0, pattern.length() - 1);
        }
        if (pattern.endsWith("^")) {
            pattern = pattern.substring(0, pattern.length() - 1);
        }

        if (pattern.isEmpty() || pattern.contains("*")) {
            return null;
        }
        try {
            return IDN.toASCII(pattern).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    private static final class RuleRef {
        final RuleType type;
        final String key;

        RuleRef(RuleType type, String key) {
            this.type = type;
            this.key = key;
        }
    }

    private static final class Result {
        final Set<String> confirmedValid = new HashSet<>();
        final Set<String> confirmedInvalid = new HashSet<>();
        final Set<String> notCompleted = new HashSet<>();
    }
}
