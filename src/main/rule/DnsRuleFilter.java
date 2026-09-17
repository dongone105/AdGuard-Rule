package org.fordes.adg.rule;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.TimeInterval;
import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.DnsConfig;
import org.fordes.adg.rule.enums.RuleType;

import java.net.IDN;
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

        // 不再维护 Java 侧的本地结论缓存：所有域名都真实发起一次查询，
        // 查询是否快、是否产生真实上游流量，完全交给 servers 指向的 SmartDNS 自身的查询缓存决定
        // （命中缓存时 SmartDNS 在 loopback 上是毫秒级响应，详见 config/smartdns.conf）
        List<String> toCheck = new ArrayList<>(keysByDomain.keySet());
        log.info("DNS 校验：涉及域名 {} 个，全部通过本地 SmartDNS 发起查询（缓存命中与否由 SmartDNS 自身决定）",
                toCheck.size());

        Result result = validate(toCheck, config);

        int evaluated = result.confirmedValid.size() + result.confirmedInvalid.size();
        double failureRatio = evaluated == 0 ? 0 : (double) result.confirmedInvalid.size() / evaluated;

        log.info("DNS 校验完成 => 实际查询 {} 确认有效 {} 确认失效 {} 未完成(按保留处理) {} "
                        + "失败率 {} 耗时 {} ms",
                toCheck.size(), result.confirmedValid.size(),
                result.confirmedInvalid.size(), result.notCompleted.size(),
                String.format("%.2f%%", failureRatio * 100), interval.intervalMs());

        if (failureRatio > config.getMaxFailureRatio()) {
            log.warn("DNS 校验失败率 {} 超过阈值 {}，判定为 DNS 环境异常（例如 CI 出网受限、SmartDNS sidecar 未就绪），"
                            + "本次跳过剔除，规则集保持不变",
                    String.format("%.2f%%", failureRatio * 100),
                    String.format("%.2f%%", config.getMaxFailureRatio() * 100));
            return;
        }

        Set<String> allInvalid = result.confirmedInvalid;

        Map<RuleType, Set<String>> keysToRemove = new EnumMap<>(RuleType.class);
        for (String domain : allInvalid) {
            for (RuleRef ref : keysByDomain.get(domain)) {
                keysToRemove.computeIfAbsent(ref.type, t -> new HashSet<>()).add(ref.key);
            }
        }
        int removedRules = keysToRemove.values().stream().mapToInt(Set::size).sum();
        for (Map.Entry<RuleType, Set<String>> entry : keysToRemove.entrySet()) {
            aggregator.removeIf(entry.getKey(), entry.getValue()::contains);
        }
        log.info("DNS 校验剔除 {} 条失效规则（对应 {} 个失效域名）", removedRules, allInvalid.size());
    }

    /**
     * 校验一批域名。底层是异步非阻塞查询，不再需要线程池；
     * 但仍然按 {@code maxConcurrentQueries} 分批（chunk）派发，避免瞬间向 DNS 服务器
     * 发出远超其承受能力的并发查询包（例如几万个域名 × 6 台服务器 一次性全部发出）。
     */
    private static Result validate(List<String> toCheck, DnsConfig config) {
        Result result = new Result();
        if (toCheck.isEmpty()) {
            return result;
        }

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

        int chunkSize = Math.max(1, config.getMaxConcurrentQueries());

        try {
            List<String> round = toCheck;
            int roundsLeft = Math.max(0, config.getRetries()) + 1;

            attempts:
            for (int attempt = 0; attempt < roundsLeft && !round.isEmpty(); attempt++) {
                if (attempt > 0) {
                    log.info("DNS 校验：对上一轮 {} 个未解析域名进行第 {} 次重试", round.size(), attempt);
                }

                List<String> nextRound = new ArrayList<>();
                for (int from = 0; from < round.size(); from += chunkSize) {
                    long remaining = deadline - System.currentTimeMillis();
                    if (remaining <= 0) {
                        // 本批及之后所有未派发的域名，一律按保留处理，不再发起新查询
                        result.notCompleted.addAll(round.subList(from, round.size()));
                        round = new ArrayList<>();
                        break attempts;
                    }

                    List<String> chunk = round.subList(from, Math.min(from + chunkSize, round.size()));
                    Map<String, CompletableFuture<Boolean>> futures = new HashMap<>();
                    for (String domain : chunk) {
                        futures.put(domain, DnsValidator.isResolvableAsync(domain, config)
                                .whenComplete((resolvable, error) -> totalChecked.incrementAndGet()));
                    }

                    try {
                        CompletableFuture.allOf(futures.values().toArray(new CompletableFuture[0]))
                                .get(remaining, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException timeout) {
                        long pending = futures.values().stream().filter(f -> !f.isDone()).count();
                        log.warn("DNS 校验达到总体时间上限（{} 分钟），当前批次仍有 {} 个域名未完成校验，按保留处理",
                                config.getMaxDurationMinutes(), pending);
                    } catch (Exception e) {
                        log.warn("DNS 校验等待过程中出现异常: {}", e.getMessage());
                    }

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
                }
                round = nextRound;
            }
            result.confirmedInvalid.addAll(round);
        } finally {
            progressTask.cancel(false);
            scheduler.shutdownNow();
        }

        return result;
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
