package org.fordes.adg.rule;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.TimeInterval;
import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.DnsConfig;
import org.fordes.adg.rule.enums.RuleType;

import java.net.IDN;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
        log.info("DNS 校验：涉及域名 {} 个，优先 TCP 探活分流，未命中的才通过本地 SmartDNS 发起查询",
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
     * <p>
     * 另外按 {@code restartBatchSize} 维护一条独立的、更粗粒度的批次边界：每处理满一批就
     * 执行一次 {@code restartCommand}，重启本地 SmartDNS 进程，并在重启前后主动做健康检查、
     * 按指数退避等待其恢复，防止长跑任务里守护进程状态退化
     * （参考 217heidai/adblockfilters-modified 的 {@code health_check_interval} / {@code __wait_for_smartdns} 机制）。
     */
    private static Result validate(List<String> toCheck, DnsConfig config) {
        Result result = new Result();
        if (toCheck.isEmpty()) {
            return result;
        }

        // 开跑之前先确认一次 SmartDNS 是健康的，避免一上来就把大批查询打在一个还没就绪/已经异常的实例上
        waitForSmartDnsHealthy(config);

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
        int restartBatchSize = config.getRestartBatchSize();
        AtomicInteger nextRestartThreshold = new AtomicInteger(restartBatchSize > 0 ? restartBatchSize : Integer.MAX_VALUE);

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
                        futures.put(domain, DnsValidator.validateAsync(domain, config)
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

                    // 参考 adblockfilters-modified 的 health_check_interval：
                    // 每处理满一批（restartBatchSize 个域名），重启一次本地 SmartDNS 进程，
                    // 重启前后都主动做健康检查、按指数退避等待其恢复，而不是重启完就立刻无脑继续。
                    // restartBatchSize<=0 时该功能关闭。
                    while (totalChecked.get() >= nextRestartThreshold.get()) {
                        restartSmartDnsIfConfigured(config);
                        waitForSmartDnsHealthy(config);
                        nextRestartThreshold.addAndGet(restartBatchSize);
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

    /**
     * 执行一次 SmartDNS 重启命令（同步等待其退出）。命令为空、执行异常或超时都只记录警告，
     * 不会中断本轮 DNS 校验——重启只是尽力而为的优化手段，不是校验流程的硬性前置条件。
     */
    private static void restartSmartDnsIfConfigured(DnsConfig config) {
        String command = config.getRestartCommand();
        if (command == null || command.isBlank()) {
            return;
        }
        try {
            log.info("DNS 校验：达到批次边界，执行 SmartDNS 重启命令: {}", command);
            Process process = new ProcessBuilder("sh", "-c", command)
                    .redirectErrorStream(true)
                    .start();
            boolean finished = process.waitFor(config.getRestartTimeoutSeconds(), TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                log.warn("DNS 校验：SmartDNS 重启命令超过 {} 秒未完成，已强制终止，本轮校验继续",
                        config.getRestartTimeoutSeconds());
            } else if (process.exitValue() != 0) {
                log.warn("DNS 校验：SmartDNS 重启命令退出码非 0（{}），本轮校验继续", process.exitValue());
            }
        } catch (Exception e) {
            log.warn("DNS 校验：执行 SmartDNS 重启命令异常，本轮校验继续: {}", e.getMessage());
        }
    }

    /**
     * 主动探测 SmartDNS（servers 中的第一台，通常就是本地 sidecar）是否健康：
     * 对 example.com 发起一次真实的 A 记录查询，成功即视为健康。
     * 不健康则按指数退避（{@code healthCheckInitialBackoffSeconds} 起步，每次翻倍，
     * 上限 60 秒）持续重试，直到健康或达到 {@code healthCheckMaxWaitSeconds} 总等待上限为止——
     * 参考 217heidai/adblockfilters-modified 的 {@code __wait_for_smartdns}。
     * <p>
     * 达到等待上限仍不健康只记录警告、继续后续校验，不中断整个任务
     * （SmartDNS 若确实起不来，后续查询自然会大量失败，交给外层的 {@code maxFailureRatio} 兜底）。
     */
    private static void waitForSmartDnsHealthy(DnsConfig config) {
        if (!config.isHealthCheckEnabled() || config.getServers() == null || config.getServers().isEmpty()) {
            return;
        }
        String server = config.getServers().get(0);
        long start = System.currentTimeMillis();
        long maxWaitMillis = Math.max(0, config.getHealthCheckMaxWaitSeconds()) * 1000L;
        int backoffSeconds = Math.max(1, config.getHealthCheckInitialBackoffSeconds());
        int attempt = 0;

        while (true) {
            if (isSmartDnsHealthy(server, config.getHealthCheckTimeoutSeconds())) {
                if (attempt > 0) {
                    log.info("SmartDNS 健康检查通过（第 {} 次尝试后恢复）", attempt);
                }
                return;
            }
            attempt++;
            if (System.currentTimeMillis() - start >= maxWaitMillis) {
                log.warn("SmartDNS 健康检查在 {} 秒内始终未通过，放弃等待，继续后续校验",
                        config.getHealthCheckMaxWaitSeconds());
                return;
            }
            log.warn("SmartDNS 健康检查未通过（第 {} 次尝试），{} 秒后重试", attempt, backoffSeconds);
            try {
                TimeUnit.SECONDS.sleep(backoffSeconds);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
            backoffSeconds = Math.min(backoffSeconds * 2, 60);
        }
    }

    private static boolean isSmartDnsHealthy(String server, int timeoutSeconds) {
        DnsConfig probeConfig = new DnsConfig();
        probeConfig.setServers(Collections.singletonList(server));
        probeConfig.setTimeout(timeoutSeconds);
        probeConfig.setCheckAaaa(false);
        try {
            Boolean resolvable = DnsValidator.isResolvableAsync("example.com.", probeConfig)
                    .get(timeoutSeconds + 1L, TimeUnit.SECONDS);
            return Boolean.TRUE.equals(resolvable);
        } catch (Exception e) {
            return false;
        }
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
