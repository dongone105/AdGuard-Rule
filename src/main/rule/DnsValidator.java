package org.fordes.adg.rule;

import org.fordes.adg.rule.config.DnsConfig;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 基于 dnsjava 3.x 异步非阻塞 I/O（{@link org.xbill.DNS.Resolver#sendAsync(Message)}）的域名校验器。
 * <p>
 * dnsjava 3.x 起，内置 Resolver 的 {@code sendAsync} 已经是真正的 NIO 实现，
 * 不再像旧版本那样每次查询占用一个操作系统线程；也不同于「线程池 + 阻塞 Lookup.run()」
 * 这种只是把阻塞调用包了一层 CompletableFuture 的伪异步方式——这里每次查询只是
 * 向事件循环注册一个回调，调用线程立即返回，因此可以同时发起远高于线程池模型的并发查询数。
 */
public final class DnsValidator {

    // 按 DNS 服务器地址复用 SimpleResolver 实例（内部持有各自的 NIO 客户端，线程安全，可并发复用），
    // 避免每次查询都重新创建/初始化
    private static final ConcurrentHashMap<String, SimpleResolver> RESOLVERS = new ConcurrentHashMap<>();

    private DnsValidator() {
    }

    /**
     * 对一个域名，向配置的全部 DNS 服务器（以及 A/AAAA 记录类型）并发发起异步查询，
     * 任意一个查询率先返回「有结果」即视为该域名有效并立即完成；
     * 全部查询都失败（超时/NXDOMAIN/SERVFAIL/连接异常等）才视为无效。
     */
    public static CompletableFuture<Boolean> isResolvableAsync(String domain, DnsConfig config) {
        Name name;
        try {
            name = Name.fromString(domain, Name.root);
        } catch (Exception e) {
            // 域名格式本身不合法，直接判定为不可解析，不消耗任何网络查询
            return CompletableFuture.completedFuture(false);
        }

        int[] recordTypes = config.isCheckAaaa() ? new int[]{Type.A, Type.AAAA} : new int[]{Type.A};

        List<CompletableFuture<Boolean>> queries = new ArrayList<>();
        for (String server : config.getServers()) {
            SimpleResolver resolver = resolverFor(server, config.getTimeout());
            for (int type : recordTypes) {
                Record question = Record.newRecord(name, type, DClass.IN);
                Message query = Message.newQuery(question);
                queries.add(resolver.sendAsync(query).toCompletableFuture()
                        .handle((message, error) -> error == null && isPositive(message)));
            }
        }

        CompletableFuture<Boolean> result = new CompletableFuture<>();
        AtomicInteger remaining = new AtomicInteger(queries.size());
        for (CompletableFuture<Boolean> query : queries) {
            query.whenComplete((resolvable, error) -> {
                if (Boolean.TRUE.equals(resolvable)) {
                    result.complete(true);
                } else if (remaining.decrementAndGet() == 0) {
                    // 所有服务器/记录类型都已返回且均未成功，才判定为本轮不可解析
                    result.complete(false);
                }
            });
        }
        return result;
    }

    /**
     * 判定响应是否为「域名存活」的正向结果：响应码为 NOERROR 且 ANSWER 区非空。
     * NXDOMAIN、SERVFAIL、REFUSED 或 NOERROR 但空应答（例如只有 SOA 的否定应答）都不算有效。
     */
    private static boolean isPositive(Message message) {
        return message != null
                && message.getRcode() == Rcode.NOERROR
                && !message.getSection(Section.ANSWER).isEmpty();
    }

    private static SimpleResolver resolverFor(String server, int timeoutSeconds) {
        return RESOLVERS.computeIfAbsent(server, s -> {
            try {
                SimpleResolver resolver = new SimpleResolver(s);
                resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));
                return resolver;
            } catch (Exception e) {
                throw new IllegalStateException("无法初始化 DNS 服务器: " + s, e);
            }
        });
    }
}
