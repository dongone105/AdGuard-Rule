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

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

    /**
     * TCP 连接探测专用线程池。{@link Socket#connect} 是阻塞调用，但探测本身很轻量
     * （只需要三次握手成功与否），用一个独立的、按需扩容的线程池承载即可，
     * 不会影响 DNS 查询那边真正的异步 NIO 模型
     */
    private static final ExecutorService PROBE_EXECUTOR = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "dns-tcp-probe");
        t.setDaemon(true);
        return t;
    });

    private DnsValidator() {
    }

    /**
     * 校验入口。若启用了连接探测（{@link DnsConfig#isConnectProbeEnabled()}），
     * 先尝试对域名的 80/443 端口做一次 TCP 连接：连通即直接判定存活，不消耗任何真实 DNS 查询。
     * <p>
     * 关键点：这一步用的是 JVM/操作系统默认的域名解析（{@link java.net.InetAddress}），
     * 完全不经过 servers 里配置的本地 SmartDNS，因此不受 SmartDNS 是否命中缓存、是否过载的影响，
     * 是一条独立于 DNS 校验之外、更快速也更抗干扰的存活判定路径——
     * 参考 217heidai/adblockfilters-modified 里 {@code __pingx} 的思路：
     * 能连通就不必再指望本地那台「每次都要打真实上游」的 SmartDNS。
     * <p>
     * 连接失败（或未启用探测）时才 fallback 到 {@link #isResolvableAsync(String, DnsConfig)}。
     */
    public static CompletableFuture<Boolean> validateAsync(String domain, DnsConfig config) {
        if (!config.isConnectProbeEnabled()) {
            return isResolvableAsync(domain, config);
        }
        return isReachableViaTcp(domain, config.getConnectProbeTimeoutMs())
                .thenCompose(reachable -> Boolean.TRUE.equals(reachable)
                        ? CompletableFuture.completedFuture(true)
                        : isResolvableAsync(domain, config));
    }

    /**
     * 依次尝试 80、443 端口的 TCP 连接，任意一个能建立连接即视为存活。
     * 两次尝试都失败（含域名无法解析、连接超时、连接拒绝等）才返回 false。
     */
    public static CompletableFuture<Boolean> isReachableViaTcp(String domain, int timeoutMs) {
        return CompletableFuture.supplyAsync(
                () -> tryConnect(domain, 80, timeoutMs) || tryConnect(domain, 443, timeoutMs),
                PROBE_EXECUTOR);
    }

    private static boolean tryConnect(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
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
                // 支持 "host:port" 格式（如本地 SmartDNS 的 127.0.0.1:5053）；
                // SimpleResolver(String) 只接受纯主机名且端口固定为 53，无法满足非标准端口的场景
                String host = s;
                int port = SimpleResolver.DEFAULT_PORT;
                int idx = s.lastIndexOf(':');
                if (idx > 0 && s.indexOf(':') == idx) {
                    host = s.substring(0, idx);
                    port = Integer.parseInt(s.substring(idx + 1));
                }
                SimpleResolver resolver = new SimpleResolver(new InetSocketAddress(host, port));
                resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));
                return resolver;
            } catch (Exception e) {
                throw new IllegalStateException("无法初始化 DNS 服务器: " + s, e);
            }
        });
    }
}
