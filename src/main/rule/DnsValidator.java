package org.fordes.adg.rule;

import org.fordes.adg.rule.config.DnsConfig;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.time.Duration;

/**
 * 域名 DNS 有效性校验
 * <p>
 * 依次尝试配置中的每一台 DNS 服务器，只要有任意一台能解析出 A 或 AAAA 记录，
 * 即认为该域名仍然有效；全部服务器均解析失败（NXDOMAIN/SERVFAIL/超时）才判定为失效。
 */
public final class DnsValidator {

    private DnsValidator() {
    }

    public static boolean isResolvable(String domain, DnsConfig config) {
        for (String server : config.getServers()) {
            int attempts = Math.max(1, config.getRetries());
            for (int i = 0; i < attempts; i++) {
                if (query(domain, server, Type.A, config.getTimeout())
                        || query(domain, server, Type.AAAA, config.getTimeout())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean query(String domain, String server, int type, int timeoutSeconds) {
        try {
            SimpleResolver resolver = new SimpleResolver(server);
            resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));

            Lookup lookup = new Lookup(domain + ".", type);
            lookup.setResolver(resolver);
            // 关闭 dnsjava 自带的静态缓存，避免多线程共享缓存互相干扰、也保证每次都是真实查询
            lookup.setCache(null);

            Record[] records = lookup.run();
            return lookup.getResult() == Lookup.SUCCESSFUL && records != null && records.length > 0;
        } catch (Exception e) {
            return false;
        }
    }
}
