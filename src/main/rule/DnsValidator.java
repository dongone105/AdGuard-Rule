package org.fordes.adg.rule;

import org.fordes.adg.rule.config.DnsConfig;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

public final class DnsValidator {

    private static final int[] RECORD_TYPES = {Type.A, Type.AAAA};

    private DnsValidator() {
    }

    public static CompletableFuture<Boolean> isResolvableAsync(String domain, DnsConfig config, ExecutorService pool) {
        List<CompletableFuture<Boolean>> queries = new ArrayList<>();
        for (String server : config.getServers()) {
            for (int type : RECORD_TYPES) {
                queries.add(CompletableFuture.supplyAsync(
                        () -> query(domain, server, type, config.getTimeout()), pool));
            }
        }

        CompletableFuture<Boolean> result = new CompletableFuture<>();
        AtomicInteger remaining = new AtomicInteger(queries.size());
        for (CompletableFuture<Boolean> query : queries) {
            query.whenComplete((resolvable, error) -> {
                if (error == null && Boolean.TRUE.equals(resolvable)) {
                    result.complete(true);
                } else if (remaining.decrementAndGet() == 0) {
                    result.complete(false);
                }
            });
        }
        return result;
    }

    private static boolean query(String domain, String server, int type, int timeoutSeconds) {
        try {
            SimpleResolver resolver = new SimpleResolver(server);
            resolver.setTimeout(Duration.ofSeconds(timeoutSeconds));

            Lookup lookup = new Lookup(domain + ".", type);
            lookup.setResolver(resolver);
            lookup.setCache(null);

            Record[] records = lookup.run();
            return lookup.getResult() == Lookup.SUCCESSFUL && records != null && records.length > 0;
        } catch (Exception e) {
            return false;
        }
    }
}
