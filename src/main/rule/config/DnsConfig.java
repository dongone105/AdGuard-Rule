package org.fordes.adg.rule.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS 域名有效性校验配置
 * <p>
 * 在输出前，对 DNS_FILTER / DNS_EXCEPTION 类型规则（即 ||domain^ 形式的规范域名规则）
 * 中涉及的域名做真实 DNS 解析，剔除已经无法解析（域名失效/过期/已注销）的规则，
 * 参考 217heidai/adblockfilters 的思路：任意一台配置的 DNS 服务器能解析出结果即视为有效。
 * <p>
 * 底层使用 dnsjava 的异步 NIO 接口（{@code Resolver#sendAsync}）发起查询，
 * 不需要为每个查询占用一个操作系统线程，因此可以支撑远高于传统线程池模型的并发量。
 *
 * @see org.fordes.adg.rule.DnsRuleFilter
 * @see org.fordes.adg.rule.DnsValidator
 */
@Data
@Component
@ConfigurationProperties(prefix = "application.dns")
public class DnsConfig {

    /**
     * 是否启用 DNS 校验，默认关闭，不影响原有行为
     */
    private boolean enabled = false;

    /**
     * 用于校验的 DNS 服务器（建议国内、国外各配置几组，交叉验证降低误判）
     */
    private List<String> servers = new ArrayList<>();

    /**
     * 单次查询超时时间（秒）。同一域名对所有服务器、记录类型都是并发查询的，
     * 因此单个域名单轮的最坏耗时约等于这个值，而不是「服务器数量 × 该值」
     */
    private int timeout = 3;

    /**
     * 一个域名首轮校验失败（所有服务器都无结果）后，额外重试的轮次数。
     * 只有仍在重试名单里的域名才会被再次查询，不会拖慢已经成功/明确失败的域名，
     * 用来降低网络抖动造成的误杀
     */
    private int retries = 1;

    /**
     * 同一时刻允许「在飞」的域名校验数量上限。
     * 底层是异步 NIO 查询，不占用操作系统线程，因此这个值可以设得比传统线程池大很多
     * （比如几千），主要作用是避免瞬间对 DNS 服务器发出过大突发流量，而不是保护 JVM 线程资源
     */
    private int maxConcurrentQueries = 2000;

    /**
     * 是否额外查询 AAAA (IPv6) 记录。广告/跟踪域名基本只需要 A 记录即可判断存活，
     * 默认关闭 AAAA 校验可以把每个域名的查询次数直接减半，是提速最直接的一步。
     * 只有极少数纯 IPv6 域名会因此被误判，且有重试机制兜底
     */
    private boolean checkAaaa = false;

    /**
     * 整个 DNS 校验阶段允许运行的最长时间（分钟）。一旦超时，
     * 已完成校验的结果照常生效，尚未完成的域名一律视为「保留」，不参与剔除，
     * 用来在 CI 总时长有限（例如 GitHub Actions 单次运行 30 分钟内需要跑完构建+校验+提交）
     * 的场景下兜底，避免任务被平台强制杀死
     */
    private int maxDurationMinutes = 20;

    /**
     * 进度日志打印间隔（秒），避免校验期间长时间没有任何输出、看起来像卡死
     */
    private int progressLogIntervalSeconds = 15;

    /**
     * 安全阈值：当（实际查询过的域名中）解析失败的比例超过该值时，
     * 视为 DNS 环境本身异常（例如 CI 出网被限制、DNS 服务器不可达），
     * 自动放弃本次剔除操作、保留原始规则，避免把全部规则误杀清空
     */
    private double maxFailureRatio = 0.3;

    // 【已移除】原本地磁盘缓存配置（cacheEnabled/cachePath/cacheTtlHours/invalidCacheTtlHours）。
    // 校验结论缓存改由 DNS 服务器（本地 SmartDNS sidecar）自身承担：只要 servers 指向的是带持久化
    // 查询缓存的 SmartDNS（见 config/smartdns.conf 的 cache-persist / serve-expired），命中缓存时
    // 在 loopback 上是毫秒级响应，不会产生真实上游查询；Java 侧因此不再需要一份平行的结论缓存，
    // 每次都会发起真实查询，但慢不慢完全取决于 SmartDNS 是否命中它自己的缓存。
}
