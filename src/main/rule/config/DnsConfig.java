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
 *
 * @see org.fordes.adg.rule.DnsRuleFilter
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
     * 单次查询超时时间（秒）。同一域名对所有服务器、A/AAAA 记录都是并发查询的，
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
     * 校验并发线程数，I/O 密集型任务，可以设置得比 CPU 核心数大很多。
     * 该线程池同时承担「域名调度」和「实际 DNS 查询」，不会相互阻塞
     */
    private int threads = 200;

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

    /**
     * 是否启用磁盘缓存。开启后，近期已确认可解析的域名会跳过真实查询，
     * 只需要校验新增/缓存过期的域名，能大幅缩短重复运行（12 小时一次）的总耗时，
     * 是解决「首次全量校验容易超时」问题的关键手段
     */
    private boolean cacheEnabled = true;

    /**
     * 缓存文件路径，相对路径从项目目录开始解析。
     * 默认放在 rule 目录下且不以 "." 开头，这样已有的 CI 提交步骤
     * （git add -- rule/*.txt）会自动把它一并提交，缓存天然跨运行持久化，
     * 不需要额外改动 workflow 或引入 actions/cache
     */
    private String cachePath = "rule/dns-cache.txt";

    /**
     * 缓存有效期（小时），超过该时间的缓存记录视为过期，需要重新真实校验
     */
    private int cacheTtlHours = 72;
}
