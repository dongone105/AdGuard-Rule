package org.fordes.adg.rule.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS 域名有效性校验配置
 * <p>
 * 用于在输出前，对 DNS_FILTER 类型规则（即 ||domain^ 形式的域名拦截规则）中的域名
 * 进行真实 DNS 解析，剔除已经无法解析（域名已失效/已过期/已注销）的规则，
 * 参考 217heidai/adblockfilters 的思路：任意一台配置的 DNS 服务器能解析出结果即视为有效。
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
     * 单次查询超时时间（秒）
     */
    private int timeout = 3;

    /**
     * 单台 DNS 服务器查询失败后的重试次数
     */
    private int retries = 1;

    /**
     * 校验并发线程数
     */
    private int threads = 64;

    /**
     * 安全阈值：当整体解析失败率超过该比例时，视为 DNS 环境异常（例如 CI 网络被限制），
     * 自动放弃本次剔除操作、保留原始规则，避免把全部规则误杀清空
     */
    private double maxFailureRatio = 0.3;
}
