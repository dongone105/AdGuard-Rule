package org.fordes.adg.rule;

import org.fordes.adg.rule.enums.RuleType;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

public final class RuleAggregator {

    private final Map<RuleType, LinkedHashMap<String, String>> rules = new EnumMap<>(RuleType.class);
    private final Set<String> sources = new LinkedHashSet<>();

    public RuleAggregator() {
        for (RuleType type : RuleType.values()) {
            if (type != RuleType.INVALID) {
                rules.put(type, new LinkedHashMap<>());
            }
        }
    }

    public void add(SourceResult sourceResult) {
        String source = sourceResult.isRemote()
                ? sourceResult.getSource()
                : Paths.get(sourceResult.getSource()).getFileName().toString();
        sources.add(source);
        for (ParsedRule rule : sourceResult.getRules()) {
            rules.get(rule.getType()).putIfAbsent(rule.getDeduplicationKey(), rule.getOutput());
        }
    }

    public List<String> getRules(List<RuleType> types) {
        Set<String> output = new LinkedHashSet<>();
        for (RuleType type : types) {
            Map<String, String> typedRules = rules.get(type);
            if (typedRules != null) {
                output.addAll(typedRules.values());
            }
        }
        return new ArrayList<>(output);
    }

    public int size(RuleType type) {
        Map<String, String> typedRules = rules.get(type);
        return typedRules == null ? 0 : typedRules.size();
    }

    public List<String> getSources() {
        return new ArrayList<>(sources);
    }

    /**
     * 获取指定类型下已去重的规则原文（去重键）集合，用于外部做进一步校验（如 DNS 有效性）
     */
    public Set<String> keys(RuleType type) {
        Map<String, String> typedRules = rules.get(type);
        return typedRules == null ? new LinkedHashSet<>() : new LinkedHashSet<>(typedRules.keySet());
    }

    /**
     * 从指定类型中剔除满足条件的规则（按去重键匹配）
     */
    public void removeIf(RuleType type, Predicate<String> shouldRemove) {
        Map<String, String> typedRules = rules.get(type);
        if (typedRules != null) {
            typedRules.keySet().removeIf(shouldRemove);
        }
    }
}
