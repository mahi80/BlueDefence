package com.bluedefence.aegis.bridge;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Everything the bridge needs, read from the environment so one image runs in every bank's
 * Kafka estate. Nothing here is secret except {@code AEGIS_INGEST_TOKEN}, which is the bearer
 * token the AEGIS push receiver expects on every {@code /ingest/*} call.
 */
public record BridgeConfig(
        String bootstrapServers,
        String applicationId,
        String aegisUrl,
        String ingestToken,
        String topicSyslog,
        String topicNetflow,
        String topicTelemetry,
        String topicAlerts,
        String topicVerdicts,
        Duration dedupeTtl,
        Duration flapWindow,
        int flapForwardN,
        int batchLines,
        Duration linger,
        int maxBufferedLines,
        Duration verdictPoll,
        Path cursorFile,
        boolean persistentStores,
        Path stateDir) {

    public BridgeConfig {
        Objects.requireNonNull(bootstrapServers, "KAFKA_BOOTSTRAP_SERVERS");
        Objects.requireNonNull(aegisUrl, "AEGIS_URL");
        if (aegisUrl.endsWith("/")) {
            aegisUrl = aegisUrl.substring(0, aegisUrl.length() - 1);
        }
        if (flapForwardN < 1) throw new IllegalArgumentException("BRIDGE_FLAP_FORWARD_N must be >= 1");
        if (batchLines < 1) throw new IllegalArgumentException("BRIDGE_BATCH_LINES must be >= 1");
        if (maxBufferedLines < batchLines) throw new IllegalArgumentException("BRIDGE_MAX_BUFFERED_LINES must be >= BRIDGE_BATCH_LINES");
    }

    /** Read from {@code env}; every knob has a default except the two that identify the estate. */
    public static BridgeConfig fromEnv(Map<String, String> env) {
        return new BridgeConfig(
                required(env, "KAFKA_BOOTSTRAP_SERVERS"),
                env.getOrDefault("BRIDGE_APPLICATION_ID", "aegis-kafka-bridge"),
                required(env, "AEGIS_URL"),
                env.getOrDefault("AEGIS_INGEST_TOKEN", ""),
                env.getOrDefault("AEGIS_TOPIC_SYSLOG", "aegis.syslog"),
                env.getOrDefault("AEGIS_TOPIC_NETFLOW", "aegis.netflow"),
                env.getOrDefault("AEGIS_TOPIC_TELEMETRY", "aegis.telemetry"),
                env.getOrDefault("AEGIS_TOPIC_ALERTS", "aegis.alerts"),
                env.getOrDefault("AEGIS_TOPIC_VERDICTS", "aegis.verdicts"),
                Duration.ofSeconds(longOr(env, "BRIDGE_DEDUPE_TTL_S", 120)),
                Duration.ofSeconds(longOr(env, "BRIDGE_FLAP_WINDOW_S", 300)),
                (int) longOr(env, "BRIDGE_FLAP_FORWARD_N", 8),
                (int) longOr(env, "BRIDGE_BATCH_LINES", 500),
                Duration.ofMillis(longOr(env, "BRIDGE_LINGER_MS", 1000)),
                (int) longOr(env, "BRIDGE_MAX_BUFFERED_LINES", 20_000),
                Duration.ofMillis(longOr(env, "BRIDGE_VERDICT_POLL_MS", 2000)),
                Path.of(env.getOrDefault("BRIDGE_CURSOR_FILE", "/var/lib/aegis-bridge/verdict.cursor")),
                "1".equals(env.getOrDefault("BRIDGE_PERSISTENT_STORES", "0")),
                Path.of(env.getOrDefault("BRIDGE_STATE_DIR", "/var/lib/aegis-bridge/streams")));
    }

    private static String required(Map<String, String> env, String key) {
        String v = env.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return v.trim();
    }

    private static long longOr(Map<String, String> env, String key, long dflt) {
        String v = env.get(key);
        if (v == null || v.isBlank()) return dflt;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(key + " must be an integer, got '" + v + "'");
        }
    }
}
