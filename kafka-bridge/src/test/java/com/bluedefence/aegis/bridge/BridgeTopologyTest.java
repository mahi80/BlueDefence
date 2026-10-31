package com.bluedefence.aegis.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The topology end to end against a recording sink — no broker, no AEGIS. */
class BridgeTopologyTest {

    private static final Instant T0 = Instant.parse("2026-10-29T06:00:00Z");

    private final List<String[]> sent = new ArrayList<>();          // [path, line]
    private AegisSink sink;
    private TopologyTestDriver driver;
    private BridgeConfig cfg;

    @BeforeEach
    void setUp() throws Exception {
        Path tmp = Files.createTempDirectory("bridge-test");
        cfg = BridgeConfig.fromEnv(Map.of(
                "KAFKA_BOOTSTRAP_SERVERS", "test:9092", "AEGIS_URL", "http://aegis.test",
                "BRIDGE_DEDUPE_TTL_S", "120", "BRIDGE_FLAP_WINDOW_S", "300", "BRIDGE_FLAP_FORWARD_N", "5",
                "BRIDGE_BATCH_LINES", "1000", "BRIDGE_MAX_BUFFERED_LINES", "100000", "BRIDGE_STATE_DIR", tmp.toString()));
        // a sink that records instead of posting; batchLines is huge so nothing flushes on its own
        sink = new AegisSink((path, body) -> 200, 1_000_000, Duration.ofHours(1), 10_000_000) {
            @Override
            public void offer(String path, String line) {
                sent.add(new String[] {path, line});
            }
        };
        Properties p = new Properties();
        p.put(StreamsConfig.APPLICATION_ID_CONFIG, "test");
        p.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, "test:9092");
        p.put(StreamsConfig.DEFAULT_KEY_SERDE_CLASS_CONFIG, Serdes.String().getClass());
        p.put(StreamsConfig.DEFAULT_VALUE_SERDE_CLASS_CONFIG, Serdes.String().getClass());
        p.put(StreamsConfig.STATE_DIR_CONFIG, tmp.toString());
        driver = new TopologyTestDriver(BridgeTopology.build(cfg, sink), p, T0);
    }

    @AfterEach
    void tearDown() {
        driver.close();
    }

    private TestInputTopic<String, String> topic(String name) {
        return driver.createInputTopic(name, new StringSerializer(), new StringSerializer(), T0, Duration.ZERO);
    }

    private long count(String path) {
        return sent.stream().filter(s -> s[0].equals(path)).count();
    }

    @Test
    void syslogIsKeyedByDeviceAndRouted() {
        var in = topic(cfg.topicSyslog());
        in.pipeInput(null, "<189>DIST-01: 2026 Oct 29 06:00:01 UTC: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent", T0);
        assertEquals(1, count(BridgeTopology.PATH_SYSLOG));
        assertTrue(sent.get(0)[1].contains("BGP-5-ADJCHANGE"));
    }

    @Test
    void redeliveredRecordIsDroppedInsideTtlAndPassedAfter() {
        var in = topic(cfg.topicSyslog());
        String line = "<189>CORE-01: Oct 29 2026 06:00:00: %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Ethernet1/1 from FULL to DOWN";
        in.pipeInput("CORE-01", line, T0);
        in.pipeInput("CORE-01", line, T0.plusSeconds(30));          // relay reconnect replays it
        assertEquals(1, count(BridgeTopology.PATH_SYSLOG), "duplicate inside the TTL is dropped");
        in.pipeInput("CORE-01", line, T0.plusSeconds(200));         // the same text 200 s later is a new event
        assertEquals(2, count(BridgeTopology.PATH_SYSLOG));
    }

    @Test
    void flappingInterfaceIsCappedAndSummarised() {
        var in = topic(cfg.topicSyslog());
        for (int i = 0; i < 40; i++) {
            String st = i % 2 == 0 ? "down" : "up";
            // every line differs (timestamp) so dedupe does not interfere
            in.pipeInput("ACC-17", "<189>ACC-17: *Oct 29 06:0" + (i / 10) + ":" + String.format("%02d", i % 60)
                    + ".000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/49, changed state to " + st, T0.plusSeconds(i * 3L));
        }
        assertEquals(5, count(BridgeTopology.PATH_SYSLOG), "only the first N transitions reach AEGIS inside the window");
        // the window closes on wall-clock punctuation: advance past it
        driver.advanceWallClockTime(Duration.ofSeconds(320));
        List<String> lines = sent.stream().map(s -> s[1]).toList();
        assertEquals(6, lines.size(), "one summary line after the window");
        String summary = lines.get(5);
        assertTrue(summary.contains("%AEGIS-5-FLAP_SUPPRESSED"), summary);
        assertTrue(summary.contains("GigabitEthernet1/0/49"), summary);
        assertTrue(summary.contains("35 further"), summary);
    }

    @Test
    void nonTransitionLinesAreNotTouchedByFlapAggregation() {
        var in = topic(cfg.topicSyslog());
        for (int i = 0; i < 20; i++) {
            in.pipeInput("DIST-02", "<189>DIST-02: 2026 Oct 29 06:00:" + String.format("%02d", i)
                    + " UTC: %ETHPORT-5-IF_ERRORS: Interface Ethernet1/5 CRC errors " + i, T0.plusSeconds(i));
        }
        assertEquals(20, count(BridgeTopology.PATH_SYSLOG));
    }

    @Test
    void netflowTelemetryAndAlertsGoToTheirEndpoints() {
        topic(cfg.topicNetflow()).pipeInput("x", "{\"src_ip\":\"10.1.1.1\",\"dst_ip\":\"10.2.2.2\",\"bytes\":1200}", T0);
        topic(cfg.topicTelemetry()).pipeInput("DIST-01", "{\"device\":\"DIST-01\",\"interface\":\"Ethernet1/49\",\"in_octets\":5}", T0);
        topic(cfg.topicAlerts()).pipeInput(null, "{\"id\":\"wf-1\",\"source\":\"waf\",\"severity\":\"high\"}", T0);
        topic(cfg.topicAlerts()).pipeInput(null, "{\"id\":\"wf-1\",\"source\":\"waf\",\"severity\":\"high\"}", T0.plusSeconds(5));
        assertEquals(1, count(BridgeTopology.PATH_NETFLOW));
        assertEquals(1, count(BridgeTopology.PATH_TELEMETRY));
        assertEquals(1, count(BridgeTopology.PATH_ALERTS), "an alert re-delivered with the same id and body is deduped");
    }
}
