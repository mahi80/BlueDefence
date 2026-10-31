package com.bluedefence.aegis.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;

class VerdictPollerTest {

    private static final String FEED = """
            {"after": 0, "next": 2, "count": 2, "verdicts": [
              {"seq": 1, "prev_hash": "0000", "chain": {"alert_id": "net-link_down-abc", "verdict": "suspicious", "integrity_hash": "h1"}},
              {"seq": 2, "prev_hash": "h1", "chain": {"alert_id": "waf-9", "verdict": "malicious", "integrity_hash": "h2"}}
            ]}
            """;

    @Test
    void parsesTheFeed() throws IOException {
        List<VerdictPoller.Verdict> rows = Json.parseVerdicts(FEED);
        assertEquals(2, rows.size());
        assertEquals(1, rows.get(0).seq());
        assertEquals("net-link_down-abc", rows.get(0).alertId());
        assertEquals("h1", rows.get(1).prevHash());
        assertTrue(rows.get(1).json().contains("\"verdict\":\"malicious\""));
    }

    @Test
    void producesInOrderAndPersistsTheCursor() throws Exception {
        Path cursor = Files.createTempDirectory("poller").resolve("verdict.cursor");
        MockProducer<String, String> producer = new MockProducer<>(true, new StringSerializer(), new StringSerializer());
        VerdictPoller.Source source = (after, limit) -> after == 0 ? Json.parseVerdicts(FEED) : List.of();
        VerdictPoller poller = new VerdictPoller(source, producer, "aegis.verdicts", cursor, Duration.ofMillis(100));

        assertEquals(2, poller.pollOnce());
        assertEquals(0, poller.pollOnce(), "nothing new after the cursor");
        assertEquals(2, poller.cursor());
        assertEquals("2", Files.readString(cursor).trim());

        var records = producer.history();
        assertEquals(2, records.size());
        assertEquals("net-link_down-abc", records.get(0).key());
        assertEquals("waf-9", records.get(1).key());
        assertEquals("2", new String(records.get(1).headers().lastHeader("aegis-seq").value(), StandardCharsets.UTF_8));
        assertEquals("h1", new String(records.get(1).headers().lastHeader("aegis-prev-hash").value(), StandardCharsets.UTF_8));

        // a restart resumes from the file, not from 0
        VerdictPoller again = new VerdictPoller(source, producer, "aegis.verdicts", cursor, Duration.ofMillis(100));
        assertEquals(2, again.cursor());
    }

    @Test
    void aFailedProduceDoesNotAdvanceTheCursor() throws Exception {
        Path cursor = Files.createTempDirectory("poller").resolve("verdict.cursor");
        MockProducer<String, String> producer = new MockProducer<>(false, new StringSerializer(), new StringSerializer());
        VerdictPoller.Source source = (after, limit) -> Json.parseVerdicts(FEED);
        VerdictPoller poller = new VerdictPoller(source, producer, "aegis.verdicts", cursor, Duration.ofMillis(100));
        Thread t = new Thread(() -> {
            try {
                poller.pollOnce();
            } catch (IOException expected) {
                // the broker said no
            }
        });
        t.start();
        Thread.sleep(200);
        producer.errorNext(new RuntimeException("broker unavailable"));
        t.join(2_000);
        assertEquals(0, poller.cursor(), "the cursor stays put, so the verdict is re-sent next poll");
        assertTrue(Files.notExists(cursor));
    }
}
