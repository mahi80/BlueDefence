package com.bluedefence.aegis.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class AegisSinkTest {

    @Test
    void batchesAsNdjsonPerPath() {
        List<String> bodies = new ArrayList<>();
        List<String> paths = new ArrayList<>();
        AegisSink sink = new AegisSink((path, body) -> {
            paths.add(path);
            bodies.add(new String(body));
            return 200;
        }, 2, Duration.ofHours(1), 100);
        sink.offer("/ingest/netops?feed=syslog", "a");
        sink.offer("/ingest/alerts", "{\"id\":\"x\"}");
        sink.offer("/ingest/netops?feed=syslog", "b");
        sink.offer("/ingest/netops?feed=syslog", "c");
        sink.flush();
        assertEquals(3, paths.size());
        assertEquals("a\nb\n", bodies.get(0));                       // batchLines = 2
        assertEquals("c\n", bodies.get(1));
        assertEquals("{\"id\":\"x\"}\n", bodies.get(2));
        assertEquals(4, sink.linesSent.get());
    }

    @Test
    void retriesTheSameBatchOn503UntilAccepted() {
        AtomicInteger calls = new AtomicInteger();
        List<String> accepted = new ArrayList<>();
        AegisSink sink = new AegisSink((path, body) -> {
            if (calls.incrementAndGet() < 3) return 503;             // AEGIS queue full twice
            accepted.add(new String(body));
            return 202;
        }, 10, Duration.ofHours(1), 100);
        sink.offer("/ingest/netops?feed=syslog", "line-1");
        sink.flush();
        assertEquals(3, calls.get());
        assertEquals(List.of("line-1\n"), accepted, "the identical batch is what finally lands");
        assertEquals(2, sink.retries.get());
        assertEquals(0, sink.linesDropped.get());
    }

    @Test
    void dropsOn4xxOtherThan429() {
        AegisSink sink = new AegisSink((path, body) -> 401, 10, Duration.ofHours(1), 100);
        sink.offer("/ingest/alerts", "x");
        sink.flush();
        assertEquals(1, sink.linesDropped.get());
        assertEquals(0, sink.retries.get());
    }

    @Test
    void offerBlocksWhenTheBufferIsFullAndResumesAfterFlush() throws Exception {
        AegisSink sink = new AegisSink((path, body) -> 200, 100, Duration.ofHours(1), 3);
        sink.offer("/p", "1");
        sink.offer("/p", "2");
        sink.offer("/p", "3");
        Thread t = new Thread(() -> sink.offer("/p", "4"));
        t.start();
        Thread.sleep(150);
        assertTrue(t.isAlive(), "the fourth offer waits — that wait is the backpressure the Streams thread feels");
        sink.flush();
        t.join(2_000);
        assertTrue(!t.isAlive());
        assertEquals(1, sink.buffered());
        assertTrue(sink.blockedMs.get() >= 100);
    }
}
