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
        sink.flush();                       // drains, which wakes the waiting offer; flush may send "4" too
        t.join(2_000);
        assertTrue(!t.isAlive());
        sink.flush();
        assertEquals(0, sink.buffered());
        assertEquals(4, sink.linesSent.get(), "nothing was dropped while the producer waited");
        assertTrue(sink.blockedMs.get() >= 100);
    }

    @Test
    void closeDeliversEverythingBufferedBeforeReturning() throws Exception {
        // K1: close() used to flip running=false and the flusher's send loop returned before its first attempt,
        // so a healthy AEGIS still lost the tail of the buffer (offsets already committed). Now every batch is
        // attempted and the buffer is empty when close() returns.
        AtomicInteger posts = new AtomicInteger();
        AegisSink sink = new AegisSink((path, body) -> {
            posts.incrementAndGet();
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                throw new java.io.IOException(e);
            }
            return 200;
        }, 50, Duration.ofHours(1), 10_000).start();
        for (int i = 0; i < 2_000; i++) sink.offer("/ingest/netops?feed=syslog", "line-" + i);
        sink.close(Duration.ofSeconds(30));
        assertEquals(2_000, sink.linesSent.get(), "nothing buffered may be lost on shutdown");
        assertEquals(0, sink.linesDropped.get());
        assertEquals(0, sink.buffered());
    }

    @Test
    void closeAgainstDeadAegisCountsWhatItAbandons() throws Exception {
        AegisSink sink = new AegisSink((path, body) -> 503, 10, Duration.ofHours(1), 100).start();
        for (int i = 0; i < 5; i++) sink.offer("/ingest/alerts", "{\"id\":\"" + i + "\"}");
        sink.close(Duration.ofSeconds(1));
        assertEquals(5, sink.linesDropped.get(), "abandoned lines are counted, never silently gone");
        assertEquals(0, sink.linesSent.get());
    }
}
