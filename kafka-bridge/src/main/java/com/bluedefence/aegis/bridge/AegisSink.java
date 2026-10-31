package com.bluedefence.aegis.bridge;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Batches lines per AEGIS endpoint and POSTs them as NDJSON with the bearer token.
 *
 * <p>Backpressure is explicit: the buffer is bounded, {@link #offer} blocks when it is full, and
 * a blocked Kafka Streams thread simply stops consuming — the lag shows up on the consumer group,
 * where every bank already monitors it. When AEGIS answers 503 (its own queue is full) or 429, or
 * the connection fails, the same batch is retried with exponential backoff (250 ms → 30 s); nothing
 * is dropped on the floor. A 4xx other than 429 means the batch itself is bad (wrong token, body
 * too large); it is logged and dropped, because retrying it would never succeed.
 */
public class AegisSink implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AegisSink.class);

    /** The HTTP call, separated so tests can fake AEGIS without a socket. */
    public interface Transport {
        int post(String path, byte[] body) throws IOException;
    }

    private final Transport transport;
    private final int batchLines;
    private final long lingerMs;
    private final int maxBuffered;
    private final Map<String, List<String>> buffers = new LinkedHashMap<>();
    private final Object lock = new Object();
    private int buffered = 0;
    private volatile boolean running = true;
    private Thread flusher;

    public final AtomicLong linesSent = new AtomicLong();
    public final AtomicLong batchesSent = new AtomicLong();
    public final AtomicLong retries = new AtomicLong();
    public final AtomicLong linesDropped = new AtomicLong();
    public final AtomicLong blockedMs = new AtomicLong();

    public AegisSink(Transport transport, int batchLines, Duration linger, int maxBuffered) {
        this.transport = transport;
        this.batchLines = batchLines;
        this.lingerMs = Math.max(10, linger.toMillis());
        this.maxBuffered = maxBuffered;
    }

    /** Production transport: {@code java.net.http} with the bearer token. */
    public static Transport httpTransport(String baseUrl, String token) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        return (path, body) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/x-ndjson")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            if (token != null && !token.isBlank()) {
                b.header("Authorization", "Bearer " + token);
            }
            try {
                return client.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        };
    }

    public AegisSink start() {
        flusher = new Thread(this::flushLoop, "aegis-sink-flusher");
        flusher.setDaemon(true);
        flusher.start();
        return this;
    }

    /** Queue one line for {@code path}; blocks while the buffer is full (that is the backpressure). */
    public void offer(String path, String line) {
        if (line == null || line.isBlank()) return;
        long t0 = System.nanoTime();
        synchronized (lock) {
            while (running && buffered >= maxBuffered) {
                try {
                    lock.wait(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            if (!running) return;
            buffers.computeIfAbsent(path, k -> new ArrayList<>()).add(line);
            buffered++;
            if (buffered >= batchLines) lock.notifyAll();
        }
        long waited = (System.nanoTime() - t0) / 1_000_000;
        if (waited > 0) blockedMs.addAndGet(waited);
    }

    public int buffered() {
        synchronized (lock) {
            return buffered;
        }
    }

    /** Send everything buffered now, synchronously. Used at shutdown and by tests. */
    public void flush() {
        while (true) {
            String path;
            List<String> batch;
            synchronized (lock) {
                var it = buffers.entrySet().iterator();
                if (!it.hasNext()) return;
                var e = it.next();
                path = e.getKey();
                List<String> all = e.getValue();
                int n = Math.min(batchLines, all.size());
                batch = new ArrayList<>(all.subList(0, n));
                all.subList(0, n).clear();
                if (all.isEmpty()) it.remove();
                buffered -= n;
                lock.notifyAll();
            }
            send(path, batch);
        }
    }

    private void flushLoop() {
        while (running) {
            synchronized (lock) {
                if (buffered < batchLines) {
                    try {
                        lock.wait(lingerMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            try {
                flush();
            } catch (RuntimeException e) {
                log.error("flush failed: {}", e.toString());
            }
        }
    }

    private void send(String path, List<String> batch) {
        byte[] body = (String.join("\n", batch) + "\n").getBytes(StandardCharsets.UTF_8);
        long backoff = 250;
        int attempt = 0;
        while (running) {
            int status;
            try {
                status = transport.post(path, body);
            } catch (IOException e) {
                status = -1;
                log.warn("POST {} failed ({}); retrying in {} ms", path, e.getMessage(), backoff);
            }
            if (status >= 200 && status < 300) {
                linesSent.addAndGet(batch.size());
                batchesSent.incrementAndGet();
                return;
            }
            if (status >= 400 && status < 500 && status != 429) {
                log.error("POST {} rejected with {}: dropping {} line(s) — check AEGIS_INGEST_TOKEN / body size", path, status, batch.size());
                linesDropped.addAndGet(batch.size());
                return;
            }
            // 503 (AEGIS queue full), 429, other 5xx, connection failure: same batch, later
            retries.incrementAndGet();
            attempt++;
            if (status > 0 && attempt == 1) {
                log.warn("POST {} got {}: AEGIS is applying backpressure, retrying", path, status);
            }
            try {
                Thread.sleep(backoff);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            backoff = Math.min(backoff * 2, 30_000);
        }
    }

    @Override
    public void close() {
        running = false;
        synchronized (lock) {
            lock.notifyAll();
        }
        if (flusher != null) {
            try {
                flusher.join(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        running = true;      // let the final flush send
        flush();
        running = false;
    }
}
