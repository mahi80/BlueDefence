package com.bluedefence.aegis.bridge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The little the bridge needs to know about a Cisco system message: which device sent it, whether
 * it is an interface up/down transition and on which interface. Parsing proper stays in AEGIS
 * ({@code aegis/ingest/netops.py}); this is only enough to key, dedupe and pre-aggregate.
 */
public final class Syslog {

    private Syslog() {}

    /** {@code <189>HOST: ...} / {@code <189>HOST Oct 29 ...} / {@code HOST: ...} — the relay's host field. */
    private static final Pattern HOST = Pattern.compile(
            "^(?:<\\d{1,3}>)?(?:\\d+:\\s+)?(?:\\d{4}\\s+)?(?:[A-Z][a-z]{2}\\s+\\d{1,2}\\s+[\\d:.]+\\s+(?:[A-Z]{3,4}\\s+)?)?"
            + "(?<host>[A-Za-z][A-Za-z0-9_.-]*):?\\s");

    /** {@code %LINK-3-UPDOWN: Interface X, changed state to down} and the NX-OS {@code %ETHPORT-5-IF_DOWN_*: Interface X is down}. */
    private static final Pattern UPDOWN = Pattern.compile(
            "%(?:LINK-3-UPDOWN|LINEPROTO-5-UPDOWN|ETHPORT-5-IF_DOWN_[A-Z_]+|ETHPORT-5-IF_UP):\\s*(?:Line protocol on )?Interface\\s+(?<iface>[A-Za-z]+[0-9][0-9/.:-]*)");

    public static Optional<String> host(String line) {
        if (line == null) return Optional.empty();
        if (line.startsWith("{")) {
            return jsonField(line, "device").or(() -> jsonField(line, "host"));
        }
        Matcher m = HOST.matcher(line);
        if (!m.find()) return Optional.empty();
        String h = m.group("host");
        // a bare "%FACILITY" or a month name is not a host
        if (h.startsWith("%") || h.matches("[A-Z][a-z]{2}")) return Optional.empty();
        return Optional.of(h);
    }

    /** The interface of an up/down transition line, or empty when the line is anything else. */
    public static Optional<String> transitionInterface(String line) {
        if (line == null) return Optional.empty();
        Matcher m = UPDOWN.matcher(line);
        return m.find() ? Optional.of(m.group("iface")) : Optional.empty();
    }

    /** Minimal field read for a flat JSON record: {@code "name": "value"}. Good enough for a key. */
    static Optional<String> jsonField(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"(?<v>[^\"]*)\"").matcher(json);
        return m.find() ? Optional.of(m.group("v")) : Optional.empty();
    }

    public static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A syslog-shaped line AEGIS parses like any other, saying how many transitions the bridge folded. */
    public static String suppressedSummary(String host, String iface, long suppressed, long windowSeconds) {
        return "<189>" + host + ": %AEGIS-5-FLAP_SUPPRESSED: Interface " + iface + ", " + suppressed
                + " further up/down transitions suppressed by the Kafka bridge in " + windowSeconds + " s";
    }
}
