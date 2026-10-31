package com.bluedefence.aegis.bridge;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** The one place Jackson is touched: the verdict feed and the alert-id key of a passthrough alert. */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {}

    /** {@code {"after":..,"next":..,"count":..,"verdicts":[{"seq":..,"prev_hash":..,"chain":{...}}]}} */
    public static List<VerdictPoller.Verdict> parseVerdicts(String body) throws IOException {
        JsonNode root = MAPPER.readTree(body);
        List<VerdictPoller.Verdict> out = new ArrayList<>();
        JsonNode rows = root.path("verdicts");
        if (!rows.isArray()) return out;
        for (JsonNode row : rows) {
            JsonNode chain = row.path("chain");
            String alertId = chain.path("alert_id").asText("");
            if (alertId.isEmpty()) alertId = chain.path("id").asText("unknown");
            out.add(new VerdictPoller.Verdict(row.path("seq").asLong(), row.path("prev_hash").asText(""), alertId,
                    MAPPER.writeValueAsString(chain)));
        }
        return out;
    }

    /** The {@code id} of an already-normalised AEGIS alert, for the record key; empty when it is not one. */
    public static String alertId(String json) {
        try {
            JsonNode n = MAPPER.readTree(json);
            return n.isObject() ? n.path("id").asText("") : "";
        } catch (IOException e) {
            return "";
        }
    }
}
