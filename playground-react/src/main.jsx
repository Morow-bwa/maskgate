import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const SAMPLE_PROMPT =
  "Draft a short reply to the customer at billing@example.org. Mention that the $1,234.56 invoice is under review and ask them not to share card details in chat.";

function makeId() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function makeConversationId() {
  return `conv_${makeId().replace(/[^A-Za-z0-9_-]/g, "")}`;
}

function initialTrace() {
  return {
    request_id: "READY",
    conversation_id: null,
    detected_entity_types: [],
    detected_entities_count: 0,
    masked_request: null,
    upstream_response: null,
    blocked_entities: [],
    preview_only: false,
    preview_reason: null,
  };
}

function formatJson(value, emptyText) {
  return value ? JSON.stringify(value, null, 2) : emptyText;
}

function extractText(response) {
  return response?.choices?.[0]?.message?.content || response?.error?.message || "No response";
}

async function loadPlaygroundConfig(signal) {
  const response = await fetch("/playground/config", { signal });
  if (!response.ok) throw new Error("config unavailable");
  return response.json();
}

const playgroundConfigRequest = loadPlaygroundConfig();

function useObjectUrl(blob) {
  const [url, setUrl] = useState(null);

  useEffect(() => {
    if (!blob) {
      setUrl(null);
      return undefined;
    }
    const nextUrl = URL.createObjectURL(blob);
    setUrl(nextUrl);
    return () => URL.revokeObjectURL(nextUrl);
  }, [blob]);

  return url;
}

function FileAnonymizer() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState(null);
  const requestInFlightRef = useRef(false);
  const downloadUrl = useObjectUrl(result?.blob || null);

  async function sanitize(event) {
    event.preventDefault();
    if (!file || requestInFlightRef.current) return;
    requestInFlightRef.current = true;
    setStatus("running");
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);
    try {
      const response = await fetch("/v1/privacy/files/anonymize", {
        method: "POST",
        body: formData,
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({}));
        throw new Error(failure?.error?.message || "MaskGate could not sanitize this file");
      }

      const blob = await response.blob();
      const disposition = response.headers.get("content-disposition") || "";
      const filename = disposition.match(/filename="([^"]+)"/)?.[1] || "maskgate-output";
      setResult({
        blob,
        filename,
        redactions: response.headers.get("x-maskgate-redactions") || "0",
        types: response.headers.get("x-maskgate-entity-types") || "none",
      });
      setStatus("complete");
    } catch (fileError) {
      setResult({ error: fileError.message });
      setStatus("error");
    } finally {
      requestInFlightRef.current = false;
    }
  }

  return (
    <details className="file-tool">
      <summary>
        <span><strong>Sanitize a file</strong><small>DOCX, PDF, or image</small></span>
        <span>local processing</span>
      </summary>
      <form className="file-form" onSubmit={sanitize}>
        <div>
          <label htmlFor="privacy-file">Choose a file</label>
          <input
            id="privacy-file"
            type="file"
            accept=".docx,.pdf,.png,.jpg,.jpeg,.webp,.tif,.tiff,.bmp"
            onChange={(event) => {
              setFile(event.target.files?.[0] || null);
              setStatus("idle");
              setResult(null);
            }}
          />
          <p>Text, metadata, links, and detected faces are removed locally. Files are never sent to the LLM provider.</p>
        </div>
        <button className="secondary-button" type="submit" disabled={!file || status === "running"}>
          {status === "running" ? "sanitizing" : "sanitize"}
        </button>
      </form>
      {result?.blob && downloadUrl && (
        <div className="file-result success" role="status">
          <span>{result.redactions} redactions / {result.types}</span>
          <a href={downloadUrl} download={result.filename}>download {result.filename}</a>
        </div>
      )}
      {result?.error && <div className="file-result failure" role="alert">{result.error}</div>}
    </details>
  );
}

function App() {
  const [config, setConfig] = useState({
    provider: "openai",
    model: "gpt-4.1-mini",
    masking_mode: "placeholder",
    conversation_ttl_seconds: 1800,
    provider_ready: false,
  });
  const [draft, setDraft] = useState("");
  const [mode, setMode] = useState("placeholder");
  const [model, setModel] = useState("gpt-4.1-mini");
  const [conversationId, setConversationId] = useState(makeConversationId);
  const [history, setHistory] = useState([]);
  const [trace, setTrace] = useState(initialTrace);
  const [finalText, setFinalText] = useState("");
  const [runState, setRunState] = useState("idle");
  const [connection, setConnection] = useState("connecting");
  const [error, setError] = useState("");
  const promptRef = useRef(null);
  const submitInFlightRef = useRef(false);
  const clearInFlightRef = useRef(false);

  useEffect(() => {
    let active = true;
    playgroundConfigRequest
      .then((data) => {
        if (!active) return;
        setConfig(data);
        setModel(data.model || "gpt-4.1-mini");
        setMode(data.masking_mode || "placeholder");
        setConnection("online");
      })
      .catch((loadError) => {
        if (active && loadError.name !== "AbortError") setConnection("offline");
      });
    return () => {
      active = false;
    };
  }, []);

  function addHistory(role, content) {
    setHistory((current) => [...current.slice(-5), { id: makeId(), role, content }]);
  }

  function resetOutput() {
    setTrace(initialTrace());
    setFinalText("");
    setError("");
    setRunState("idle");
  }

  async function submit(event) {
    event.preventDefault();
    const prompt = draft.trim();
    if (!prompt || runState === "running" || submitInFlightRef.current) return;
    submitInFlightRef.current = true;

    addHistory("user", prompt);
    setDraft("");
    resetOutput();
    setRunState("running");

    try {
      const response = await fetch("/playground/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: model.trim() || "gpt-4.1-mini",
          messages: [{ role: "user", content: prompt }],
          temperature: 0.7,
          masking_mode: mode,
          conversation_id: conversationId,
        }),
      });
      if (!response.ok) {
        const failedEnvelope = await response.json().catch(() => ({}));
        const failedResult = failedEnvelope.response || failedEnvelope;
        setTrace({ ...initialTrace(), ...(failedEnvelope.trace || {}) });
        const message = failedResult?.error?.message || "MaskGate stopped the request";
        setRunState("blocked");
        setError(message);
        addHistory("error", message);
        return;
      }

      const envelope = await response.json();
      const result = envelope.response || envelope;
      const nextTrace = { ...initialTrace(), ...(envelope.trace || {}) };
      setTrace(nextTrace);

      if (
        response.ok &&
        nextTrace.preview_only &&
        nextTrace.preview_reason === "provider_not_configured"
      ) {
        const previewMessage = "Preview only — no provider call was made.";
        setFinalText(previewMessage);
        setRunState("preview");
        addHistory("assistant", previewMessage);
        return;
      }

      if (result.error) {
        const message = result?.error?.message || "MaskGate stopped the request";
        setRunState("blocked");
        setError(message);
        addHistory("error", message);
        return;
      }

      const answer = extractText(result);
      setFinalText(answer);
      setRunState("complete");
      addHistory("assistant", answer);
    } catch {
      const message = "Could not connect to the local MaskGate proxy.";
      setRunState("error");
      setError(message);
      addHistory("error", message);
    } finally {
      submitInFlightRef.current = false;
    }
  }

  async function clearConversation() {
    if (clearInFlightRef.current) return;
    clearInFlightRef.current = true;
    const oldId = conversationId;
    try {
      await fetch(`/playground/api/conversations/${encodeURIComponent(oldId)}`, { method: "DELETE" }).catch(() => {});
      setConversationId(makeConversationId());
      setHistory([]);
      setDraft("");
      resetOutput();
    } finally {
      clearInFlightRef.current = false;
    }
  }

  function loadSample() {
    setDraft(SAMPLE_PROMPT);
    promptRef.current?.focus();
  }

  const providerName = config.provider || "openai";
  const readyLabel = config.provider_ready ? "key configured" : "preview only";
  const statusLabel =
    runState === "running"
      ? "sending"
      : runState === "complete"
        ? "complete"
        : runState === "preview"
          ? "preview"
          : runState === "blocked" || runState === "error"
            ? "stopped"
            : "waiting";

  return (
    <main className="page-shell">
      <header className="page-header">
        <div>
          <div className="wordmark">MASKGATE / PLAYGROUND</div>
          <h1>Inspect every request before it leaves.</h1>
          <p>Original input on the left. The exact masked payload and the returned result on the right.</p>
        </div>
        <div className="header-status">
          <span className={`status-dot ${connection === "offline" ? "offline" : ""}`} />
          <span>{connection === "online" ? "local proxy online" : "local proxy"}</span>
        </div>
      </header>

      <section className="module-grid">
        <article className="module input-module">
          <div className="module-header">
            <div>
              <div className="module-index">01 / INPUT</div>
              <h2>What I send</h2>
            </div>
            <button className="text-button" type="button" onClick={clearConversation} disabled={runState === "running"}>new conversation</button>
          </div>

          <div className="history" aria-live="polite">
            {history.length === 0 ? (
              <div className="history-empty">
                <span>No messages yet.</span>
                <button className="link-button" type="button" onClick={loadSample}>load English example</button>
              </div>
            ) : (
              history.map((item) => (
                <div className={`history-item ${item.role}`} key={item.id}>
                  <span>{item.role === "user" ? "you" : item.role === "assistant" ? "model" : "maskgate"}</span>
                  <p>{item.content}</p>
                </div>
              ))
            )}
          </div>

          <form className="composer" onSubmit={submit}>
            <label htmlFor="prompt">New message</label>
            <textarea
              ref={promptRef}
              id="prompt"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  event.currentTarget.form.requestSubmit();
                }
              }}
              placeholder="Example: reply to billing@example.org"
              rows="5"
            />
            <div className="composer-footer">
              <div className="field-row">
                <label className="select-field"><span>mode</span><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="placeholder">placeholder</option><option value="surrogate">surrogate</option><option value="redact">redact</option></select></label>
                <label className="model-field"><span>model</span><input value={model} onChange={(event) => setModel(event.target.value)} /></label>
              </div>
              <button className="primary-button" type="submit" disabled={runState === "running"}>{runState === "running" ? "processing" : "send request"}</button>
            </div>
          </form>
        </article>

        <article className="module output-module">
          <div className="module-header">
            <div>
              <div className="module-index">02 / OUTPUT</div>
              <h2>What happens next</h2>
            </div>
            <span className={`run-label ${runState}`}>{statusLabel}</span>
          </div>

          <div className="provider-line">
            <span>provider</span><strong>{providerName}</strong><span>status</span><strong className={config.provider_ready ? "ready" : "warning"}>{readyLabel}</strong>
          </div>

          <section className="readout">
            <div className="readout-header"><div><span className="readout-index">A</span><div><h3>Outbound payload</h3><p>Exact request after masking</p></div></div><span className="readout-state">{trace.masked_request ? "ready" : "—"}</span></div>
            <pre>{formatJson(trace.masked_request, "// the masked payload will appear after you send a request")}</pre>
          </section>

          <section className="readout returned-readout">
            <div className="readout-header"><div><span className="readout-index">B</span><div><h3>Returned to the user</h3><p>Provider response after local rehydration</p></div></div><span className="readout-state">{finalText ? "ready" : "—"}</span></div>
            <div className={`final-answer ${finalText ? "filled" : ""}`}>{finalText || "// the model response will appear here"}</div>
          </section>

          <details className="raw-details">
            <summary>Show provider response before rehydration</summary>
            <pre>{formatJson(trace.upstream_response, "// the provider has not returned anything")}</pre>
          </details>

          <div className="module-note">
            <span className="note-mark">i</span>
            <p>Mapping stays in RAM for this conversation and expires after {config.conversation_ttl_seconds || 1800} seconds of inactivity.</p>
          </div>
          {trace.preview_only && trace.preview_reason === "provider_not_configured" && <div className="notice preview-notice">Preview only. No provider key is configured, so nothing was sent upstream.</div>}
          {trace.preview_only && trace.preview_reason !== "provider_not_configured" && <div className="notice warning-notice">Policy blocked this request. The masked preview is local-only and was not sent to the provider.</div>}
          {error && <div className="notice error-notice">{error}</div>}
        </article>
      </section>

      <FileAnonymizer />

      <footer className="page-footer">
        <span>conversation {conversationId.slice(0, 14)}…</span>
        <span>{trace.detected_entities_count || 0} detected signals</span>
        <span>MaskGate · RAM only</span>
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
