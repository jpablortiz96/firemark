"use client";

import { ChangeEvent, FormEvent, useRef, useState } from "react";

import { VerificationLayers } from "@/components/verification-layers";
import type { LensResult, VerificationProgress } from "@/lib/file-verification/types";
import { verifyLocalAudio } from "@/lib/file-verification/verify-audio";

function formatSize(bytes: number): string {
  return bytes < 1024 * 1024
    ? `${(bytes / 1024).toFixed(1)} KiB`
    : `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function AudioVerifier() {
  const inputRef = useRef<HTMLInputElement>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const [certId, setCertId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<LensResult | null>(null);
  const [progress, setProgress] = useState<VerificationProgress | null>(null);
  const [processing, setProcessing] = useState(false);

  function choose(event: ChangeEvent<HTMLInputElement>) {
    controllerRef.current?.abort();
    setFile(event.target.files?.[0] ?? null);
    setResult(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setProcessing(true);
    setResult(null);
    try {
      setResult(
        await verifyLocalAudio(file, certId, {
          signal: controller.signal,
          onProgress: setProgress,
        }),
      );
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setResult({
          state: "unavailable",
          fileName: file.name,
          fileSize: file.size,
          mediaType: "audio",
          certId: certId.trim(),
          layers: [],
        });
      }
    } finally {
      setProcessing(false);
      setProgress(null);
    }
  }

  return (
    <div className="lens-workspace">
      <form className="lens-input-panel" onSubmit={submit} noValidate>
        <div className="form-heading">
          <span className="step-label">FIREMARK AUDIO</span>
          <h1>Verify AI voice by hash, without uploading it.</h1>
          <p>Select the sealed MP3 and enter its public certificate ID.</p>
        </div>
        <div className="privacy-badge">
          <span aria-hidden="true">●</span> Processed locally — your audio is not uploaded
        </div>
        <label htmlFor="audio-cert-id">Certificate ID <span>Required</span></label>
        <input
          id="audio-cert-id"
          value={certId}
          onChange={(event) => setCertId(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="firemark-cert-…"
          required
        />
        <div
          className="lens-drop-zone"
          role="button"
          tabIndex={0}
          aria-label="Choose a FIREMARK sealed MP3"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") inputRef.current?.click();
          }}
        >
          <span className="lens-drop-icon" aria-hidden="true">♫</span>
          <strong>Choose a sealed MP3</strong>
          <small>MP3 only · maximum 50 MiB</small>
          <input
            ref={inputRef}
            className="visually-hidden"
            type="file"
            accept="audio/mpeg,.mp3"
            aria-label="Choose MP3 file"
            onChange={choose}
          />
        </div>
        {file && (
          <div className="lens-file-row">
            <div><strong>{file.name}</strong><small>{formatSize(file.size)}</small></div>
            <button type="button" onClick={() => { setFile(null); setResult(null); }}>
              Reset
            </button>
          </div>
        )}
        <button className="button button-primary submit-button" type="submit" disabled={!file || processing}>
          {processing ? "Hashing locally…" : "Run audio Verify Gate"}
        </button>
        {progress && <p className="form-privacy" role="status">Local progress: {progress.percent}%</p>}
        <p className="form-privacy">
          Only cert_id and the browser-calculated SHA-256 reach FIREMARK. Audio has no embedded PNG capsule.
        </p>
      </form>
      <div className="result-region" aria-live="polite" aria-busy={processing}>
        {result ? (
          <VerificationLayers result={result} />
        ) : (
          <div className="result-empty">
            <div className="empty-shield" aria-hidden="true">FM</div>
            <h2>Audio verification result</h2>
            <p>The embedded-capsule layer will be marked not checked; hash and certificate evidence remain enforced.</p>
          </div>
        )}
      </div>
    </div>
  );
}
