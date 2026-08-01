"use client";

import { ChangeEvent, DragEvent, FormEvent, useEffect, useRef, useState } from "react";

import { VerificationLayers } from "@/components/verification-layers";
import type { LensResult, VerificationProgress } from "@/lib/file-verification/types";
import { MAX_AUDIO_FILE_BYTES } from "@/lib/file-verification/types";
import { isAudioMimeAlias, verifyLocalAudio } from "@/lib/file-verification/verify-audio";

function formatSize(bytes: number): string {
  return bytes < 1024 * 1024
    ? `${(bytes / 1024).toFixed(1)} KiB`
    : `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function AudioVerifier({ initialCertId = "" }: { initialCertId?: string }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const previewRef = useRef<string | null>(null);
  const [certId, setCertId] = useState(initialCertId);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [result, setResult] = useState<LensResult | null>(null);
  const [progress, setProgress] = useState<VerificationProgress | null>(null);
  const [processing, setProcessing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  /** The object URL is local only: revoke the previous one and revoke on unmount. */
  function setLocalPreview(next: File | null) {
    if (previewRef.current) URL.revokeObjectURL(previewRef.current);
    previewRef.current = next ? URL.createObjectURL(next) : null;
    setPreview(previewRef.current);
  }

  useEffect(() => {
    return () => {
      if (previewRef.current) URL.revokeObjectURL(previewRef.current);
      previewRef.current = null;
      controllerRef.current?.abort();
    };
  }, []);

  /** Any change invalidates a prior decision. Never keep a stale success. */
  function select(next: File | null, rejection?: string) {
    controllerRef.current?.abort();
    controllerRef.current = null;
    setResult(null);
    setProgress(null);
    setNotice(rejection ?? null);
    setFile(next);
    setLocalPreview(next);
  }

  function choose(event: ChangeEvent<HTMLInputElement>) {
    select(event.target.files?.[0] ?? null);
  }

  function drop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (!dropped) return;
    if (dropped.type && !isAudioMimeAlias(dropped.type)) {
      select(null, "That file is not an MP3. Audio mode expects an MP3 file.");
      return;
    }
    select(dropped);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setProcessing(true);
    setResult(null);
    setNotice(null);
    try {
      const outcome = await verifyLocalAudio(file, certId, {
        signal: controller.signal,
        onProgress: setProgress,
      });
      // Discard a result the user has already moved past.
      if (controllerRef.current === controller) setResult(outcome);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setResult(null);
        setNotice("Verification is temporarily unavailable. Nothing was uploaded.");
      }
    } finally {
      if (controllerRef.current === controller) {
        setProcessing(false);
        setProgress(null);
      }
    }
  }

  return (
    <div className="lens-workspace">
      <form className="lens-input-panel" onSubmit={submit} noValidate>
        <div className="form-heading">
          <span className="step-label">FIREMARK LENS · AUDIO</span>
          <h1>
            Verify an AI asset
            <br />
            without uploading it.
          </h1>
          <p>
            PNG and MP3 files are processed locally in your browser. The asset bytes never leave
            this device.
          </p>
        </div>
        <div className="privacy-badge">
          <span aria-hidden="true">●</span> Processed locally — your asset is not uploaded
        </div>

        <label htmlFor="audio-cert-id">
          Certificate ID <span>Required</span>
        </label>
        <input
          id="audio-cert-id"
          value={certId}
          onChange={(event) => {
            setCertId(event.target.value);
            setResult(null);
            setNotice(null);
          }}
          autoComplete="off"
          spellCheck={false}
          placeholder="firemark-cert-…"
          required
        />

        <div
          className={`lens-drop-zone${dragging ? " is-dragging" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Choose a FIREMARK sealed MP3"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragEnter={() => setDragging(true)}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={() => setDragging(false)}
          onDrop={drop}
        >
          <span className="lens-drop-icon" aria-hidden="true">
            ♫
          </span>
          <strong>Drop a sealed MP3 here</strong>
          <small>or choose a file · MP3 only · use the certificate ID to verify it locally</small>
          <input
            ref={inputRef}
            className="visually-hidden"
            type="file"
            accept="audio/mpeg,audio/mp3,.mp3"
            aria-label="Choose MP3 file"
            onChange={choose}
          />
        </div>

        {notice && (
          <p className="form-privacy" role="alert">
            {notice}
          </p>
        )}

        {file && (
          <div className="lens-file-row">
            <div>
              <strong>{file.name}</strong>
              <small>{formatSize(file.size)}</small>
            </div>
            <button type="button" onClick={() => select(null)}>
              Reset
            </button>
          </div>
        )}

        {preview && (
          <audio className="lens-audio-preview" controls preload="metadata" src={preview}>
            Your browser cannot play this local preview.
          </audio>
        )}

        <button
          className="button button-primary submit-button"
          type="submit"
          disabled={!file || processing}
        >
          {processing ? "Hashing locally…" : "Verify this MP3 locally"}
        </button>
        {progress && (
          <p className="form-privacy" role="status">
            Local progress: {progress.percent}%
          </p>
        )}
        <p className="form-privacy">
          The selected asset is read and hashed locally. Only its public certificate ID and SHA-256
          are used for verification. Maximum {MAX_AUDIO_FILE_BYTES / (1024 * 1024)} MiB.
        </p>
      </form>

      <div className="result-region" aria-live="polite" aria-busy={processing}>
        {result ? (
          <VerificationLayers result={result} />
        ) : (
          <div className="result-empty">
            <div className="empty-shield" aria-hidden="true">
              FM
            </div>
            <h2>Audio verification result</h2>
            <p>
              MP3 sealing is byte-preserving, so there is no embedded capsule. Verification uses the
              public certificate ID and the SHA-256 this browser calculates.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
