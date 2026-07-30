"use client";

import { ChangeEvent, DragEvent, KeyboardEvent, useRef, useState } from "react";

import { VerificationLayers } from "@/components/verification-layers";
import type { LensResult, VerificationProgress } from "@/lib/file-verification/types";
import { verifyLocalPng } from "@/lib/file-verification/verify-file";

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

const PHASE_COPY: Record<VerificationProgress["phase"], string> = {
  reading: "Reading selected PNG locally",
  capsule: "Inspecting FIREMARK metadata",
  hashing: "Calculating sealed SHA-256",
  verifying: "Requesting the final Verify Gate decision",
  complete: "Verification complete",
};

export function LensVerifier() {
  const inputRef = useRef<HTMLInputElement>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const operationRef = useRef(0);
  const [selected, setSelected] = useState<{ name: string; size: number } | null>(null);
  const [progress, setProgress] = useState<VerificationProgress | null>(null);
  const [result, setResult] = useState<LensResult | null>(null);
  const [processing, setProcessing] = useState(false);
  const [dragging, setDragging] = useState(false);

  async function processFile(file: File) {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const operation = ++operationRef.current;
    setSelected({ name: file.name, size: file.size });
    setResult(null);
    setProgress({ phase: "reading", percent: 5 });
    setProcessing(true);
    try {
      const next = await verifyLocalPng(file, {
        signal: controller.signal,
        onProgress: (value) => {
          if (operationRef.current === operation) setProgress(value);
        },
      });
      if (operationRef.current === operation && !controller.signal.aborted) setResult(next);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        if (operationRef.current === operation) {
          setResult({ state: "unavailable", fileName: file.name, fileSize: file.size, layers: [] });
        }
      }
    } finally {
      if (operationRef.current === operation) {
        setProcessing(false);
        setProgress(null);
      }
    }
  }

  function reset() {
    controllerRef.current?.abort();
    operationRef.current += 1;
    setSelected(null);
    setProgress(null);
    setResult(null);
    setProcessing(false);
    if (inputRef.current) inputRef.current.value = "";
  }

  function choose(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) void processFile(file);
  }

  function drop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) void processFile(file);
  }

  function openFromKeyboard(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <div className="lens-workspace">
      <div className="lens-input-panel">
        <div className="form-heading">
          <span className="step-label">FIREMARK LENS</span>
          <h1>Verify an AI asset without uploading it.</h1>
          <p>The PNG is parsed and hashed in this browser. Only its certificate ID and hash leave.</p>
        </div>
        <div className="privacy-badge"><span aria-hidden="true">●</span> Processed locally — your image is not uploaded</div>
        <div
          className={`lens-drop-zone${dragging ? " is-dragging" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Choose or drop a FIREMARK sealed PNG"
          onClick={() => inputRef.current?.click()}
          onKeyDown={openFromKeyboard}
          onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={() => setDragging(false)}
          onDrop={drop}
        >
          <span className="lens-drop-icon" aria-hidden="true">◎</span>
          <strong>Drop a sealed PNG here</strong>
          <small>or choose a file · PNG only · maximum 25 MiB</small>
          <input
            ref={inputRef}
            className="visually-hidden"
            type="file"
            accept="image/png,.png"
            aria-label="Choose PNG file"
            onChange={choose}
          />
        </div>
        {selected && (
          <div className="lens-file-row">
            <div><strong>{selected.name}</strong><small>{formatFileSize(selected.size)}</small></div>
            <button type="button" onClick={reset}>Reset</button>
          </div>
        )}
        {processing && progress && (
          <div className="lens-progress" role="status" aria-live="polite">
            <div><span>{PHASE_COPY[progress.phase]}</span><strong>{progress.percent}%</strong></div>
            <progress max="100" value={progress.percent}>{progress.percent}%</progress>
          </div>
        )}
        <p className="form-privacy">No file bytes, local path, EXIF, prompt, or private manifest is transmitted.</p>
      </div>
      <div className="result-region" aria-live="polite" aria-atomic="true" aria-busy={processing}>
        {result ? (
          <VerificationLayers result={result} />
        ) : (
          <div className="result-empty">
            <div className="empty-shield" aria-hidden="true">FM</div>
            <h2>{processing ? "Inspecting local evidence" : "Local verification result"}</h2>
            <p>
              {processing
                ? "The selected bytes remain inside this browser while FIREMARK Lens works."
                : "Choose a sealed PNG to inspect eight independent trust layers."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
