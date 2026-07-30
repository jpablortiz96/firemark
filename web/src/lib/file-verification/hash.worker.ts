self.onmessage = async (event: MessageEvent<ArrayBuffer>) => {
  try {
    const digest = await crypto.subtle.digest("SHA-256", event.data);
    self.postMessage({ digest }, { transfer: [digest] });
  } catch {
    self.postMessage({ error: "HASH_UNAVAILABLE" });
  }
};

export {};
