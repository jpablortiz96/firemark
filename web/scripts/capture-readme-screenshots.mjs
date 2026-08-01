/**
 * Capture real FIREMARK production screenshots for the repository README.
 *
 * Public GET navigation only. This script never sends an admin bearer, a
 * delivery bearer, a provider key or any credential, never submits a form that
 * would mutate state, and never records URLs with query strings, cookies or
 * headers.
 *
 * Usage:
 *   npm run capture:readme -- --origin https://firemark-web.vercel.app
 *   FIREMARK_PUBLIC_SITE_URL=https://... npm run capture:readme
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");
const OUTPUT_DIR = path.join(REPO_ROOT, "docs", "assets", "screenshots");
const MANIFEST = path.join(OUTPUT_DIR, "manifest.json");

/** Public certificate identifiers already published in the safe reports. */
const GEMINI_CERT = "firemark-cert-977dce1a6b5b7add352854900ddac911";

const DESKTOP = { width: 1440, height: 1000 };
const MOBILE = { width: 390, height: 844 };

/** Every target is a public route. None of them mutate server state. */
const TARGETS = [
  { file: "landing-desktop.webp", route: "/", viewport: DESKTOP, fullPage: false },
  { file: "landing-mobile.webp", route: "/", viewport: MOBILE, fullPage: false },
  { file: "verify.webp", route: "/verify", viewport: DESKTOP, fullPage: false },
  {
    file: "certificate-gemini.webp",
    route: `/certificate/${GEMINI_CERT}`,
    viewport: DESKTOP,
    fullPage: true,
  },
];

function resolveOrigin() {
  const flag = process.argv.indexOf("--origin");
  const raw =
    (flag !== -1 ? process.argv[flag + 1] : undefined) ??
    process.env.FIREMARK_PUBLIC_SITE_URL ??
    process.env.NEXT_PUBLIC_FIREMARK_SITE_URL;
  if (!raw) {
    console.error("PUBLIC_SITE_URL_UNAVAILABLE");
    console.error("Pass --origin https://<public-site> or set FIREMARK_PUBLIC_SITE_URL.");
    process.exit(2);
  }
  const parsed = new URL(raw);
  if (parsed.protocol !== "https:") throw new Error("The public origin must use HTTPS.");
  if (parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error("The public origin must not carry a query, fragment or credentials.");
  }
  return parsed.origin;
}

/** Reject a blank or single-colour capture before it reaches the README. */
async function isMeaningful(page) {
  return page.evaluate(() => document.body.innerText.trim().length > 200);
}

async function capture(browser, origin, target) {
  const context = await browser.newContext({
    viewport: target.viewport,
    deviceScaleFactor: 2,
    reducedMotion: "reduce",
    colorScheme: "dark",
  });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(1);
  });

  const response = await page.goto(`${origin}${target.route}`, {
    waitUntil: "networkidle",
    timeout: 60_000,
  });
  const status = response?.status() ?? 0;
  if (status >= 400) throw new Error(`${target.route} responded ${status}`);

  await page.evaluate(() => document.fonts.ready);
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}
              *{caret-color:transparent!important}`,
  });
  await page.waitForTimeout(600);

  if (!(await isMeaningful(page))) throw new Error(`${target.route} rendered no readable content`);
  if (await page.locator("text=/404|not found/i").first().isVisible().catch(() => false)) {
    throw new Error(`${target.route} rendered an error page`);
  }

  const buffer = await page.screenshot({
    type: "png",
    fullPage: target.fullPage,
    animations: "disabled",
  });
  await context.close();

  // Re-encode to WebP through the sharp build Next.js already pins.
  const { default: sharp } = await import("sharp");
  const webp = await sharp(buffer).webp({ quality: 86, effort: 5 }).toBuffer();
  const destination = path.join(OUTPUT_DIR, target.file);
  await writeFile(destination, webp);
  const meta = await sharp(webp).metadata();

  return {
    filename: target.file,
    route: target.route,
    viewport: `${target.viewport.width}x${target.viewport.height}`,
    rendered: `${meta.width}x${meta.height}`,
    http_status: status,
    captured_at: new Date().toISOString(),
    sha256: createHash("sha256").update(webp).digest("hex"),
    byte_size: webp.length,
    console_errors: consoleErrors.length,
  };
}

async function main() {
  const origin = resolveOrigin();
  console.log(`public origin: ${origin}`);
  await mkdir(OUTPUT_DIR, { recursive: true });

  const browser = await chromium.launch();
  const entries = [];
  try {
    for (const target of TARGETS) {
      try {
        const entry = await capture(browser, origin, target);
        entries.push(entry);
        console.log(`PASS ${target.file} (${entry.rendered}, ${entry.byte_size} bytes)`);
      } catch (error) {
        // Omit rather than fabricate: a missing route simply produces no asset.
        console.warn(`SKIP ${target.file}: ${error.message}`);
      }
    }
  } finally {
    await browser.close();
  }

  if (entries.length === 0) {
    console.error("No screenshot was captured.");
    process.exit(1);
  }
  await writeFile(
    MANIFEST,
    `${JSON.stringify({ schema_version: "firemark.screenshot-manifest.v1", origin, screenshots: entries }, null, 2)}\n`,
  );
  console.log(`manifest: ${path.relative(REPO_ROOT, MANIFEST)}`);
}

await main();
