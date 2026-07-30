# Production deployment

FIREMARK deploys as two independently configured services:

- Railway builds the repository-root `Dockerfile` and runs the FastAPI factory.
- Vercel builds `web/` as a Next.js project and retains the server-side delivery Route Handler.

Neither build needs credentials in source control or image layers. Application construction and
the Railway health check are zero-network; external clients remain lazy until an authenticated
operation requires them.

## Preflight

Place the deployment inventory in the ignored repository `.env` and run:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\check_production_readiness.py
```

The command prints only a field name and `PRESENT`, `MISSING`, `VALID`, or `INVALID`. It never
prints a configured value. Copy values into Railway and Vercel through their protected environment
variable controls; do not upload `.env` to either platform.

Railway requires these backend variables:

```text
FIREMARK_REPOSITORY_BACKEND
FIREMARK_ADMIN_API_KEY
FIREMARK_DELIVERY_API_KEY
FIREMARK_SIGNING_PRIVATE_KEY_B64
FIREMARK_SIGNING_PUBLIC_KEY_B64
FIREMARK_PUBLIC_BASE_URL
FIREMARK_ALLOWED_ORIGINS
FIREMARK_DELIVERY_TTL_SECONDS
FIREMARK_GENERATION_TIMEOUT_SECONDS
FIREMARK_MAX_GENERATED_IMAGE_BYTES
FIREMARK_VAULT_RETENTION_DAYS
FIREMARK_PRESIGNED_URL_TTL_SECONDS
OPENAI_API_KEY
OPENAI_IMAGE_MODEL
OPENAI_IMAGE_SIZE
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
SUPABASE_SERVICE_ROLE_KEY
B2_ENDPOINT
B2_REGION
B2_ASSETS_BUCKET
B2_ASSETS_KEY_ID
B2_ASSETS_APPLICATION_KEY
B2_VAULT_BUCKET
B2_VAULT_KEY_ID
B2_VAULT_APPLICATION_KEY
```

The two retention/download variables are existing custody requirements and therefore remain part
of a complete runtime. The backend also accepts legacy local names `B2_ASSETS_APP_KEY` and
`B2_VAULT_APP_KEY`; new deployments should use the `APPLICATION_KEY` names above and must not
configure conflicting aliases.

Vercel requires these variables:

```text
NEXT_PUBLIC_FIREMARK_API_BASE_URL
FIREMARK_DELIVERY_API_KEY
FIREMARK_PUBLIC_SITE_URL
```

Only the API base is browser-visible. `FIREMARK_DELIVERY_API_KEY` is server-only and must exactly
match Railway. No credential may use a `NEXT_PUBLIC_` name.

## Deployment order

1. Create the Railway service from this repository with the repository root as its root directory.
2. Add the Railway variables and deploy.
3. Obtain the generated Railway HTTPS domain and verify `GET /healthz` returns HTTP 200.
4. Create the Vercel project with Root Directory `web`, Framework Preset `Next.js`, install command
   `npm ci`, and build command `npm run build`.
5. Set `NEXT_PUBLIC_FIREMARK_API_BASE_URL` to the Railway HTTPS origin, set the server-only delivery
   bearer, and deploy Vercel.
6. Obtain the Vercel HTTPS domain. Set `FIREMARK_PUBLIC_SITE_URL` on Vercel to that origin and
   redeploy the frontend so canonical metadata uses the final origin.
7. Update Railway `FIREMARK_PUBLIC_BASE_URL` to the Vercel HTTPS origin. Existing certificate URLs
   remain compatible through the frontend `/v1/certificates/:certId` redirect.
8. Set Railway `FIREMARK_ALLOWED_ORIGINS` to an exact JSON array containing the Vercel origin, for
   example `["https://firemark.example"]`. Do not use `*` and do not add paths.
9. Redeploy Railway, then run the deployed-stack smoke below.

Do not generate a certificate while `FIREMARK_PUBLIC_BASE_URL` still holds a temporary value.

## Railway backend

Railway uses `railway.toml` with its Dockerfile builder, `/healthz` health check, bounded restart
policy, and deployment draining. The effective command is:

```text
uvicorn api.firemark.app:create_app --factory --host 0.0.0.0 --port ${PORT} --workers 1 --timeout-graceful-shutdown 30 --no-server-header
```

One worker avoids duplicate in-process state and is appropriate for the first hackathon deployment.
The shell wrapper uses `exec`, so Railway termination signals reach Uvicorn and its graceful
shutdown window. The hostname is never hardcoded.

## Vercel frontend

No `web/vercel.json` is needed: Vercel natively detects Next.js and the package already defines the
production build. Keep the project Root Directory at `web`. Dynamic certificate rendering and the
delivery Route Handler remain server-capable; do not export the application as static files.

Next.js config applies `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and a CSP
with `frame-ancestors 'none'`. The CSP allows the inline framework bootstrap required by the
current Next.js application and HTTPS API/media access while blocking plugins and framing.

## Deployed-stack smoke

After both final domains are active, add only these ignored local values to the repository `.env`:

```text
FIREMARK_DEPLOYED_API_BASE_URL=https://<railway-domain>
FIREMARK_DEPLOYED_WEB_BASE_URL=https://<vercel-domain>
```

Review zero-network mode first, then let one owner run:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_deployed_stack.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_deployed_stack.py --live `
  --output-report .artifacts\deployed-stack-report.json --force
```

Live mode reuses `.artifacts/generate-and-seal-report.json` and its existing certificate. It makes
no OpenAI request, creates no object or certificate, performs no registration, and mutates no
certificate. Public verification and authenticated delivery append only their normal audit events.
The short-lived download URL exists only in memory and is excluded from output and the safe report.

## Rollback

1. Stop smoke execution and disable production Generate & Seal access if integrity is uncertain.
2. Roll Vercel back to the last known-good deployment.
3. Roll Railway back to the matching known-good image/configuration.
4. Restore the corresponding Vercel origin in `FIREMARK_PUBLIC_BASE_URL` and the exact JSON CORS
   allowlist, then redeploy Railway.
5. Re-run `/healthz`, public page checks, and the deployed-stack smoke with the existing certificate.

Do not delete or shorten retained B2 evidence, mutate Supabase certificate records, rotate signing
material casually, or create replacement evidence as part of rollback.

## Operational logging and remaining work

Never log `.env`, bearer headers, raw delivery URLs, prompts, private manifests, provider bodies,
OpenAI credentials, Supabase keys, B2 credentials, or signing private material. Log only normalized
safe codes, public IDs, hashes, stage names, and deployed hostnames when needed.

Production deployment is prepared but not performed by this checkpoint. Demo recording and the
hackathon submission remain pending after the owner completes deployment and smoke verification.
