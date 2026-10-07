/**
 * @system runtime-auth-flow
 * @status handwritten
 */
import type { MountContext } from "@teamscala/os/runtime-contracts/mount-context";
import { getCookieDomain } from "@teamscala/db/registry/cookie-domain";
import { getSession } from "@teamscala/auth/get-session";
import { registerAuthFactory } from "@teamscala/auth-factory/auth-registry";
import { createAuth } from "@teamscala/auth-factory/auth-factory";
import { normalizeError } from "@teamscala/os/errors/adapter-error-normalizer";
import {
	handleOAuthCallback,
	handleOAuthConnect,
	parseState,
} from "@teamscala/runtime-auth-oauth-connect/oauth-connect-flow";
import {
	handleTelegramStatus,
	type TelegramFlowDeps,
	telegramConnectData,
	telegramConnectQrImage,
	telegramPhoneStepData,
	telegramCodeStepData,
	telegramPasswordStepData,
	TELEGRAM_CONNECT_COOKIE,
} from "@teamscala/runtime-auth-telegram-connect/telegram-flow";
import {
	handleWhatsAppStatus,
	whatsappConnectData,
	whatsappConnectQrImage,
	type WhatsAppFlowDeps,
} from "@teamscala/runtime-auth-whatsapp-connect/whatsapp-flow";
import { whatsappRequestPairingCode } from "@teamscala/runtime-auth-whatsapp-connect/whatsapp-gowa-steps";
import {
	authoriseOrgMembership,
	isSafeCallbackUrl,
	readConnectCookie,
	requireOrg,
} from "@teamscala/runtime-org-authz/mount-org-auth";
import { findProviderDef, resolveCreds } from "@teamscala/runtime-auth-oauth-connect/mount-provider-credentials";
import { onOAuthReady, onTelegramReady, onWhatsAppReady } from "@teamscala/runtime-connect-persistence/mount-connect-persistence";

let _authWired = false;
/** Wire the BetterAuth factory once on this process so getSession() can resolve
 *  .scala.business session cookies. scala-oauth-gateway-v3 is kind:backend with
 *  auth:null, so service-boot's attachAuthGate does NOT run here — we register
 *  the same factory the auth-gate registers elsewhere (one-auth-instance-builder). */
function wireAuth(): void {
	if (_authWired) return;
	registerAuthFactory(createAuth);
	_authWired = true;
}

const telegramDeps: TelegramFlowDeps = { onReady: onTelegramReady };

const whatsappDeps: WhatsAppFlowDeps = { onReady: onWhatsAppReady };

export function mount(ctx: MountContext): void {
	wireAuth();

	// --- Telegram (TDLib multi-step) — every handler requires a valid session;
	//     organisationId comes from the session, never the query/form ---
	// The QR step as JSON, for the portal to render (same shape as
	// whatsapp-connect-data). organisationId is session-derived, never from query.
	ctx.registerHandler("telegram-connect-data", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		return telegramConnectData(auth.orgId);
	});
	// The QR as image bytes for an <img src>. Mints the per-connection accountId
	// and returns it as a gateway-scoped cookie (see telegramConnectQrImage) so
	// the page never has to carry it — which is what keeps it out of the cached
	// SSR loader graph.
	ctx.registerHandler("telegram-connect-qr-image", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		return telegramConnectQrImage(auth.orgId);
	});
	// JSON multi-step phone login, for the portal to drive. telegram-forms.ts
	// stays until a portal UI consumes these — its step handlers RETURN forms, so
	// it is a working login flow, not dead display code.
	const stepBody = async (req: Request) => {
		const ct = req.headers.get("content-type") ?? "";
		if (ct.includes("application/json")) return (await req.json().catch(() => ({}))) as Record<string, string>;
		const form = await req.formData().catch(() => null);
		if (!form) return {} as Record<string, string>;
		return Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));
	};
	ctx.registerHandler("telegram-phone-step-data", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const b = await stepBody(req);
		return telegramPhoneStepData(auth.orgId, b.phoneNumber ?? "", b.accountId ?? readConnectCookie(req, TELEGRAM_CONNECT_COOKIE), telegramDeps, b.returnTo ?? "", b.successUrl ?? "");
	});
	ctx.registerHandler("telegram-code-step-data", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const b = await stepBody(req);
		return telegramCodeStepData(auth.orgId, b.code ?? "", b.phoneNumber ?? "", b.accountId ?? readConnectCookie(req, TELEGRAM_CONNECT_COOKIE), telegramDeps, b.returnTo ?? "", b.successUrl ?? "");
	});
	ctx.registerHandler("telegram-password-step-data", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const b = await stepBody(req);
		return telegramPasswordStepData(auth.orgId, b.password ?? "", b.phoneNumber ?? "", b.accountId ?? readConnectCookie(req, TELEGRAM_CONNECT_COOKIE), telegramDeps, b.returnTo ?? "", b.successUrl ?? "");
	});
	ctx.registerHandler("telegram-connect-status", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		// Prefer the explicit param (the legacy hand-rolled page passes it); fall
		// back to the cookie the image endpoint set, which is the only place the
		// id exists for the primitives-composed page.
		const fromQuery = url.searchParams.get("accountId") ?? "";
		const accountId = fromQuery || readConnectCookie(req, TELEGRAM_CONNECT_COOKIE);
		return handleTelegramStatus(accountId, telegramDeps);
	});

	// --- WhatsApp (GOWA QR) — every handler requires a valid session; accountId is
	//     the messaging_bots.id the portal passes; organisationId is session-derived ---
	// The connect flow as JSON, for the portal to render (the gateway is
	// kind:'backend' — no page-server, so UI cannot live here). Same authz as the
	// HTML page: organisationId is session-derived, never read from the query.
	ctx.registerHandler("whatsapp-connect-data", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		return whatsappConnectData({
			organisationId: auth.orgId,
			accountId: url.searchParams.get("accountId") ?? "",
			callbackUrl: url.searchParams.get("callbackUrl") ?? "",
			userId: auth.userId,
			accountType: url.searchParams.get("accountType") ?? undefined,
		});
	});
	// The QR as image bytes for an <img src>. Auth happens at IMAGE-FETCH time
	// (the .scala.business session cookie rides the browser's request), which is
	// what keeps the per-user QR out of the cached SSR loader graph.
	ctx.registerHandler("whatsapp-connect-qr-image", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		return whatsappConnectQrImage({
			organisationId: auth.orgId,
			accountId: url.searchParams.get("accountId") ?? "",
			callbackUrl: "",
			userId: auth.userId,
			accountType: url.searchParams.get("accountType") ?? undefined,
		});
	});
	ctx.registerHandler("whatsapp-connect-status", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		return handleWhatsAppStatus(
			url.searchParams.get("accountId") ?? "",
			whatsappDeps,
			{
				userId: auth.userId,
				accountType: url.searchParams.get("accountType") ?? undefined,
				organisationId: auth.orgId,
			},
		);
	});

	ctx.registerHandler("whatsapp-connect-code", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		const phone = url.searchParams.get("phone") ?? "";
		if (!phone) return Response.json({ error: "missing phone" }, { status: 400 });
		const result = await whatsappRequestPairingCode(phone);
		if (!result.ok || !result.code) {
			return Response.json({ error: result.error ?? "could not generate a pairing code" }, { status: 502 });
		}
		return Response.json({ code: result.code });
	});

	// --- Generic OAuth (config-driven; one pair for every oauth-provider-definitions entry) ---
	ctx.registerHandler("oauth-connect", async (req: Request) => {
		const auth = await requireOrg(req);
		if (!auth.ok) return auth.res;
		const url = new URL(req.url);
		const provider = url.searchParams.get("provider") ?? "";
		const def = await findProviderDef(provider);
		if (!def) return new Response(`Unknown oauth provider: ${provider}`, { status: 400 });
		const callbackUrl = url.searchParams.get("callbackUrl") ?? "";
		const cookieDomain = await getCookieDomain();
		if (!isSafeCallbackUrl(callbackUrl, cookieDomain)) {
			return new Response(`callbackUrl must be an https://*${cookieDomain} URL`, {
				status: 400,
			});
		}
		let creds: { clientId: string; clientSecret: string };
		try {
			creds = await resolveCreds(def);
		} catch (error) {
			// normalizeError, NOT String(error): a structured rejection stringifies
			// to "[object Object]" — measured as a literal 15-byte response body on
			// the live gateway — which tells the reader nothing. The canonical
			// normalizer unwraps message/nested-error and applies the standard HTTP
			// rules (adapter-errors-use-shared-normalizer).
			return new Response(normalizeError([], error).message || "credential resolution failed", {
				status: 500,
			});
		}
		// organisationId is the session's active org — embedded into the SIGNED
		// state, never read from the query. The callback verifies the signature
		// AND that the state's org matches the caller's session org.
		return handleOAuthConnect(def, auth.orgId, callbackUrl, { clientId: creds.clientId });
	});
	ctx.registerHandler("oauth-callback", async (req: Request) => {
		const session = await getSession(req.headers);
		if (!session?.user) {
			return Response.json({ error: "unauthorized" }, { status: 401 });
		}
		const url = new URL(req.url);
		const code = url.searchParams.get("code") ?? "";
		const state = url.searchParams.get("state") ?? "";
		const parsed = parseState(state);
		if (!parsed) return new Response("Invalid state", { status: 400 });
		// The OAuth provider's callback carries code+state ONLY — no organisationId
		// query param — so the org comes from the SIGNED state this server minted at
		// /oauth/connect under the caller's org (not from requireOrg, which reads the
		// query). The signature proves the state wasn't forged; the shared membership
		// gate proves the caller may act on that org.
		const denied = await authoriseOrgMembership(session.user, parsed.organisationId);
		if (denied) return denied;
		const def = await findProviderDef(parsed.provider);
		if (!def) return new Response(`Unknown oauth provider: ${parsed.provider}`, { status: 400 });
		let creds: { clientId: string; clientSecret: string };
		try {
			creds = await resolveCreds(def);
		} catch (error) {
			// normalizeError, NOT String(error): a structured rejection stringifies
			// to "[object Object]" — measured as a literal 15-byte response body on
			// the live gateway — which tells the reader nothing. The canonical
			// normalizer unwraps message/nested-error and applies the standard HTTP
			// rules (adapter-errors-use-shared-normalizer).
			return new Response(normalizeError([], error).message || "credential resolution failed", {
				status: 500,
			});
		}
		return handleOAuthCallback(def, code, state, creds, { onReady: onOAuthReady });
	});
}
