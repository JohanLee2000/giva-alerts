// Giva -> Slack relay (Netlify Function)
// Verifies Giva's signature, skips staff activity, and threads updates per ticket.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const TOLERANCE_SECONDS = 5 * 60; // reject requests older than 5 minutes

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const body = await req.text();
  const id = req.headers.get("webhook-id");
  const timestamp = req.headers.get("webhook-timestamp");
  const signature = req.headers.get("webhook-signature");

  if (!verifySignature({ id, timestamp, signature, body })) {
    console.warn("Rejected: invalid signature", { id });
    return new Response("Invalid signature", { status: 401 });
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return new Response("Bad JSON", { status: 400 });
  }

  if (process.env.DEBUG_LOG === "true") console.log("Payload:", body);

  const { event, actor } = payload;
  const ticket = payload.data?.ticket;
  console.log("Event", { event, actor, ticket: ticket?.key ?? ticket?.id ?? null });

  // Test pings carry no ticket data
  if (!ticket?.id) return new Response("OK (no ticket data)");

  const store = getStore("giva-relay");

  // Giva retries reuse the same webhook-id, so skip anything already handled
  const seenKey = `seen/${id}`;
  if (await store.get(seenKey)) return new Response("OK (duplicate)");

  const staffIds = (process.env.STAFF_IDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const isStaff = actor != null && staffIds.includes(String(actor));

  // STAFF_MODE: "skip" (default) ignores staff activity; "thread" posts it in the thread
  if (isStaff && (process.env.STAFF_MODE || "skip") === "skip") {
    await store.set(seenKey, "1");
    return new Response("OK (staff activity skipped)");
  }

  try {
    const threadKey = `thread/${ticket.id}`;
    const threadTs = await store.get(threadKey);
    const name = ticket.key || ticket.id;
    const label = ticket.url ? `<${ticket.url}|${name}>` : name;

    if (!threadTs) {
      // First message for this ticket becomes the thread parent
      const text =
        event === "ticket.created"
          ? `:new: *New ticket* ${label}`
          : `:ticket: *Ticket* ${label}\n${describe(payload)}`;
      const res = await postToSlack({ text });
      await store.set(threadKey, res.ts);
    } else {
      await postToSlack({
        text: describe(payload),
        thread_ts: threadTs,
        // Also show customer activity in the channel if BROADCAST_CUSTOMER=true
        reply_broadcast: !isStaff && process.env.BROADCAST_CUSTOMER === "true",
      });
    }

    await store.set(seenKey, "1");
    return new Response("OK");
  } catch (err) {
    console.error(err);
    // Non-2xx makes Giva retry later
    return new Response("Slack post failed", { status: 500 });
  }
};

export const config = { path: "/api/giva-webhook" };

function describe({ event, data }) {
  const changes =
    Array.isArray(data?.changes) && data.changes.length ? data.changes.join(", ") : null;
  switch (event) {
    case "ticket.created":
      return ":new: Ticket opened";
    case "ticket.updated":
      return `:pencil2: Updated${changes ? `: ${changes}` : ""}`;
    case "ticket.note.added":
      return ":speech_balloon: New note added";
    case "ticket.attachment.added":
      return ":paperclip: Attachment added";
    case "ticket.survey.completed":
      return ":star: Satisfaction survey completed";
    default:
      return `:bell: ${event}`;
  }
}

async function postToSlack(message) {
  const res = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
    },
    body: JSON.stringify({
      channel: process.env.SLACK_CHANNEL_ID,
      unfurl_links: false,
      ...message,
    }),
  });
  const json = await res.json();
  if (!json.ok) throw new Error(`Slack error: ${json.error}`);
  return json;
}

// Standard Webhooks-style check: HMAC-SHA256 over "id.timestamp.body", base64,
// sent as "v1,<signature>" (possibly several, space-separated).
function verifySignature({ id, timestamp, signature, body }) {
  if (process.env.SKIP_SIGNATURE_CHECK === "true") {
    console.warn("WARNING: signature check is OFF. Troubleshooting only.");
    return true;
  }
  const secret = (process.env.GIVA_SIGNING_SECRET || "").trim();
  if (!secret) {
    console.warn("Signature check failed: GIVA_SIGNING_SECRET is not set (redeploy after adding it)");
    return false;
  }
  if (!id || !timestamp || !signature) {
    console.warn("Signature check failed: missing webhook headers", {
      hasId: !!id, hasTimestamp: !!timestamp, hasSignature: !!signature,
    });
    return false;
  }

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > TOLERANCE_SECONDS) {
    console.warn("Signature check failed: timestamp outside 5-minute window", { timestamp, age });
    return false;
  }

  const signed = `${id}.${timestamp}.${body}`;
  const expected = candidateKeys(secret).map((key) =>
    crypto.createHmac("sha256", key).update(signed).digest("base64")
  );
  const provided = signature
    .split(" ")
    .map((part) => part.split(","))
    .filter(([version]) => version === "v1")
    .map(([, sig]) => sig);

  const ok = provided.some((sig) => expected.some((exp) => safeEqual(sig, exp)));
  if (!ok) {
    console.warn("Signature check failed: signature mismatch", {
      signatureFormat: signature.slice(0, 3),
      providedCount: provided.length,
      secretHasWhsecPrefix: secret.startsWith("whsec_"),
      secretLength: secret.length,
    });
  }
  return ok;
}

// Accept the secret either as raw text or as base64 (with or without a "whsec_" prefix)
function candidateKeys(secret) {
  const keys = [Buffer.from(secret, "utf8")];
  const decoded = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  if (decoded.length) keys.push(decoded);
  return keys;
}

function safeEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
