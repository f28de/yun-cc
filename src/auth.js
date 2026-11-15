import { promises as fsp } from 'node:fs';
import { PATHS } from './config.js';
import { randomToken, safeEqual } from './util.js';

/**
 * Two-step, token-invisible bootstrap (security officer's C4 fix):
 *  1. GET / navigation  -> HttpOnly __bt ticket, Path=/__bootstrap, 5s
 *  2. POST /__bootstrap -> server validates ticket + Sec-Fetch + one-shot state,
 *     clears the ticket, emits a session-level HttpOnly cookie.
 * Neither token ever enters a URL, the DOM, JS, a command line, or a log.
 *
 * The session token is MEMORY-ONLY. Earlier builds wrote it in plaintext to
 * PATHS.session even though nothing ever read it back. We now remove that
 * legacy artifact on construction so an old install cannot leave it behind.
 */
export function createSessionStore({
  exchangeTtlMs = 5000,
  requireSecFetch = true,
} = {}) {
  void fsp.unlink(PATHS.session).catch(() => {});
  let token = randomToken(32);          // 32B CSPRNG
  let ticket = randomToken(32);         // 32B CSPRNG
  let ticketIssued = false;
  let ticketIssuedAt = 0;
  let firstNavAt = 0;                   // total window starts at FIRST navigation
  let reissueCount = 0;
  const TOTAL_WINDOW_MS = 30000;        // hard cap; NOT renewed per re-issue
  const MAX_REISSUE = 3;
  let bootstrapConsumed = false;        // authoritative server state, NOT cookie Max-Age
  let sessionLive = false;
  let failedAttempts = 0;
  let throttleUntil = 0;

  const navHeadersOk = (req) => !requireSecFetch || (
    req.headers['sec-fetch-dest'] === 'document'
    && req.headers['sec-fetch-mode'] === 'navigate'
    && ['none', 'same-origin'].includes(String(req.headers['sec-fetch-site'] || ''))
  );

  const sessionCookie = () => `fcc_session=${token}; Path=/; HttpOnly; SameSite=Strict`;
  const clearSessionCookie = () => 'fcc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';
  const clearTicketCookie = () => '__bt=; Path=/__bootstrap; HttpOnly; SameSite=Strict; Max-Age=0';

  return {
    get token() { return token; },
    get bootstrapConsumed() { return bootstrapConsumed; },
    get sessionLive() { return sessionLive; },
    get failedAttempts() { return failedAttempts; },

    /** Called once, on the initial document navigation. */
    ticketForNavigation(req) {
      if (bootstrapConsumed || !navHeadersOk(req)) return null;
      const now = Date.now();
      if (!ticketIssued) {
        firstNavAt = now;
      } else if (now - firstNavAt > TOTAL_WINDOW_MS || reissueCount >= MAX_REISSUE) {
        return null; // total window exhausted: user must restart the app
      } else if (now - ticketIssuedAt <= exchangeTtlMs) {
        return null; // a live ticket must never be handed out twice
      } else {
        reissueCount += 1;
      }
      // Every re-issue immediately invalidates the previous ticket.
      ticket = randomToken(32);
      ticketIssued = true;
      ticketIssuedAt = now;
      return `__bt=${ticket}; Path=/__bootstrap; HttpOnly; SameSite=Strict; Max-Age=5`;
    },

    async consumeTicket(req) {
      if (bootstrapConsumed || !ticketIssued) return { ok: false, reason: 'bootstrap_closed' };
      const now = Date.now();
      if (now - firstNavAt > TOTAL_WINDOW_MS) return { ok: false, reason: 'total_window_exceeded' };
      if (now - ticketIssuedAt > exchangeTtlMs) return { ok: false, reason: 'ticket_expired' };
      if (requireSecFetch && String(req.headers['sec-fetch-site'] || '') !== 'same-origin') {
        return { ok: false, reason: 'sec_fetch_rejected' };
      }
      const cookies = this.parseCookie(req.headers.cookie);
      if (!cookies.__bt || !safeEqual(cookies.__bt, ticket)) {
        return { ok: false, reason: 'ticket_invalid' };
      }
      bootstrapConsumed = true;
      sessionLive = true;
      ticket = '';
      return { ok: true, cookies: [clearTicketCookie(), sessionCookie()] };
    },

    noteFailedAttempt() {
      failedAttempts += 1;
      if (failedAttempts >= 10) throttleUntil = Date.now() + 30000;
      return failedAttempts;
    },
    isThrottled() { return Date.now() < throttleUntil; },

    clearCookieHeader: clearSessionCookie,

    parseCookie(header) {
      const out = {};
      for (const part of String(header || '').split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
      return out;
    },

    /** WebUI session only. The AI relay uses a SEPARATE local API key. */
    isValid(req) {
      if (!sessionLive || this.isThrottled()) return false;
      const cookie = this.parseCookie(req.headers.cookie).fcc_session;
      return Boolean(cookie && safeEqual(cookie, token));
    },

    expire() {
      sessionLive = false;
      bootstrapConsumed = true;
      token = '';
      ticket = '';
    },

    async destroy() {
      this.expire();
      await fsp.unlink(PATHS.session).catch(() => {});
    },
  };
}
