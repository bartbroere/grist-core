/**
 * A self-contained email + password login system.
 *
 * Unlike OIDC, SAML or forward-auth, this provider needs no external identity
 * provider and no mail server: accounts are created directly from a small login
 * screen served by Grist, and the password hashes live in Grist's own home
 * database (the `login_passwords` table). It is intended for small, self-hosted
 * installations that just want a handful of people to be able to register and
 * sign in without standing up extra infrastructure.
 *
 * Enable it by setting:
 *   env GRIST_PASSWORD_LOGIN=true
 *
 * Optional tuning:
 *   env GRIST_PASSWORD_LOGIN_MIN_LENGTH
 *       Minimum password length to accept on registration. Defaults to 8.
 *   env GRIST_PASSWORD_LOGIN_ALLOW_SIGNUP
 *       Set to "false" to disable new registrations (existing users can still
 *       log in). Defaults to true.
 *
 * Security notes:
 *   - Passwords are hashed with scrypt and a per-user random salt, and compared
 *     in constant time. Plain passwords are never stored.
 *   - This is deliberately a "basic" system: there is no email verification,
 *     password reset, rate limiting or account lockout. Put Grist behind HTTPS
 *     and only enable this where that trade-off is acceptable.
 */

import { ApiError } from "app/common/ApiError";
import { normalizeEmail } from "app/common/emails";
import { PASSWORD_PROVIDER_KEY } from "app/common/loginProviders";
import { UserProfile } from "app/common/UserAPI";
import { LoginPassword } from "app/gen-server/entity/LoginPassword";
import { AppSettings } from "app/server/lib/AppSettings";
import { expressWrap } from "app/server/lib/expressWrap";
import { GristLoginMiddleware, GristLoginSystem, GristServer, setUserInSession } from "app/server/lib/GristServer";
import log from "app/server/lib/log";
import { createLoginProviderFactory, NotConfiguredError } from "app/server/lib/loginSystemHelpers";
import { getOrgUrl, optStringParam } from "app/server/lib/requestUtils";

import * as crypto from "crypto";
import { promisify } from "util";

import * as express from "express";

const scrypt = promisify<crypto.BinaryLike, crypto.BinaryLike, number, Buffer>(crypto.scrypt);

// Base path under which the login screen and form handlers live.
const LOGIN_PATH = "/auth/local";
const SCRYPT_KEYLEN = 64;

/**
 * Configuration for the built-in password login system.
 */
export interface PasswordLoginConfig {
  /** Minimum accepted password length when registering. */
  readonly minPasswordLength: number;
  /** Whether new accounts may be registered. */
  readonly allowSignup: boolean;
}

/**
 * Read password login configuration from application settings. Throws
 * NotConfiguredError (so other providers get a chance) unless
 * GRIST_PASSWORD_LOGIN is truthy.
 */
export function readPasswordConfigFromSettings(settings: AppSettings): PasswordLoginConfig {
  const section = settings.section("login").section("system").section(PASSWORD_PROVIDER_KEY);

  const enabled = section.flag("enabled").readBool({
    envVar: "GRIST_PASSWORD_LOGIN",
    defaultValue: false,
  });
  if (!enabled) {
    throw new NotConfiguredError("GRIST_PASSWORD_LOGIN is not set");
  }

  const minPasswordLength = section.flag("minLength").readInt({
    envVar: "GRIST_PASSWORD_LOGIN_MIN_LENGTH",
    defaultValue: 8,
    minValue: 1,
  })!;

  const allowSignup = section.flag("allowSignup").readBool({
    envVar: "GRIST_PASSWORD_LOGIN_ALLOW_SIGNUP",
    defaultValue: true,
  })!;

  return { minPasswordLength, allowSignup };
}

/**
 * Hash a password with scrypt and a fresh random salt, returning a
 * self-describing string of the form "scrypt$<saltHex>$<hashHex>".
 */
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const derived = await scrypt(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("hex")}$${derived.toString("hex")}`;
}

/**
 * Verify a password against a stored hash in constant time. Returns false for
 * any malformed or non-matching hash rather than throwing.
 */
async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  if (salt.length === 0 || expected.length === 0) {
    return false;
  }
  const derived = await scrypt(password, salt, expected.length);
  return crypto.timingSafeEqual(derived, expected);
}

/**
 * Restrict a user-supplied "next" destination to a same-origin path, to avoid
 * being used as an open redirect. Returns a leading-slash path or undefined.
 */
function safeNextPath(next: string | undefined): string | undefined {
  if (!next) { return undefined; }
  // Only accept relative paths (no scheme, no host, no protocol-relative "//").
  if (!next.startsWith("/") || next.startsWith("//")) { return undefined; }
  return next;
}

async function getLoginSystem(settings: AppSettings): Promise<GristLoginSystem> {
  const config = readPasswordConfigFromSettings(settings);

  return {
    async getMiddleware(gristServer: GristServer): Promise<GristLoginMiddleware> {
      // Send users to our own login screen, carrying along where they were
      // trying to go so we can return them there afterwards.
      function loginScreenUrl(req: express.Request, target: URL, signUp: boolean): string {
        const url = new URL(getOrgUrl(req, LOGIN_PATH));
        const next = safeNextPath(target.pathname + target.search);
        if (next) { url.searchParams.set("next", next); }
        if (signUp && config.allowSignup) { url.searchParams.set("signup", "1"); }
        return url.href;
      }

      // Look up the password row for a user id, if any.
      async function getStoredPassword(userId: number): Promise<LoginPassword | null> {
        const dbManager = gristServer.getHomeDBManager();
        return dbManager.connection.manager.findOne(LoginPassword, { where: { userId } });
      }

      return {
        async getLoginRedirectUrl(req: express.Request, target: URL) {
          return loginScreenUrl(req, target, false);
        },
        async getSignUpRedirectUrl(req: express.Request, target: URL) {
          return loginScreenUrl(req, target, true);
        },
        async getLogoutRedirectUrl(req: express.Request, nextUrl: URL) {
          return nextUrl.href;
        },
        async addEndpoints(app: express.Express) {
          // The login screen itself.
          app.get(LOGIN_PATH, expressWrap(async (req, res) => {
            const next = safeNextPath(optStringParam(req.query.next, "next"));
            const signUp = config.allowSignup && optStringParam(req.query.signup, "signup") === "1";
            const error = optStringParam(req.query.error, "error");
            res.status(error ? 400 : 200).send(renderLoginPage({
              next,
              signUp,
              error,
              allowSignup: config.allowSignup,
            }));
          }));

          // Parse the urlencoded form bodies our login screen submits. Grist
          // only installs a JSON body parser globally, so add one here.
          const parseForm = express.urlencoded({ extended: false });

          // Handle a sign-in attempt.
          app.post(`${LOGIN_PATH}/login`, parseForm, expressWrap(async (req, res) => {
            const next = safeNextPath(optStringParam(req.body.next, "next"));
            try {
              const email = normalizeEmail(requireField(req.body.email, "email"));
              const password = requireField(req.body.password, "password");

              const dbManager = gristServer.getHomeDBManager();
              const existing = await dbManager.getExistingUserByLogin(email);
              const stored = existing && await getStoredPassword(existing.id);
              // Always run a verification, even when there is no such user, to
              // avoid leaking which emails are registered via timing.
              const placeholder = "scrypt$00$00";
              const ok = await verifyPassword(password, stored?.passwordHash || placeholder);
              if (!existing || !stored || !ok) {
                throw new ApiError("Incorrect email or password.", 401);
              }

              const profile: UserProfile = { email: existing.loginEmail || email, name: existing.name };
              await setUserInSession(req, gristServer, profile);
              res.redirect(getOrgUrl(req, next || "/"));
            } catch (err) {
              redirectWithError(res, req, { error: err, next, signUp: false });
            }
          }));

          // Handle a registration attempt.
          app.post(`${LOGIN_PATH}/register`, parseForm, expressWrap(async (req, res) => {
            const next = safeNextPath(optStringParam(req.body.next, "next"));
            try {
              if (!config.allowSignup) {
                throw new ApiError("Registration is disabled.", 403);
              }
              const displayEmail = requireField(req.body.email, "email").trim();
              const email = normalizeEmail(displayEmail);
              const name = optStringParam(req.body.name, "name")?.trim() || "";
              const password = requireField(req.body.password, "password");
              const confirm = requireField(req.body.confirm, "confirm");

              if (!isValidEmail(email)) {
                throw new ApiError("Please enter a valid email address.", 400);
              }
              if (password.length < config.minPasswordLength) {
                throw new ApiError(
                  `Password must be at least ${config.minPasswordLength} characters.`, 400);
              }
              if (password !== confirm) {
                throw new ApiError("Passwords do not match.", 400);
              }

              const dbManager = gristServer.getHomeDBManager();
              if (await dbManager.getExistingUserByLogin(email)) {
                throw new ApiError("An account with this email already exists.", 409);
              }

              const profile: UserProfile = { email: displayEmail, name };
              const user = await dbManager.getUserByLoginWithRetry(email, { profile });
              if (!user) {
                throw new ApiError("Could not create account.", 500);
              }
              // New password accounts don't need the first-time survey flow.
              if (user.isFirstTimeUser) {
                user.isFirstTimeUser = false;
                await user.save();
              }

              const passwordHash = await hashPassword(password);
              const entity = LoginPassword.create({ userId: user.id, passwordHash });
              await dbManager.connection.manager.save(entity);

              log.info("PasswordLogin: registered new user %s", email);
              await setUserInSession(req, gristServer, profile);
              res.redirect(getOrgUrl(req, next || "/"));
            } catch (err) {
              redirectWithError(res, req, { error: err, next, signUp: true });
            }
          }));

          return PASSWORD_PROVIDER_KEY;
        },
      };
    },
    async deleteUser(user) {
      // Remove any stored password when the account is deleted. The foreign key
      // is ON DELETE CASCADE too, but the user row may outlive this call.
      await LoginPassword.delete({ userId: user.id });
    },
  };
}

function requireField(value: unknown, name: string): string {
  if (typeof value !== "string" || value === "") {
    throw new ApiError(`Missing ${name}.`, 400);
  }
  return value;
}

function isValidEmail(email: string): boolean {
  // Deliberately permissive: just enough to catch obvious mistakes.
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

/**
 * Redirect back to the login screen, preserving the destination and showing an
 * error message. Falls back to re-throwing for unexpected (non-ApiError) errors.
 */
function redirectWithError(
  res: express.Response,
  req: express.Request,
  options: { error: unknown; next: string | undefined; signUp: boolean },
) {
  const { error, next, signUp } = options;
  const message = error instanceof ApiError ? error.message : "Something went wrong. Please try again.";
  if (!(error instanceof ApiError)) {
    log.error("PasswordLogin: unexpected error: %s", error);
  }
  const url = new URL(getOrgUrl(req, LOGIN_PATH));
  url.searchParams.set("error", message);
  if (next) { url.searchParams.set("next", next); }
  if (signUp) { url.searchParams.set("signup", "1"); }
  res.redirect(url.href);
}

/**
 * Render the (self-contained) login / registration screen.
 */
function renderLoginPage(options: {
  next: string | undefined;
  signUp: boolean;
  error: string | undefined;
  allowSignup: boolean;
}): string {
  const { next, signUp, error, allowSignup } = options;
  const nextField = next ? `<input type="hidden" name="next" value="${escapeHtml(next)}">` : "";
  const errorBox = error ? `<div class="error" role="alert">${escapeHtml(error)}</div>` : "";

  const signInForm = `
    <form method="post" action="${LOGIN_PATH}/login" class="form" id="signin-form">
      <h1>Sign in to Grist</h1>
      ${errorBox}
      <label>Email
        <input type="email" name="email" autocomplete="username" required autofocus>
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      ${nextField}
      <button type="submit">Sign in</button>
      ${allowSignup ? `<p class="switch">No account yet? <a href="#" data-show="signup">Register</a></p>` : ""}
    </form>`;

  const signUpForm = allowSignup ? `
    <form method="post" action="${LOGIN_PATH}/register" class="form" id="signup-form">
      <h1>Create your Grist account</h1>
      ${errorBox}
      <label>Name
        <input type="text" name="name" autocomplete="name">
      </label>
      <label>Email
        <input type="email" name="email" autocomplete="username" required>
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="new-password" required>
      </label>
      <label>Confirm password
        <input type="password" name="confirm" autocomplete="new-password" required>
      </label>
      ${nextField}
      <button type="submit">Register</button>
      <p class="switch">Already have an account? <a href="#" data-show="signin">Sign in</a></p>
    </form>` : "";

  // Which form to show first.
  const showSignup = signUp && allowSignup;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${showSignup ? "Register" : "Sign in"} – Grist</title>
  <style>
    :root { --accent: #16b378; --accent-dark: #009058; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #f7f7f7;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #262633;
    }
    .card {
      background: #fff; width: 100%; max-width: 360px; padding: 32px;
      border-radius: 8px; box-shadow: 0 2px 18px rgba(0,0,0,0.08);
    }
    h1 { font-size: 20px; margin: 0 0 20px; text-align: center; }
    .form { display: none; flex-direction: column; }
    .form.active { display: flex; }
    label { display: flex; flex-direction: column; font-size: 13px; margin-bottom: 14px; gap: 4px; }
    input {
      padding: 9px 10px; font-size: 14px; border: 1px solid #d9d9d9; border-radius: 4px;
    }
    input:focus { outline: none; border-color: var(--accent); }
    button {
      margin-top: 4px; padding: 10px; font-size: 15px; font-weight: 500; color: #fff;
      background: var(--accent); border: none; border-radius: 4px; cursor: pointer;
    }
    button:hover { background: var(--accent-dark); }
    .switch { font-size: 13px; text-align: center; margin: 16px 0 0; }
    .switch a { color: var(--accent-dark); text-decoration: none; }
    .error {
      background: #fdecea; color: #b3261e; border: 1px solid #f5c6c2;
      padding: 9px 12px; border-radius: 4px; font-size: 13px; margin-bottom: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div id="signin" class="${showSignup ? "" : "active"} form-wrap">${signInForm}</div>
    <div id="signup" class="${showSignup ? "active" : ""} form-wrap">${signUpForm}</div>
  </div>
  <script>
    document.addEventListener('click', function(e) {
      var trigger = e.target.closest('[data-show]');
      if (!trigger) { return; }
      e.preventDefault();
      var show = trigger.getAttribute('data-show');
      ['signin', 'signup'].forEach(function(id) {
        var form = document.querySelector('#' + id + ' .form');
        if (form) { form.classList.toggle('active', id === show); }
      });
    });
  </script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export const getPasswordLoginSystem = createLoginProviderFactory(
  PASSWORD_PROVIDER_KEY,
  getLoginSystem,
);
