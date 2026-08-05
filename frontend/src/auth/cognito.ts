// ============================================================================
// Cognito authentication (SRP) — amazon-cognito-identity-js.
// The backend Cognito client is SRP-only (ALLOW_USER_SRP_AUTH), so we use SRP login only.
// The ID token is attached to the API Authorization header (client.ts real()).
//
// Tokens are kept in memory only (see inMemoryStorage) — not localStorage — to reduce token-theft
// exposure. Tokens are cleared on refresh/tab close.
//
// env: VITE_COGNITO_USER_POOL_ID, VITE_COGNITO_CLIENT_ID (injected when the web stack is deployed).
// ============================================================================
import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  type CognitoUserSession,
} from "amazon-cognito-identity-js";
import { memStorage } from "./inMemoryStorage";

const USER_POOL_ID = import.meta.env.VITE_COGNITO_USER_POOL_ID ?? "";
const CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID ?? "";

// No pool in mock mode or when env is unset (the login gate is bypassed).
export const cognitoConfigured = Boolean(USER_POOL_ID && CLIENT_ID);

const pool = cognitoConfigured
  ? new CognitoUserPool({ UserPoolId: USER_POOL_ID, ClientId: CLIENT_ID, Storage: memStorage })
  : null;

export function currentUser(): CognitoUser | null {
  return pool?.getCurrentUser() ?? null;
}

/** Current session's ID token (if valid). Attempts refresh on expiry. Returns null if none. */
export function getIdToken(): Promise<string | null> {
  return new Promise((resolve) => {
    const user = currentUser();
    if (!user) return resolve(null);
    user.getSession((err: Error | null, session: CognitoUserSession | null) => {
      if (err || !session || !session.isValid()) return resolve(null);
      resolve(session.getIdToken().getJwtToken());
    });
  });
}

/** SRP login. Resolves with the ID token on success, throws on failure. */
export function signIn(email: string, password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!pool) return reject(new Error("Cognito is not configured"));
    // Pass the in-memory Storage so login tokens are not persisted to localStorage.
    const user = new CognitoUser({ Username: email, Pool: pool, Storage: memStorage });
    const details = new AuthenticationDetails({ Username: email, Password: password });
    user.authenticateUser(details, {
      onSuccess: (session) => resolve(session.getIdToken().getJwtToken()),
      onFailure: (err) => reject(err),
      // A new password required on first login (admin-created account) is not supported here.
      newPasswordRequired: () => reject(new Error("Password reset required (contact your administrator).")),
    });
  });
}

export function signOut(): Promise<void> {
  // Use globalSignOut() to **invalidate the refresh token server-side** (a local signOut alone leaves
  // the refresh token valid, so a stolen token could still be reissued). globalSignOut requires a valid
  // session, so on failure (e.g. expired session) fall back to a local signOut; either way the local
  // tokens are cleared.
  return new Promise((resolve) => {
    const user = currentUser();
    if (!user) return resolve();
    user.getSession((err: Error | null) => {
      if (err) {
        user.signOut();
        return resolve();
      }
      user.globalSignOut({
        onSuccess: () => resolve(),
        onFailure: () => {
          user.signOut(); // still clear the local session even if server invalidation fails
          resolve();
        },
      });
    });
  });
}

export async function isAuthenticated(): Promise<boolean> {
  return (await getIdToken()) !== null;
}
