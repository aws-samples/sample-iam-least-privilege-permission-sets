// In-memory token storage for Cognito (implements the Web Storage interface).
//
// Security: by default amazon-cognito-identity-js persists tokens (id/access/refresh) in
// localStorage, where they survive page reloads and are readable by any script (XSS exfiltration
// risk). Storing them only in memory means tokens live for the lifetime of the tab/page and are
// cleared on refresh or tab close — reducing token theft exposure. The trade-off is that a refresh
// requires re-authentication, which is acceptable for this tool.
class InMemoryStorage implements Storage {
  private store: Record<string, string> = {};

  get length(): number {
    return Object.keys(this.store).length;
  }

  clear(): void {
    this.store = {};
  }

  getItem(key: string): string | null {
    return Object.prototype.hasOwnProperty.call(this.store, key) ? this.store[key] : null;
  }

  key(index: number): string | null {
    return Object.keys(this.store)[index] ?? null;
  }

  removeItem(key: string): void {
    delete this.store[key];
  }

  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }
}

// Module-scoped singleton — one in-memory store shared by the Cognito user pool.
export const memStorage = new InMemoryStorage();
