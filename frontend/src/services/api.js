/**
 * Cliente de comunicación con el backend FastAPI de SniperScope.
 */

const AUTH_TOKEN_KEY = 'sniperscope_auth_token_v3';

export function getAuthToken() {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setAuthToken(token) {
  try {
    if (token) {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

export function clearAuthToken() {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  } catch {
    // Ignore
  }
}

function getAuthHeaders(extra = {}) {
  const token = getAuthToken();
  return {
    ...extra,
    ...(token ? { 'X-SniperScope-Token': token } : {}),
  };
}

export async function loginOperator(username, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || 'Credenciales de operador incorrectas');
  }

  const data = await response.json();
  if (data.token) {
    setAuthToken(data.token);
  }
  return data;
}

export async function verifyAuthSession() {
  const token = getAuthToken();
  if (!token) {
    return { authenticated: false };
  }
  try {
    const response = await fetch('/api/auth/verify', {
      headers: getAuthHeaders(),
    });
    if (response.ok) {
      return await response.json();
    }
    clearAuthToken();
    return { authenticated: false };
  } catch {
    return { authenticated: false };
  }
}

export async function fetchScan(target, refresh = false, mode = 'passive') {
  const url = `/api/scan?target=${encodeURIComponent(target)}&mode=${encodeURIComponent(mode)}${refresh ? '&refresh=true' : ''}`;
  const response = await fetch(url, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const err = new Error(errorData.detail || `Error al escanear el objetivo (${response.status})`);
    err.status = response.status;
    throw err;
  }
  return response.json();
}

export async function checkShodanStatus() {
  try {
    const response = await fetch('/api/shodan-status', {
      headers: getAuthHeaders(),
    });
    if (response.ok) {
      return response.json();
    }
  } catch {
    // Falla de red silenciosa
  }
  return { configured: false, message: 'Backend no disponible' };
}
