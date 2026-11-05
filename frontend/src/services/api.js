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

export async function fetchSherlockSites() {
  const response = await fetch('/api/sherlock/sites', {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Error al obtener catálogo de plataformas SOCMINT');
  }
  return response.json();
}

/**
 * Escucha el stream SSE de Sherlock para descubrimiento en tiempo real.
 * Retorna una función de cancelación (AbortController.abort).
 */
export function startSherlockStream(username, category, { onInit, onProgress, onComplete, onError }) {
  const controller = new AbortController();
  const token = getAuthToken();
  const catParam = category && category !== 'Todos' ? `&category=${encodeURIComponent(category)}` : '';
  const tokenParam = token ? `&token=${encodeURIComponent(token)}` : '';
  const url = `/api/sherlock/stream/${encodeURIComponent(username)}?${catParam}${tokenParam}`;

  (async () => {
    try {
      const response = await fetch(url, {
        headers: getAuthHeaders({ Accept: 'text/event-stream' }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.detail || `Error HTTP ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data: ')) {
            try {
              const data = JSON.parse(trimmed.slice(6));
              if (data.event === 'init' && onInit) onInit(data);
              else if (data.event === 'progress' && onProgress) onProgress(data);
              else if (data.event === 'complete' && onComplete) onComplete(data);
              else if (data.event === 'error' && onError) onError(new Error(data.message));
            } catch {
              // Ignore malformed chunk
            }
          }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError' && onError) {
        onError(err);
      }
    }
  })();

  return () => controller.abort();
}

export async function fetchPhoneOsint(phoneNumber) {
  const response = await fetch(`/api/osint/phone/${encodeURIComponent(phoneNumber)}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to analyze phone number (${response.status})`);
  }
  return response.json();
}

export async function fetchEmailOsint(emailAddress) {
  const response = await fetch(`/api/osint/email/${encodeURIComponent(emailAddress)}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to analyze email address (${response.status})`);
  }
  return response.json();
}

export async function fetchBrandProtection(domain) {
  const response = await fetch(`/api/brand-protection?domain=${encodeURIComponent(domain)}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to audit brand protection (${response.status})`);
  }
  return response.json();
}


