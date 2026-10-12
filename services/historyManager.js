const STORAGE_KEY = 'des_vault_history_v1';

/**
 * Loads history items from localStorage.
 */
export function getHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const items = JSON.parse(raw);
    return Array.isArray(items) ? items : [];
  } catch (err) {
    console.warn('Failed to load history:', err);
    return [];
  }
}

/**
 * Saves a new safe history entry. Never saves keys or file contents!
 */
export function addHistoryEntry({
  operation, // 'ENCRYPT' | 'DECRYPT'
  filename,
  fileSize,
  mode = 'CBC',
  hashHex = '',
  status = 'SUCCESS', // 'SUCCESS' | 'FAILED'
  errorReason = ''
}) {
  try {
    const history = getHistory();
    const entry = {
      id: 'h_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      operation,
      filename: filename || 'unknown',
      fileSize: Number(fileSize) || 0,
      mode,
      hashPrefix: hashHex ? hashHex.slice(0, 16) + '...' : '—',
      status,
      errorReason: errorReason ? errorReason.slice(0, 120) : '',
      timestamp: Date.now()
    };

    history.unshift(entry);
    // Keep last 100 items
    if (history.length > 100) {
      history.length = 100;
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    return entry;
  } catch (err) {
    console.warn('Failed to save history entry:', err);
    return null;
  }
}

/**
 * Clears history from localStorage.
 */
export function clearHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Computes dashboard statistics from stored history.
 */
export function getVaultStats() {
  const history = getHistory();
  let encryptedCount = 0;
  let decryptedCount = 0;
  let totalBytesProcessed = 0;
  let lastOperation = null;

  for (const item of history) {
    if (item.status === 'SUCCESS') {
      if (item.operation === 'ENCRYPT') encryptedCount++;
      if (item.operation === 'DECRYPT') decryptedCount++;
      totalBytesProcessed += item.fileSize || 0;
    }
    if (!lastOperation) {
      lastOperation = item;
    }
  }

  return {
    encryptedCount,
    decryptedCount,
    totalBytesProcessed,
    lastOperation
  };
}
