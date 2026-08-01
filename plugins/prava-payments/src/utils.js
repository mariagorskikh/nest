/**
 * Utility functions for Prava Payments Plugin
 */

/**
 * Convert dollars to cents
 * @param {number} dollars - Amount in dollars
 * @returns {number} Amount in cents
 */
function dollarsToCents(dollars) {
  return Math.round(dollars * 100);
}

/**
 * Convert cents to dollars
 * @param {number} cents - Amount in cents
 * @returns {number} Amount in dollars
 */
function centsToDollars(cents) {
  return (cents / 100).toFixed(2);
}

/**
 * Format currency for display
 * @param {number} cents - Amount in cents
 * @param {string} currency - Currency code (USD, EUR, etc.)
 * @returns {string} Formatted currency string
 */
function formatCurrency(cents, currency = 'USD') {
  const dollars = cents / 100;
  const formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency
  });
  return formatter.format(dollars);
}

/**
 * Validate email address
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid email
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate card token
 * @param {string} token - Token to validate
 * @returns {boolean} True if valid token format
 */
function isValidCardToken(token) {
  return typeof token === 'string' && token.startsWith('tok_') && token.length >= 10;
}

/**
 * Generate unique transaction ID
 * @returns {string} Unique transaction ID
 */
function generateTransactionId() {
  return `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Handle API errors gracefully
 * @param {Error} error - Error object
 * @returns {Object} Formatted error object
 */
function formatError(error) {
  return {
    success: false,
    error: error.message || 'Unknown error',
    code: error.code || 'UNKNOWN_ERROR',
    timestamp: new Date().toISOString()
  };
}

/**
 * Retry logic for API calls
 * @param {Function} fn - Function to retry
 * @param {number} retries - Number of retries
 * @param {number} delay - Delay between retries (ms)
 * @returns {Promise} Result of function
 */
async function retryWithBackoff(fn, retries = 3, delay = 1000) {
  try {
    return await fn();
  } catch (error) {
    if (retries <= 0) {
      throw error;
    }
    await new Promise(resolve => setTimeout(resolve, delay));
    return retryWithBackoff(fn, retries - 1, delay * 2);
  }
}

/**
 * Log transaction details
 * @param {Object} transaction - Transaction object
 * @param {string} action - Action performed
 */
function logTransaction(transaction, action) {
  console.log(`[${new Date().toISOString()}] ${action}:`, JSON.stringify(transaction, null, 2));
}

module.exports = {
  dollarsToCents,
  centsToDollars,
  formatCurrency,
  isValidEmail,
  isValidCardToken,
  generateTransactionId,
  formatError,
  retryWithBackoff,
  logTransaction
};