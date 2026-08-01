require('dotenv').config();
const QuoteGenerator = require('./src/quote');
const PaymentProcessor = require('./src/payment');
const RefundProcessor = require('./src/refund');
const PaymentVerifier = require('./src/verify');

class PravaPayments {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.PRAVA_API_KEY;
    this.publicKey = options.publicKey || process.env.PRAVA_PUBLIC_KEY;
    this.baseURL = options.baseURL || 'https://api.prava.space/v1';

    if (!this.apiKey) {
      throw new Error('PRAVA_API_KEY is required');
    }

    const config = {
      apiKey: this.apiKey,
      publicKey: this.publicKey,
      baseURL: this.baseURL,
      ...options
    };

    // Shared in-memory state to link operations in sandbox/fallback mode
    this.sharedState = {
      transactions: new Map(),
      quotes: new Map(),
      refunds: new Map(),
      verifications: new Map()
    };

    // Initialize submodule processors
    this.quoteGenerator = new QuoteGenerator(config, this.sharedState);
    this.paymentProcessor = new PaymentProcessor(config, this.sharedState);
    this.refundProcessor = new RefundProcessor(config, this.sharedState);
    this.paymentVerifier = new PaymentVerifier(config, this.sharedState);
  }

  /**
   * Generate a payment quote
   * @param {Object} options - Quote options
   * @param {number} options.amount - Amount in cents
   * @param {string} options.currency - ISO 4217 currency code
   * @param {string} options.description - Transaction description
   * @returns {Promise<Object>} Quote object
   */
  async getQuote(options) {
    return this.quoteGenerator.generateQuote(options);
  }

  /**
   * Process a payment
   * @param {Object} options - Payment options
   * @param {string} options.cardToken - Prava card token
   * @param {number} options.amount - Amount in cents
   * @param {string} options.description - Transaction description
   * @param {Object} options.metadata - Optional metadata
   * @returns {Promise<Object>} Payment result
   */
  async processPayment(options) {
    return this.paymentProcessor.processPayment(options);
  }

  /**
   * Verify a payment status
   * @param {string} transactionId - Transaction ID to verify
   * @returns {Promise<Object>} Payment status
   */
  async verifyPayment(transactionId) {
    return this.paymentVerifier.verifyPayment(transactionId);
  }

  /**
   * Refund a payment
   * @param {string} transactionId - Transaction to refund
   * @param {number} amount - Optional partial refund amount in cents
   * @returns {Promise<Object>} Refund result
   */
  async refundPayment(transactionId, amount = null) {
    return this.refundProcessor.processRefund({ transactionId, amount });
  }
}

// Export both PravaPayments and the alias PravPayments for backward compatibility
const PravPayments = PravaPayments;
module.exports = PravaPayments;
module.exports.PravaPayments = PravaPayments;
module.exports.PravPayments = PravPayments;