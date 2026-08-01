/**
 * Quote Generation Module
 * Generates payment quotes for transactions
 */

const axios = require('axios');
const { formatCurrency, logTransaction } = require('./utils');

class QuoteGenerator {
  constructor(config = {}, sharedState = {}) {
    this.currency = config.currency || 'USD';
    this.quoteTimeout = config.quoteTimeout || 3600; // 1 hour in seconds
    this.sharedState = sharedState;
    this.apiKey = config.apiKey || process.env.PRAVA_API_KEY;
    this.baseURL = config.baseURL || 'https://api.prava.space/v1';
    this.timeout = config.timeout || 30000;

    if (this.apiKey) {
      this.client = axios.create({
        baseURL: this.baseURL,
        timeout: this.timeout,
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        }
      });
    }

    this.quotes = sharedState.quotes || new Map();
  }

  /**
   * Generate a payment quote
   * @param {Object} options - Quote options
   * @param {number} options.amount - Amount in dollars
   * @param {string} options.currency - Currency code
   * @param {string} options.description - Transaction description
   * @param {Object} options.metadata - Optional metadata
   * @returns {Promise<Object>} Quote object
   */
  async generateQuote(options) {
    try {
      const { amount, currency = this.currency, description, metadata = {} } = options;

      // Validate input
      if (!amount || amount <= 0) {
        throw new Error('Amount must be greater than 0');
      }

      if (!description) {
        throw new Error('Description is required');
      }

      // Try API first if client is configured
      if (this.client) {
        try {
          const response = await this.client.post('/quotes', {
            amount, // already in cents
            currency,
            description,
            metadata
          });

          const quote = {
            id: response.data.id,
            total: response.data.amount,
            amount: response.data.amount,
            currency: response.data.currency,
            transactionId: response.data.id,
            expiresAt: response.data.expires_at,
            status: 'active',
            createdAt: new Date().toISOString(),
            formattedAmount: formatCurrency(response.data.amount, response.data.currency)
          };

          this.quotes.set(quote.id, quote);
          logTransaction(quote, 'QUOTE_GENERATED');
          return quote;
        } catch (error) {
          console.warn('API quote generation failed, falling back to offline sandbox:', error.message);
        }
      }

      // Generate quote ID locally (fallback)
      const quoteId = `quote_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const expiresAt = new Date(Date.now() + this.quoteTimeout * 1000);

      // Create quote object
      const quote = {
        id: quoteId,
        total: amount,
        amount: amount,
        currency: currency,
        transactionId: quoteId,
        description: description,
        metadata: metadata,
        status: 'active',
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        formattedAmount: formatCurrency(amount, currency)
      };

      // Store quote in memory
      this.quotes.set(quoteId, quote);

      // Log quote generation
      logTransaction(quote, 'QUOTE_GENERATED_FALLBACK');

      return quote;
    } catch (error) {
      console.error('Quote generation error:', error.message);
      throw error;
    }
  }

  /**
   * Get a quote by ID
   * @param {string} quoteId - Quote ID
   * @returns {Promise<Object>} Quote object
   */
  async getQuote(quoteId) {
    try {
      if (!quoteId) {
        throw new Error('Quote ID is required');
      }

      const quote = this.quotes.get(quoteId);

      if (!quote) {
        throw new Error(`Quote ${quoteId} not found`);
      }

      // Check if quote expired
      if (new Date(quote.expiresAt) < new Date()) {
        quote.status = 'expired';
      }

      return quote;
    } catch (error) {
      console.error('Get quote error:', error.message);
      throw error;
    }
  }

  /**
   * Calculate fees for a quote
   * @param {number} amount - Amount in dollars
   * @param {string} feeType - Type of fee (processing, merchant, etc.)
   * @returns {Object} Fee breakdown
   */
  async calculateFees(amount, feeType = 'processing') {
    try {
      const feePercentage = {
        processing: 0.029, // 2.9%
        merchant: 0.02,    // 2%
        international: 0.05 // 5%
      };

      const percentage = feePercentage[feeType] || feePercentage.processing;
      const fee = Math.round(amount * percentage);
      const total = amount + fee;

      return {
        subtotal: amount,
        fee: fee,
        total: total,
        feePercentage: `${(percentage * 100).toFixed(2)}%`
      };
    } catch (error) {
      console.error('Calculate fees error:', error.message);
      throw error;
    }
  }

  /**
   * Generate quote for NANDA marketplace
   * @param {Object} booking - Booking object
   * @returns {Promise<Object>} Quote with breakdown
   */
  async generateNandaQuote(booking) {
    try {
      const { flight, hotel, activity, destination, days } = booking;

      const subtotal = flight + hotel + activity;
      const fees = await this.calculateFees(subtotal);

      const quote = await this.generateQuote({
        amount: fees.total,
        description: `NANDA Booking: ${destination} (${days} days)`,
        metadata: {
          bookingType: 'travel',
          destination: destination,
          duration: days,
          items: {
            flight: flight,
            hotel: hotel,
            activity: activity
          }
        }
      });

      return {
        ...quote,
        breakdown: {
          flight: flight,
          hotel: hotel,
          activity: activity,
          subtotal: subtotal,
          fees: fees
        }
      };
    } catch (error) {
      console.error('Generate NANDA quote error:', error.message);
      throw error;
    }
  }
}

module.exports = QuoteGenerator;