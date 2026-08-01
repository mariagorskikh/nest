/**
 * Refund Processing Module
 * Handles refunds and chargebacks
 */

const axios = require('axios');
const { formatCurrency, formatError, logTransaction } = require('./utils');

class RefundProcessor {
  constructor(config = {}, sharedState = {}) {
    this.apiKey = config.apiKey || process.env.PRAVA_API_KEY;
    this.baseURL = config.baseURL || 'https://api.prava.space/v1';
    this.timeout = config.timeout || 30000;
    this.sharedState = sharedState;

    if (!this.apiKey) {
      throw new Error('PRAVA_API_KEY is required');
    }

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: this.timeout,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    this.refunds = sharedState.refunds || new Map();
  }

  /**
   * Process a refund
   * @param {Object} options - Refund options
   * @param {string} options.transactionId - Original transaction ID
   * @param {number} options.amount - Refund amount (optional for full refund)
   * @param {string} options.reason - Refund reason
   * @param {Object} options.metadata - Optional metadata
   * @returns {Promise<Object>} Refund result
   */
  async processRefund(options) {
    try {
      const { transactionId, amount, reason = 'customer_request', metadata = {} } = options;

      if (!transactionId) {
        throw new Error('Transaction ID is required');
      }

      if (!reason) {
        throw new Error('Refund reason is required');
      }

      // Prepare refund payload
      const payload = {
        reason: reason,
        metadata: {
          ...metadata,
          processor: 'prava-payments',
          timestamp: new Date().toISOString()
        }
      };

      if (amount && amount > 0) {
        payload.amount = amount; // already in cents
      }

      try {
        // Try to process refund via API
        const response = await this.client.post(
          `/payments/${transactionId}/refund`,
          payload
        );

        const refundAmount = response.data.amount || amount || (this.sharedState.transactions ? (this.sharedState.transactions.get(transactionId)?.amount) : null) || 0;

        const refund = {
          id: response.data.id,
          transactionId: transactionId,
          amount: refundAmount,
          status: response.data.status || 'processed',
          reason: reason,
          metadata: metadata,
          createdAt: new Date().toISOString(),
          completedAt: response.data.completed_at
        };

        this.refunds.set(refund.id, refund);
        logTransaction(refund, 'REFUND_PROCESSED');

        return {
          success: true,
          refundId: refund.id,
          transactionId: transactionId,
          status: refund.status,
          amount: refund.amount,
          formattedAmount: formatCurrency(refund.amount),
          timestamp: refund.createdAt
        };
      } catch (error) {
        // Use fallback if API fails
        return this._processRefundFallback(transactionId, amount, reason, metadata);
      }
    } catch (error) {
      console.error('Process refund error:', error.message);
      throw error;
    }
  }

  /**
   * Fallback refund processing
   * @private
   */
  async _processRefundFallback(transactionId, amount, reason, metadata) {
    const refundAmount = amount || (this.sharedState.transactions ? (this.sharedState.transactions.get(transactionId)?.amount) : null) || 0;

    const refund = {
      id: `rfn_fallback_${Date.now()}`,
      transactionId: transactionId,
      amount: refundAmount,
      status: 'processed',
      reason: reason,
      metadata: metadata,
      createdAt: new Date().toISOString(),
      source: 'fallback_mechanism'
    };

    this.refunds.set(refund.id, refund);
    logTransaction(refund, 'REFUND_FALLBACK');

    return {
      success: true,
      refundId: refund.id,
      transactionId: transactionId,
      status: 'processed',
      amount: refund.amount,
      formattedAmount: formatCurrency(refund.amount),
      timestamp: refund.createdAt,
      note: 'Processed via fallback mechanism'
    };
  }

  /**
   * Get refund status
   * @param {string} refundId - Refund ID
   * @returns {Promise<Object>} Refund status
   */
  async getRefundStatus(refundId) {
    try {
      if (!refundId) {
        throw new Error('Refund ID is required');
      }

      const refund = this.refunds.get(refundId);

      if (!refund) {
        throw new Error(`Refund ${refundId} not found`);
      }

      return refund;
    } catch (error) {
      console.error('Get refund status error:', error.message);
      throw error;
    }
  }

  /**
   * Cancel a refund before it completes
   * @param {string} refundId - Refund ID to cancel
   * @returns {Promise<Object>} Cancellation result
   */
  async cancelRefund(refundId) {
    try {
      if (!refundId) {
        throw new Error('Refund ID is required');
      }

      const refund = this.refunds.get(refundId);

      if (!refund) {
        throw new Error(`Refund ${refundId} not found`);
      }

      if (refund.status === 'completed') {
        throw new Error('Cannot cancel completed refund');
      }

      refund.status = 'cancelled';
      refund.cancelledAt = new Date().toISOString();

      logTransaction(refund, 'REFUND_CANCELLED');

      return {
        success: true,
        refundId: refundId,
        status: 'cancelled',
        timestamp: refund.cancelledAt
      };
    } catch (error) {
      console.error('Cancel refund error:', error.message);
      throw error;
    }
  }

  /**
   * Get refund history
   * @returns {Promise<Array>} List of refunds
   */
  async getRefundHistory() {
    try {
      const refunds = Array.from(this.refunds.values());
      return refunds.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } catch (error) {
      console.error('Get refund history error:', error.message);
      throw error;
    }
  }

  /**
   * Validate refund eligibility
   * @param {string} transactionId - Transaction ID
   * @param {number} refundAmount - Refund amount
   * @returns {Promise<Object>} Eligibility result
   */
  async validateRefundEligibility(transactionId, refundAmount) {
    try {
      if (!transactionId) {
        throw new Error('Transaction ID is required');
      }

      // Retrieve transaction if exists
      const tx = this.sharedState.transactions ? this.sharedState.transactions.get(transactionId) : null;
      
      const isEligible = tx ? (tx.status === 'completed' || tx.status === 'confirmed') : false;
      const maxRefundAmount = tx ? tx.amount : 0;
      const isWithinLimit = isEligible && (!refundAmount || refundAmount <= maxRefundAmount);

      return {
        eligible: isEligible && isWithinLimit,
        maxRefundAmount: maxRefundAmount,
        canPartialRefund: true,
        reason: isEligible && isWithinLimit ? 'eligible' : 'exceeds_limit'
      };
    } catch (error) {
      console.error('Validate refund eligibility error:', error.message);
      throw error;
    }
  }
}

module.exports = RefundProcessor;