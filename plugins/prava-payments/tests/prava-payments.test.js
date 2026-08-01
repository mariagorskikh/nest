const axios = require('axios');
const PravPayments = require('../index');

// Mock axios client
const mockPost = jest.fn();
const mockGet = jest.fn();

jest.mock('axios', () => {
  return {
    create: jest.fn(() => ({
      post: mockPost,
      get: mockGet
    }))
  };
});

describe('PravPayments', () => {
  let payment;

  beforeEach(() => {
    process.env.PRAVA_API_KEY = 'sk_test_123';
    payment = new PravPayments();

    // Reset mocks before each test
    mockPost.mockReset();
    mockGet.mockReset();

    // Setup default mock behaviors to simulate successful API calls
    mockPost.mockImplementation((url, data) => {
      if (url === '/quotes') {
        return Promise.resolve({
          data: {
            id: 'quote_test_123',
            amount: data.amount,
            currency: data.currency || 'USD',
            expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
          }
        });
      }
      if (url === '/payments') {
        return Promise.resolve({
          data: {
            id: 'txn_test_123',
            status: 'completed',
            amount: data.amount,
            created_at: new Date().toISOString()
          }
        });
      }
      if (url.endsWith('/refund')) {
        return Promise.resolve({
          data: {
            id: 'rfn_test_123',
            status: 'processed',
            amount: data.amount || 1500,
            created_at: new Date().toISOString()
          }
        });
      }
      return Promise.reject(new Error(`Unhandled mock POST to: ${url}`));
    });

    mockGet.mockImplementation((url) => {
      if (url.startsWith('/payments/')) {
        const id = url.split('/').pop();
        return Promise.resolve({
          data: {
            id: id,
            status: 'confirmed',
            amount: 1500,
            currency: 'USD',
            created_at: new Date().toISOString(),
            metadata: {}
          }
        });
      }
      return Promise.reject(new Error(`Unhandled mock GET to: ${url}`));
    });
  });

  describe('initialization', () => {
    test('should initialize with API key', () => {
      expect(payment.apiKey).toBe('sk_test_123');
    });

    test('should throw error without API key', () => {
      delete process.env.PRAVA_API_KEY;
      expect(() => new PravPayments()).toThrow('PRAVA_API_KEY is required');
    });
  });

  describe('getQuote', () => {
    test('should generate a quote', async () => {
      const quote = await payment.getQuote({
        amount: 1500,
        currency: 'USD',
        description: 'Test booking'
      });

      expect(quote).toHaveProperty('total');
      expect(quote).toHaveProperty('currency');
      expect(quote).toHaveProperty('transactionId');
    });

    test('should throw error without amount', async () => {
      await expect(
        payment.getQuote({ currency: 'USD' })
      ).rejects.toThrow();
    });
  });

  describe('processPayment', () => {
    test('should process payment successfully', async () => {
      const result = await payment.processPayment({
        cardToken: 'tok_test_123',
        amount: 1500,
        description: 'Test payment'
      });

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('transactionId');
    });

    test('should throw error without card token', async () => {
      await expect(
        payment.processPayment({ amount: 1500 })
      ).rejects.toThrow();
    });
  });

  describe('verifyPayment', () => {
    test('should verify payment status', async () => {
      const status = await payment.verifyPayment('txn_test_123');

      expect(status).toHaveProperty('status');
      expect(status).toHaveProperty('amount');
      expect(status).toHaveProperty('timestamp');
    });
  });

  describe('refundPayment', () => {
    test('should refund payment', async () => {
      const refund = await payment.refundPayment('txn_test_123');

      expect(refund).toHaveProperty('refundId');
      expect(refund).toHaveProperty('status');
      expect(refund).toHaveProperty('amount');
    });
  });
});