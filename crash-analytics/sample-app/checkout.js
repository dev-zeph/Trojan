/**
 * Pretend business logic for a checkout service.
 *
 * Every function in here is deliberately buggy in a *different* way, so the
 * Trojan Errors tab shows a realistic grouped list instead of five rows of the
 * same TypeError. The bugs are the boring kind that actually reach production:
 * a cache miss that returns undefined, a DB timeout, a webhook that never
 * acknowledges.
 */
'use strict';

class DatabaseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DatabaseError';
  }
}

// A "customer cache". Note what is missing: anyone who is not `cus_1001`.
const CUSTOMER_CACHE = {
  cus_1001: { id: 'cus_1001', tier: 'pro', discountRate: 0.1 },
};

function loadCustomer(customerId) {
  // Cache miss returns undefined instead of throwing. This is the bug.
  return CUSTOMER_CACHE[customerId];
}

function applyDiscount(order) {
  const customer = loadCustomer(order.customerId);
  // TypeError: Cannot read properties of undefined (reading 'discountRate')
  const discounted = order.total * (1 - customer.discountRate);
  return Math.round(discounted * 100) / 100;
}

function completeCheckout(order) {
  const total = applyDiscount(order);
  return { orderId: order.orderId, total, currency: 'USD' };
}

function queryInventoryDb(sku) {
  throw new DatabaseError(
    `connection to inventory-db timed out after 5000ms while reserving sku=${sku}`
  );
}

function reserveInventory(sku) {
  return queryInventoryDb(sku);
}

function settlePayment(orderId) {
  // Resolves nothing, ever. The caller forgets to .catch(), so this becomes an
  // unhandled promise rejection a few ticks later.
  return new Promise((_resolve, reject) => {
    setTimeout(() => {
      reject(new Error(`payment settlement webhook never acknowledged for order ${orderId}`));
    }, 10);
  });
}

function renderCartBadge(cart) {
  // TypeError: Cannot read properties of undefined (reading 'length')
  // Fires once per page render, which is why this one shows up hundreds of
  // times as a single issue rather than as hundreds of issues.
  return `${cart.items.length} items`;
}

function auditPaymentAttempt(context) {
  // Reads a field the audit record never has. The interesting part is not the
  // crash, it is that `context` holds an auth header and a password, and Trojan
  // redacts both before anything is stored.
  return context.payment.card.last4;
}

module.exports = {
  DatabaseError,
  completeCheckout,
  reserveInventory,
  settlePayment,
  renderCartBadge,
  auditPaymentAttempt,
};
