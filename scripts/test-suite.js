const https = require('https');
const crypto = require('crypto');
const readline = require('readline');

// ===== CONFIGURATION =====
const BASE_URL = 'https://api.geararea.net';
const TIMESTAMP = Date.now();

let testState = {
  seller: { email: `seller_${TIMESTAMP}@test.com`, password: 'TestPass123!', token: null, id: null },
  buyer: { email: `buyer_${TIMESTAMP}@test.com`, password: 'TestPass123!', token: null, id: null },
  products: [],
  orders: [],
};

// ===== UTILITY FUNCTIONS =====

function makeRequest(method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE_URL + path);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, body: parsed, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, body: data, headers: res.headers });
        }
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

function makeMultipartRequest(path, fileBuffer, fieldName, fileName, token) {
  return new Promise((resolve, reject) => {
    const boundary = '----WebKitFormBoundary' + crypto.randomBytes(16).toString('hex');
    const url = new URL(BASE_URL + path);
    
    const part1 = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fieldName}"; filename="${fileName}"\r\n` +
      `Content-Type: image/png\r\n\r\n`
    );
    
    const part3 = Buffer.from(`\r\n--${boundary}--\r\n`);
    const payload = Buffer.concat([part1, fileBuffer, part3]);

    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': payload.length,
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, body: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function getMockImageBuffer() {
  const base64Png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  return Buffer.from(base64Png, 'base64');
}

// ===== TEST LOGGER (closure pattern) =====
function createTestLogger() {
  let passed = 0;
  let failed = 0;

  return {
    test: async (name, fn) => {
      try {
        await fn();
        console.log(`[PASS] ${name}`);
        passed++;
      } catch (err) {
        console.log(`[FAIL] ${name}`);
        console.log(`       Error: ${err.message}`);
        failed++;
      }
    },
    summary: () => {
      console.log(`\n${'='.repeat(60)}`);
      console.log(`Tests Passed: ${passed}`);
      console.log(`Tests Failed: ${failed}`);
      console.log(`Total: ${passed + failed}`);
      console.log(`${'='.repeat(60)}\n`);
    },
  };
}

// ===== ASSERTION HELPERS =====
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertEquals(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

// ===== TEST SUITES (Each returns async function) =====

async function authTests(logger) {
  console.log('\n--- AUTH TESTS ---');

  await logger.test('SIGNUP: Create seller account', async () => {
    const res = await makeRequest('POST', '/signup', testState.seller);
    assertEquals(res.status, 201, 'Status should be 201');
    assert(res.body.status === 'created', 'Should return created status');
  });

  await logger.test('SIGNUP: Create buyer account', async () => {
    const res = await makeRequest('POST', '/signup', testState.buyer);
    assertEquals(res.status, 201, 'Status should be 201');
  });

  await logger.test('SIGNIN: Seller login', async () => {
    const res = await makeRequest('POST', '/signin', testState.seller);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.token, 'Should return token');
    testState.seller.token = res.body.token;
  });

  await logger.test('SIGNIN: Buyer login', async () => {
    const res = await makeRequest('POST', '/signin', testState.buyer);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.token, 'Should return token');
    testState.buyer.token = res.body.token;
  });
}

async function profileTests(logger) {
  console.log('\n--- PROFILE TESTS ---');

  await logger.test('GET /me: Fetch seller profile', async () => {
    const res = await makeRequest('GET', '/me', null, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.id, 'Should have user id');
    assert(res.body.email === testState.seller.email, 'Email should match');
    testState.seller.id = res.body.id;
  });

  await logger.test('GET /me: Fetch buyer profile', async () => {
    const res = await makeRequest('GET', '/me', null, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    testState.buyer.id = res.body.id;
  });

  await logger.test('PUT /me: Update seller profile', async () => {
    const updates = {
      full_name: 'Test Seller',
      bio: 'Selling gear',
      address: '123 Main St',
    };
    const res = await makeRequest('PUT', '/me', updates, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.status === 'updated', 'Should return updated status');
  });

  await logger.test('PUT /me: Update buyer address', async () => {
    const updates = {
      full_name: 'Test Buyer',
      address: '456 Oak Ave',
    };
    const res = await makeRequest('PUT', '/me', updates, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
  });

  await logger.test('GET /me/verified: Check verification status', async () => {
    const res = await makeRequest('GET', '/me/verified', null, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(typeof res.body.verified === 'boolean', 'Should return boolean verified field');
  });
}

async function productTests(logger) {
  console.log('\n--- PRODUCT TESTS ---');

  await logger.test('POST /products: Create first product by seller', async () => {
    const product = {
      title: 'Used Camera',
      description: 'Great condition',
      category: 'electronics',
      brand: 'Canon',
      price: 50000,
      condition: 'good',
      photos: ['photo1.jpg'],
      length_cm: 15,
      width_cm: 10,
      height_cm: 8,
      weight_grams: 500,
    };
    const res = await makeRequest('POST', '/products', product, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.id, 'Should return product id');
    testState.products.push({ id: res.body.id, ...product });
  });

  await logger.test('POST /products: Create second product by seller', async () => {
    const product = {
      title: 'Laptop Stand',
      description: 'Metal stand',
      category: 'accessories',
      price: 15000,
      condition: 'excellent',
      photos: ['stand.jpg'],
    };
    const res = await makeRequest('POST', '/products', product, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    testState.products.push({ id: res.body.id, ...product });
  });

  await logger.test('POST /products: Create product by buyer', async () => {
    const product = {
      title: 'Mechanical Keyboard',
      description: 'RGB switches',
      category: 'electronics',
      price: 25000,
      condition: 'new',
      photos: ['keyboard.jpg'],
    };
    const res = await makeRequest('POST', '/products', product, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    testState.products.push({ id: res.body.id, ...product });
  });

  await logger.test('POST /products: Create extra product for deletion testing', async () => {
    const product = {
      title: 'Headphones',
      description: 'Noise cancelling',
      category: 'electronics',
      price: 35000,
      condition: 'excellent',
      photos: ['headphones.jpg'],
    };
    const res = await makeRequest('POST', '/products', product, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    testState.products.push({ id: res.body.id, ...product });
  });

  await logger.test('POST /products: Create extra product for hard delete testing', async () => {
    const product = {
      title: 'Monitor',
      description: '4K display',
      category: 'electronics',
      price: 75000,
      condition: 'new',
      photos: ['monitor.jpg'],
    };
    const res = await makeRequest('POST', '/products', product, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    testState.products.push({ id: res.body.id, ...product });
  });

  await logger.test('GET /products: List all products', async () => {
    const res = await makeRequest('GET', '/products?page=1&limit=10');
    assertEquals(res.status, 200, 'Status should be 200');
    assert(Array.isArray(res.body), 'Should return array');
    assert(res.body.length > 0, 'Should have products');
  });

  await logger.test('GET /products/{id}: Get product detail', async () => {
    const productId = testState.products[0].id;
    const res = await makeRequest('GET', `/products/${productId}`);
    assertEquals(res.status, 200, 'Status should be 200');
    assertEquals(res.body.id, productId, 'Should return correct product');
  });

  await logger.test('PUT /products/{id}: Update product by owner', async () => {
    const productId = testState.products[0].id;
    const updates = { title: 'Used Camera - Updated', price: 45000 };
    const res = await makeRequest('PUT', `/products/${productId}`, updates, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.status === 'updated', 'Should return updated status');
  });

  await logger.test('PUT /products/{id}: Fail to update as non-owner', async () => {
    const productId = testState.products[0].id;
    const updates = { title: 'Hacked!' };
    const res = await makeRequest('PUT', `/products/${productId}`, updates, testState.buyer.token);
    assertEquals(res.status, 403, 'Status should be 403');
  });

  await logger.test('DELETE /products/{id}: Soft delete product', async () => {
    const productId = testState.products[3].id;
    const res = await makeRequest('DELETE', `/products/${productId}`, null, testState.seller.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.status === 'soft_deleted', 'Should return soft_deleted status');
  });

  await logger.test('GET /products/{id}: Verify soft deleted product not accessible', async () => {
    const productId = testState.products[3].id;
    const res = await makeRequest('GET', `/products/${productId}`);
    assertEquals(res.status, 404, 'Status should be 404');
  });

  await logger.test('DELETE /products/{id}/hard: Hard delete product', async () => {
    const productId = testState.products[4].id;
    const res = await makeRequest('DELETE', `/products/${productId}/hard`, null, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.status === 'hard_deleted', 'Should return hard_deleted status');
  });
}

async function cartTests(logger) {
  console.log('\n--- CART TESTS ---');

  await logger.test('POST /cart: Buyer adds seller product to cart', async () => {
    const productId = testState.products[0].id;
    const res = await makeRequest('POST', '/cart', { product_id: productId }, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.status === 'added', 'Should return added status');
  });

  await logger.test('POST /cart: Add second product to cart', async () => {
    if (testState.products.length < 2) {
      throw new Error('Not enough products');
    }
    const productId = testState.products[1].id;
    const res = await makeRequest('POST', '/cart', { product_id: productId }, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
  });

  await logger.test('GET /cart: List cart items grouped by seller', async () => {
    const res = await makeRequest('GET', '/cart', null, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(Array.isArray(res.body), 'Should return array');
  });
}

async function orderTests(logger) {
  console.log('\n--- ORDER/CHECKOUT TESTS ---');

  await logger.test('POST /checkout: Create order from cart', async () => {
    const res = await makeRequest('POST', '/checkout', { seller_id: testState.seller.id }, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.order_id, 'Should return order_id');
    testState.orders.push({ id: res.body.order_id });
  });

  await logger.test('GET /cart: Verify purchased items removed', async () => {
    const res = await makeRequest('GET', '/cart', null, testState.buyer.token);
    assertEquals(res.status, 200, 'Status should be 200');
  });
}

async function uploadTests(logger) {
  console.log('\n--- MEDIA UPLOAD TESTS ---');

  await logger.test('POST /media/upload: Upload valid PNG', async () => {
    const imgBuffer = getMockImageBuffer();
    const res = await makeMultipartRequest(
      '/media/upload',
      imgBuffer,
      'image',
      'test_image.png',
      testState.seller.token
    );
    assertEquals(res.status, 200, 'Status should be 200');
    assert(res.body.url, 'Should return a URL');
  });

  await logger.test('POST /media/upload: Fail without token', async () => {
    const imgBuffer = getMockImageBuffer();
    const res = await makeMultipartRequest(
      '/media/upload',
      imgBuffer,
      'image',
      'test.png',
      ''
    );
    assertEquals(res.status, 401, 'Should be 401');
  });

  await logger.test('POST /media/upload: Fail with wrong form key', async () => {
    const imgBuffer = getMockImageBuffer();
    const res = await makeMultipartRequest(
      '/media/upload',
      imgBuffer,
      'photo',
      'test.png',
      testState.seller.token
    );
    assertEquals(res.status, 400, 'Should be 400');
  });

  await logger.test('POST /media/upload: Fail with invalid file', async () => {
    const textBuffer = Buffer.from('This is not an image');
    const res = await makeMultipartRequest(
      '/media/upload',
      textBuffer,
      'image',
      'test.txt',
      testState.seller.token
    );
    assertEquals(res.status, 500, 'Should be 500');
  });
}

async function errorTests(logger) {
  console.log('\n--- ERROR/EDGE CASE TESTS ---');

  await logger.test('POST /signin: Fail with wrong password', async () => {
    const res = await makeRequest('POST', '/signin', {
      email: testState.seller.email,
      password: 'WrongPassword',
    });
    assertEquals(res.status, 401, 'Status should be 401');
  });

  await logger.test('GET /me: Fail without token', async () => {
    const res = await makeRequest('GET', '/me');
    assertEquals(res.status, 401, 'Status should be 401');
  });

  await logger.test('GET /me: Fail with invalid token', async () => {
    const res = await makeRequest('GET', '/me', null, 'invalid.token.here');
    assertEquals(res.status, 401, 'Status should be 401');
  });

  await logger.test('GET /products/{id}: Fail with non-existent product', async () => {
    const res = await makeRequest('GET', '/products/99999');
    assertEquals(res.status, 404, 'Status should be 404');
  });
}

// ===== MAIN FLOW =====

function resetTestState() {
  testState = {
    seller: { email: `seller_${Date.now()}@test.com`, password: 'TestPass123!', token: null, id: null },
    buyer: { email: `buyer_${Date.now()}@test.com`, password: 'TestPass123!', token: null, id: null },
    products: [],
    orders: [],
  };
}

async function runFlow(flowName, testFunctions) {
  resetTestState();
  console.log(`\n${'='.repeat(60)}`);
  console.log(`RUNNING FLOW: ${flowName}`);
  console.log(`${'='.repeat(60)}`);
  
  const logger = createTestLogger();
  
  try {
    for (const testFn of testFunctions) {
      await testFn(logger);
    }
    logger.summary();
  } catch (err) {
    console.error(`Fatal error in ${flowName}:`, err.message);
  }
}

// ===== INTERACTIVE CLI =====

function displayMenu() {
  console.log('\n' + '='.repeat(60));
  console.log('API TEST SUITE MENU');
  console.log('='.repeat(60));
  console.log('1. Auth Flow (signup + signin)');
  console.log('2. Profile Flow (get/update profile)');
  console.log('3. Product Flow (CRUD operations)');
  console.log('4. Cart Flow (add/list cart items)');
  console.log('5. Order Flow (checkout + order management)');
  console.log('6. Upload Flow (image upload)');
  console.log('7. Error Cases (edge cases)');
  console.log('8. Full Suite (all tests)');
  console.log('0. Exit');
  console.log('='.repeat(60));
}

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const question = (prompt) => new Promise((resolve) => rl.question(prompt, resolve));

  console.log('API Test Runner Started');

  let running = true;
  while (running) {
    displayMenu();
    const choice = await question('\nSelect a test flow (0-8): ');

    switch (choice) {
      case '1':
        await runFlow('Auth', [authTests]);
        break;
      case '2':
        await runFlow('Profile', [authTests, profileTests]);
        break;
      case '3':
        await runFlow('Product', [authTests, productTests]);
        break;
      case '4':
        await runFlow('Cart', [authTests, productTests, cartTests]);
        break;
      case '5':
        await runFlow('Order', [authTests, productTests, cartTests, orderTests]);
        break;
      case '6':
        await runFlow('Upload', [authTests, uploadTests]);
        break;
      case '7':
        await runFlow('Error Cases', [authTests, errorTests]);
        break;
      case '8':
        await runFlow('Full Suite', [authTests, profileTests, productTests, cartTests, orderTests, uploadTests, errorTests]);
        break;
      case '0':
        console.log('Exiting test suite');
        running = false;
        break;
      default:
        console.log('Invalid selection. Please try again.');
    }

    if (running) {
      await question('\nPress Enter to continue...');
      console.clear();
    }
  }

  rl.close();
}

main().catch(console.error);