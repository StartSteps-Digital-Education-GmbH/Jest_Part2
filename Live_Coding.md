# Live Code

### Step 1: Initial Setup

1. **Install Dependencies**  
   Run the following command to install Jest, Supertest, and TypeScript typings:

   ```bash
   npm i --save-dev jest @types/jest ts-jest supertest
   ```

2. **Configure Jest**  
   Add the following configuration to your `package.json`:

   ```json
   "jest": {
     "preset": "ts-jest",
     "testEnvironment": "node"
   }
   ```

3. **Add Test Script**  
   In the `scripts` section of your `package.json`, add:

   ```json
   "test": "jest"
   ```

### Step 2: Create Test Files

Create a directory for your tests, e.g., `__tests__`, and add the following test files.

#### 1. **Broken Access Control Tests**

**File: `brokenAccessControl.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app

describe('Broken Access Control Tests', () => {
  
  // Test Unauthorized Access
  it('should return a 403 status code when attempting to access a protected endpoint without credentials', async () => {
    await request(app)
      .get('/protected-endpoint') // Protected endpoint
      .expect(403); // Expect Forbidden status
  });

  // Test Vertical Access
  it('should return a 401 status code when attempting to perform an admin action being a regular user', async () => {
    const regularUserToken = 'yourRegularUserToken'; // Replace with actual token
    await request(app)
      .post('/admin/action') // Admin action endpoint
      .set('Authorization', `Bearer ${regularUserToken}`)
      .send({ data: 'someData' })
      .expect(401); // Expect Unauthorized status
  });

  // Test Horizontal Access
  it('should return a 401 status code when attempting to access another user\'s client', async () => {
    const userAToken = 'userAToken'; // Replace with actual token
    await request(app)
      .get('/clients/B') // Attempt to access user B's client
      .set('Authorization', `Bearer ${userAToken}`)
      .expect(401); // Expect Unauthorized status
  });
});
```

#### 2. **Cryptographic Failures Tests**

**File: `cryptographicFailures.spec.ts`**

```typescript
import { encryptWithKey, decryptWithKey } from '../src/crypto'; // Adjust the path to your crypto functions

describe('Cryptographic Failures Tests', () => {
  
  // Test key management
  it('should fail when decrypting with incorrect key', () => {
    const data = 'Sensitive information';
    const keyA = 'correctKey'; // Replace with actual key generation
    const keyB = 'incorrectKey'; // Incorrect key
    const encrypted = encryptWithKey(data, keyA); // Encrypt data

    const decryptedCorrect = decryptWithKey(encrypted, keyA); // Decrypt with correct key
    const decryptedIncorrect = decryptWithKey(encrypted, keyB); // Decrypt with incorrect key

    expect(decryptedCorrect).not.toBeNull(); // Expect successful decryption
    expect(decryptedIncorrect).toBeNull(); // Expect failed decryption
  });
});
```

#### 3. **Injection Tests**

**File: `injection.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app

describe('Injection Tests', () => {
  
  // SQL Injection Test
  it('should return 400 for SQL injection attempt in query params', async () => {
    const response = await request(app)
      .get(`/products?id=' OR 1=1 --`) // Malicious SQL injection
      .send();
    
    expect(response.status).toBe(400); // Expect Bad Request
    expect(response.body.message).toBe('invalid input syntax for integer'); // Expect specific error message
  });

  // XSS Test
  it('should sanitize user input to prevent XSS attacks', async () => {
    const newUser = {
      username: 'username',
      email: 'user@example.com',
      password: 'password',
      profile: 'User profile <script>alert("XSS vulnerability");</script>', // Malicious input
    };
    
    const response = await request(app)
      .post('/users') // User creation endpoint
      .send(newUser);
    
    expect(response.status).toBe(201); // Expect Created status
    expect(response.body.profile).not.toMatch(/<script>/i); // Expect <script> tag to be sanitized
  });
});
```

#### 4. **Insecure Design Tests**

**File: `insecureDesign.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app

describe('Insecure Design Tests', () => {
  
  // Test Unprotected Sensitive Data
  it('should not return the user password when fetching the user', async () => {
    const response = await request(app)
      .get('/user/1') // Fetch user endpoint
      .expect(200); // Expect OK status
    
    expect(response.body.data.password).not.toBeDefined(); // Password should not be included
  });

  // Testing Insecure Password
  it('should enforce strong password requirements', async () => {
    const response = await request(app)
      .post('/user') // User creation endpoint
      .send({
        username: 'username',
        password: 'weakpassword' // Weak password
      })
      .expect(422); // Expect Unprocessable Entity status
    
    expect(response.body.message).toBe('password is not strong enough'); // Expect specific error message
  });
});
```

#### 5. **Security Misconfiguration Tests**

**File: `securityMisconfiguration.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app

describe('Security Misconfiguration Tests', () => {
  
  // Security Headers Test
  it('should include security headers', async () => {
    const response = await request(app)
      .get('/endpoint') // Endpoint to check security headers
      .expect(200); // Expect OK status
    
    expect(response.headers['Content-Security-Policy']).toBeDefined(); // Check for CSP header
    expect(response.headers['X-Frame-Options']).toBeDefined(); // Check for X-Frame-Options header
    expect(response.headers['X-Frame-Options']).toBe('deny'); // Expect deny option
  });
});
```

### Step 3: Run Your Tests

To run your tests, execute the following command in your terminal:

```bash
npm run test
```

### Conclusion

This example provides a structured approach to testing API vulnerabilities using Jest. Each test case is designed to validate specific security aspects of your application, helping to ensure that it is robust against common vulnerabilities.
