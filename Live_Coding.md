# Live Code

Live coding example focused on user login and JWT token handling, including tests for various security vulnerabilities using Jest and Supertest. This example will cover user authentication, token generation, and testing for vulnerabilities related to JWT.

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

#### 1. **User Authentication Tests**

**File: `auth.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app
import { generateToken } from '../src/auth'; // Adjust the path to your token generation function

describe('User Authentication Tests', () => {
  
  // Test Successful Login
  it('should return a JWT token on successful login', async () => {
    const userCredentials = {
      username: 'testuser',
      password: 'strongpassword',
    };

    const response = await request(app)
      .post('/login') // Login endpoint
      .send(userCredentials)
      .expect(200); // Expect OK status

    expect(response.body.token).toBeDefined(); // Expect a token to be returned
  });

  // Test Invalid Credentials
  it('should return 401 for invalid credentials', async () => {
    const userCredentials = {
      username: 'testuser',
      password: 'wrongpassword',
    };

    const response = await request(app)
      .post('/login') // Login endpoint
      .send(userCredentials)
      .expect(401); // Expect Unauthorized status

    expect(response.body.message).toBe('Invalid credentials'); // Expect specific error message
  });

  // Test Token Expiration
  it('should return 401 when using an expired token', async () => {
    const expiredToken = 'yourExpiredToken'; // Replace with an actual expired token

    const response = await request(app)
      .get('/protected-endpoint') // Protected endpoint
      .set('Authorization', `Bearer ${expiredToken}`)
      .expect(401); // Expect Unauthorized status

    expect(response.body.message).toBe('Token expired'); // Expect specific error message
  });
});
```

#### 2. **JWT Security Tests**

**File: `jwtSecurity.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app
import { generateToken } from '../src/auth'; // Adjust the path to your token generation function

describe('JWT Security Tests', () => {
  
  // Test Token Tampering
  it('should return 401 for tampered token', async () => {
    const validToken = generateToken({ username: 'testuser' }); // Generate a valid token
    const tamperedToken = validToken + 'tampered'; // Tamper with the token

    const response = await request(app)
      .get('/protected-endpoint') // Protected endpoint
      .set('Authorization', `Bearer ${tamperedToken}`)
      .expect(401); // Expect Unauthorized status

    expect(response.body.message).toBe('Invalid token'); // Expect specific error message
  });

  // Test Token Revocation
  it('should return 401 for revoked token', async () => {
    const validToken = generateToken({ username: 'testuser' }); // Generate a valid token
    // Simulate revoking the token (e.g., by removing it from a database or blacklist)
    
    const response = await request(app)
      .get('/protected-endpoint') // Protected endpoint
      .set('Authorization', `Bearer ${validToken}`)
      .expect(401); // Expect Unauthorized status

    expect(response.body.message).toBe('Token revoked'); // Expect specific error message
  });
});
```

#### 3. **Security Vulnerability Tests**

**File: `securityVulnerabilities.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Adjust the path to your app

describe('Security Vulnerability Tests', () => {
  
  // Test Unprotected Sensitive Data
  it('should not return sensitive user data when fetching user info', async () => {
    const validToken = 'yourValidToken'; // Replace with an actual valid token

    const response = await request(app)
      .get('/user/info') // User info endpoint
      .set('Authorization', `Bearer ${validToken}`)
      .expect(200); // Expect OK status

    expect(response.body.password).toBeUndefined(); // Password should not be included
  });

  // Test Weak Password Enforcement
  it('should enforce strong password requirements during registration', async () => {
    const weakUser = {
      username: 'newuser',
      password: '123', // Weak password
    };

    const response = await request(app)
      .post('/register') // Registration endpoint
      .send(weakUser)
      .expect(422); // Expect Unprocessable Entity status

    expect(response.body.message).toBe('Password is not strong enough'); // Expect specific error message
  });
});
```

### Step 3: Run Your Tests

To run your tests, execute the following command in your terminal:

```bash
npm run test
```

### Conclusion

This example provides a structured approach to testing user login and JWT token handling using Jest and Supertest. Each test case is designed to validate specific security aspects of your authentication system, helping to ensure that it is robust against common vulnerabilities.
