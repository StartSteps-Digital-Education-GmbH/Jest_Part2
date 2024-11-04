# Live Code

Live coding example focused on user login and JWT token handling, including tests for various security vulnerabilities using Jest and Supertest. This example will cover user authentication, token generation, and testing for vulnerabilities related to JWT.


### Step 1: Project Setup

1. **Initialize a New Node.js Project**

   Open your terminal and create a new directory for your project. Navigate into it and initialize a new Node.js project:

   ```bash
   mkdir jwt-auth-example
   cd jwt-auth-example
   npm init -y
   ```

2. **Install Required Dependencies**

   Install the necessary packages for your project:

   ```bash
   npm install express jsonwebtoken bcryptjs body-parser
   npm install --save-dev jest @types/jest ts-jest supertest @types/supertest typescript
   ```

   - **express**: Web framework for Node.js.
   - **jsonwebtoken**: Library to work with JWTs.
   - **bcryptjs**: Library for hashing passwords.
   - **body-parser**: Middleware to parse incoming request bodies.
   - **jest**: Testing framework.
   - **supertest**: Library for testing HTTP servers.
   - **typescript**: TypeScript support.

3. **Create TypeScript Configuration**

   Create a `tsconfig.json` file for TypeScript configuration:

   ```json
   {
     "compilerOptions": {
       "target": "ES6",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "skipLibCheck": true,
       "forceConsistentCasingInFileNames": true
     },
     "include": ["src/**/*", "__tests__/**/*"]
   }
   ```

### Step 2: Create the Application Structure

Create the following directory structure:

```
jwt-auth-example/
├── src/
│   ├── app.ts
│   ├── auth.ts
│   └── user.ts
├── __tests__/
│   ├── auth.spec.ts
│   └── securityVulnerabilities.spec.ts
├── package.json
└── tsconfig.json
```

### Step 3: Implement the Application Logic

#### 1. **Create the Express Application**

**File: `src/app.ts`**

```typescript
import express from 'express';
import bodyParser from 'body-parser';
import { login, register, getUserInfo } from './auth';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Routes
app.post('/login', login); // Login route
app.post('/register', register); // Registration route
app.get('/user/info', getUserInfo); // Get user info route

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

export default app; // Export the app for testing
```

#### 2. **Implement Authentication Logic**

**File: `src/auth.ts`**

```typescript
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// In-memory user storage (for demonstration purposes)
const users: { [key: string]: { password: string } } = {};

// Secret key for JWT signing
const JWT_SECRET = 'your_jwt_secret'; // Change this to a secure key in production

// Function to register a new user
export const register = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Check if the user already exists
  if (users[username]) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = { password: hashedPassword }; // Store user

  return res.status(201).json({ message: 'User registered successfully' });
};

// Function to log in a user
export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Check if the user exists
  const user = users[username];
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Check password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  return res.status(200).json({ token });
};

// Middleware to protect routes
export const authenticateJWT = (req: Request, res: Response, next: Function) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Get token from header

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    req.user = user; // Attach user to request
    next(); // Proceed to the next middleware
  });
};

// Function to get user info
export const getUserInfo = (req: Request, res: Response) => {
  res.status(200).json({ username: req.user.username }); // Return user info
};
```

### Step 4: Write Tests

#### 1. **User Authentication Tests**

**File: `__tests__/auth.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Import the app

describe('User Authentication Tests', () => {
  
  // Test Successful Registration
  it('should register a new user successfully', async () => {
    const userCredentials = {
      username: 'testuser',
      password: 'strongpassword',
    };

    const response = await request(app)
      .post('/register') // Registration endpoint
      .send(userCredentials)
      .expect(201); // Expect Created status

    expect(response.body.message).toBe('User registered successfully'); // Expect success message
  });

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
});
```

#### 2. **Security Vulnerability Tests**

**File: `__tests__/securityVulnerabilities.spec.ts`**

```typescript
import request from 'supertest';
import app from '../src/app'; // Import the app
import { generateToken } from '../src/auth'; // Import the token generation function

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

### Step 5: Run Your Tests

To run your tests, execute the following command in your terminal:

```bash
npm run test
```

### Conclusion

This guide provides a comprehensive overview of setting up a user login system with JWT authentication in Node.js using TypeScript. The application includes user registration, login, and protected routes, along with tests to ensure the security and functionality of the application. Each section is documented with comments to help you understand the code and its purpose.
