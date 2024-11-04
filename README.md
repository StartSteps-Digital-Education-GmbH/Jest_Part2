# How to Use Jest to Test Security Vulnerabilities on APIs

In this guide, you will learn how to install Jest and use it to test API vulnerabilities. Ensuring that your application is secure and protected from potential attacks is crucial in today’s digital landscape.

## Initial Configuration

First, you need to install Jest and Supertest, which will help you test your APIs.

```bash
npm i --save-dev jest @types/jest ts-jest supertest
```

You will also install the TypeScript typings and the `ts-jest` library, which allows Jest to work seamlessly with TypeScript.

Next, add the following configuration to your `package.json`:

```json
"jest": {
  "preset": "ts-jest",
  "testEnvironment": "node"
}
```

Finally, in the `scripts` section, add:

```json
"test": "jest"
```

Now you can execute `npm run test` to run your test suite.

## Security Vulnerabilities

In this first part, we will cover the first five items on the OWASP 2021 Top Ten List. You can learn more about it [here](https://owasp.org/www-project-top-ten). Some of the most common potential security vulnerabilities in APIs include:

1. **Broken Access Control**: Occurs when an application does not properly enforce restrictions on what authenticated users are allowed to do.
2. **Cryptographic Failures**: Weaknesses in the implementation of cryptographic functions can lead to sensitive data compromise.
3. **Injection**: Untrusted data is inserted into a command or query, allowing attackers to manipulate application behavior.
4. **Insecure Design**: Security weaknesses stemming from poor architectural or design choices.
5. **Security Misconfiguration**: Insecure configuration of an application or its components can lead to vulnerabilities.

## How to Handle Them with Jest

### Broken Access Control

#### Test Unauthorized Access

This test checks that a GET request to a protected endpoint returns a 403 (Forbidden) status code when no credentials are provided.

```typescript
it('should return a 403 status code when attempting to access a protected endpoint without credentials', async () => {
  await request(app.getHttpServer())
    .get('/protected-endpoint')
    .expect(HttpStatus.FORBIDDEN);
});
```

#### Test Vertical Access

This test verifies that a regular user cannot perform an admin action.

```typescript
it('should return a 401 status code when attempting to perform an admin action being a regular user', async () => {
  const regularUserToken = generateToken(regularUser);
  await request(app)
    .post('/admin/action')
    .set('Authorization', `Bearer ${regularUserToken}`)
    .send({ data: 'someData' })
    .expect(HttpStatus.UNAUTHORIZED);
});
```

#### Test Horizontal Access

This test ensures that users can only access their own clients.

```typescript
it('should return a 401 status code when attempting to access another user’s client', async () => {
  const userAToken = generateToken(userA);
  await request(app)
    .get('/clients/A')
    .set('Authorization', `Bearer ${userAToken}`)
    .expect(HttpStatus.OK);
  
  await request(app)
    .get('/clients/B')
    .set('Authorization', `Bearer ${userAToken}`)
    .expect(HttpStatus.UNAUTHORIZED);
});
```

### Cryptographic Failures

#### Testing Key Management

This test checks that decrypting data with an incorrect key fails.

```typescript
it('should fail when decrypting with incorrect key', () => {
  const data = 'Sensitive information';
  const keyA = generateKey();
  const keyB = generateIncorrectKey();
  const encrypted = encryptWithKey(data, keyA);
  const decryptedCorrect = decryptWithKey(encrypted, keyA);
  const decryptedIncorrect = decryptWithKey(encrypted, keyB);
  
  expect(decryptedCorrect).not.toBeNull();
  expect(decryptedIncorrect).toBeNull();
});
```

### Injection

#### SQL Injection Attacks

This test sends a GET request with a malicious query parameter to check for SQL injection vulnerabilities.

```typescript
it('should return 400 for SQL injection attempt in query params', async () => {
  const response = await request(app)
    .get(`/products?id=' OR 1=1 --`) // assuming id is a number
    .send();
  
  expect(response.status).toBe(HttpStatus.BAD_REQUEST);
  expect(response.body.message).toBe('invalid input syntax for integer');
});
```

#### Cross-Site Scripting Attacks (XSS)

This test ensures that user input is sanitized to prevent XSS attacks.

```typescript
it('should sanitize user input to prevent XSS attacks', async () => {
  const newUser = {
    username: 'username',
    email: 'user@example.com',
    password: 'password',
    profile: 'User profile <script>alert("XSS vulnerability");</script>',
  };
  
  const response = await request(app.getHttpServer())
    .post('/users')
    .send(newUser);
  
  expect(response.status).toBe(HttpStatus.CREATED);
  expect(response.body.username).toBe(newUser.username);
  expect(response.body.profile).not.toMatch(/<script>/i);
});
```

### Insecure Design

#### Test Unprotected Sensitive Data

This test ensures that sensitive data, like passwords, are not returned in API responses.

```typescript
it('should not return the user password when fetching the user', async () => {
  const response = await request(app)
    .get('/user/1')
    .expect(HttpStatus.OK);
  
  expect(response.body.data.password).not.toBeDefined();
});
```

#### Testing Insecure Password

This test checks that weak passwords are rejected.

```typescript
it('should enforce strong password requirements', async () => {
  const response = await request(app)
    .post('/user')
    .send({
      username: 'username',
      password: 'weakpassword'
    })
    .expect(HttpStatus.UNPROCESSABLE_ENTITY);
  
  expect(response.body.message).toBe('password is not strong enough');
});
```

### Security Misconfiguration

#### Security Headers

This test verifies that important security headers are included in API responses.

```typescript
it('should include security headers', async () => {
  const response = await request(app.getHttpServer())
    .get('/endpoint')
    .expect(HttpStatus.OK);
  
  expect(response.headers['Content-Security-Policy']).toBeDefined();
  expect(response.headers['X-Frame-Options']).toBeDefined();
  expect(response.headers['X-Frame-Options']).toBe('deny');
});
```

## Conclusion

Using Jest to test individual functions or methods is essential, but testing API vulnerabilities is a critical aspect of application security. Identifying and fixing these security issues early in the development cycle is less complex and less expensive.

By testing for API vulnerabilities, you can ensure that your application is secure and can withstand real-world attacks. This proactive approach helps protect your organization from potential harm and maintains the trust of your customers.
