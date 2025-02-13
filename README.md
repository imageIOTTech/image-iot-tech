## Endpoints

### Register User
- **URL:** `/register`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phonenumber": "123456789",
        "password": "password123"
    }
    ```

- **Response:**
    ```json
    {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phonenumber": "123456789",
        "authProvider": "local"
    }
    ```


### Local Login
- **URL:** `/login/local`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "email": "john.doe@example.com",
        "password": "password123"
    }
    ```

- **Response:**
    ```json
    {
        "message": "OTP đã được gửi tới email của bạn."
    }
    ```


### Verify OTP
- **URL:** `/verify-otp`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "email": "john.doe@example.com",
        "otp": "123456"
    }
    ```
- **Response:**
    ```json
    {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "tokenType": "Bearer",
        "refreshToken": "d1f1e2d3-4e5f-6789-abcd-ef0123456789",
        "id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com",
        "roles": ["ROLE_USER"]
    }


### OAuth2 Login
- **URL:** `/login/{provider}`
- **Method:** `GET`
- **Path Variables:**
    - `provider`: The OAuth2 provider (e.g., `google`, `facebook`, `github`)
- **Behavior:**
  - This endpoint starts the OAuth2 login process.
  - After calling, the client is redirected to the provider's login page.

### OAuth2 Login Success
- **URL:** `/loginSuccess/{provider}`
- **Method:** `GET`
- **Path Variables:**
    - `provider`: The OAuth2 provider (e.g., `google`, `facebook`, `github`)
- **Response:**
    ```json
    {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "tokenType": "Bearer",
        "refreshToken": "d1f1e2d3-4e5f-6789-abcd-ef0123456789",
        "id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com",
        "roles": ["ROLE_USER"]
    }
    ```

### Refresh Token
- **URL:** `/refresh-token`
- **Method:** `POST`
- **Request Body:**
    ```json
    {
        "refreshToken": "d1f1e2d3-4e5f-6789-abcd-ef0123456789"
    }
    ```
- **Response:**
    ```json
    {
        "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refreshToken": "d1f1e2d3-4e5f-6789-abcd-ef0123456789"
    }
    ```