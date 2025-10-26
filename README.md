# Free Fire JWT Token Generator API Documentation

**Base URL:** `https://rasin-hex-jwt.vercel.app`  
**Developer:** Rasin Bb'z  
**Status:** Live 🟢  
**Region:** BD

---

## Endpoints

### Generate JWT Token
Generates a valid JWT token for Free Fire authentication.

**Endpoint:** `/token`  
**Method:** `GET`  
**Response Time:** ~1.5 seconds

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uid` | string | Yes | Free Fire User ID |
| `password` | string | Yes | Password hash (MD5 format) |

#### Request Example

```bash
curl "https://rasin-hex-jwt.vercel.app/token?uid=guest_uid&password=guest_pass"
```

#### Response Example (Success - 200)

```json
{
  "Time": "1.593 seconds",
  "api": "https://clientbp.ggwhitehawk.com",
  "developer": "Rasin Bb'z",
  "region": "BD",
  "status": "live",
  "token": "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV......"
}
```

#### JWT Token Payload (Decoded)

```json
{
  "account_id": 13598936522,
  "nickname": "account_name",
  "noti_region": "region",
  "lock_region": "region",
  "external_id": "dcf0c1b8a42ba603cf44ab87e707e763",
  "external_type": 4,
  "plat_id": 1,
  "client_version": "1.108.3",
  "emulator_score": 100,
  "is_emulator": true,
  "country_code": "US",
  "external_uid": uid,
  "reg_avatar": 102000007,
  "source": 4,
  "lock_region_time": 1760761185,
  "client_type": 2,
  "signature_md5": "",
  "using_version": 1,
  "release_channel": "3rd_party",
  "release_version": "OB50",
  "exp": 1761514397
}
```

---

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `Time` | string | API response time |
| `api` | string | Internal API endpoint |
| `developer` | string | API developer name |
| `region` | string | User region |
| `status` | string | API status |
| `token` | string | JWT token (use for FF auth) |

## Token Claims

| Claim | Type | Description |
|-------|------|-------------|
| `account_id` | number | FF account ID |
| `nickname` | string | In-game nickname |
| `external_uid` | number | Input UID |
| `is_emulator` | boolean | Emulator detection flag |
| `exp` | number | Token expiration (Unix timestamp) |
| `client_version` | string | FF client version |
| `country_code` | string | Country code |

---

## Usage in Node.js

```javascript
import axios from 'axios';

const getFFToken = async (uid, password) => {
  try {
    const response = await axios.get('https://rasin-hex-jwt.vercel.app/token', {
      params: { uid, password },
      timeout: 5000
    });
    
    const { token, Time } = response.data;
    console.log(`Token generated in ${Time}`);
    return token;
  } catch (error) {
    console.error('Error:', error.message);
    return null;
  }
};

// Usage
const token = await getFFToken('4199274871', 'ACA03CF93B5FD2909D1E2BEAFB155FBA3E808BADDB6FAC047CDE7AF4D8A19936');
console.log(token);
```

## Decode JWT Token

```javascript
import jwt from 'jsonwebtoken';

const decodeToken = (token) => {
  try {
    const decoded = jwt.decode(token); // No verification needed for decoding
    return decoded;
  } catch (error) {
    console.error('Invalid token:', error.message);
    return null;
  }
};

const payload = decodeToken(token);
console.log('Account ID:', payload.account_id);
console.log('Nickname:', payload.nickname);
console.log('Expires:', new Date(payload.exp * 1000));
```

---

## Error Handling

```javascript
const getTokenSafe = async (uid, password) => {
  try {
    if (!uid || !password) {
      throw new Error('UID and password are required');
    }
    
    const response = await axios.get('https://rasin-hex-jwt.vercel.app/token', {
      params: { uid, password },
      timeout: 8000
    });
    
    if (!response.data.token) {
      throw new Error('No token in response');
    }
    
    return { success: true, token: response.data.token };
  } catch (error) {
    return { 
      success: false, 
      error: error.message,
      statusCode: error.response?.status 
    };
  }
};
```

---

## Security Notes

⚠️ **Important:**
- Never expose passwords in frontend code
- Store tokens server-side only
- Check token expiration before using
- Implement token refresh mechanism
- Use HTTPS always
- Add rate limiting on your backend

---

## Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Token generated successfully ✅ |
| 400 | Invalid parameters (missing uid/password) |
| 401 | Invalid credentials |
| 500 | Server error |

---

**Last Updated:** October 26, 2025  
**API Version:** 1.0  
**Region:** Bangladesh 🇧🇩
