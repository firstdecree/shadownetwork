# ShadowNetwork
Store your contacts securely and indefinitely with ease and convenience.

# ⚙️ Installations
## Github
```
git clone https://github.com/firstdecree/shadownetwork
```

## NpmJS
```
npm install
```

## PNPM
```
pnpm install
```

# 🚀 Usage
```
node index.js
```

# 🔐 Security
## Login
- **hashedUsername:** A SHA-512 hash of the username. This field is required for user lookup. Since AES-256 encryption is randomized, it is not possible to reliably identify a user using the encrypted username alone.
- **username:** The username encrypted using AES-256.
- **password:** The password hashed using SHA-512.

The cookie is also encrypted using **aes-256-gcm**.

## Contacts
- **username:** A SHA-512 hash of the username, used to associate and track the contacts owned by a specific user.

All other fields are encrypted using AES-256.

## Others
- All API endpoints that process user-supplied data implement input sanitization to mitigate potential XSS (Cross-Site Scripting) attacks.
- The maximum length for a registered username is 35 characters.
- The maximum length for a contact alias is 25 characters.
- The maximum length for a contact public key is 5,200 characters.
- The maximum length for a contact note is 1,000 characters.
- The maximum length for a contact connection platform is 20 characters.
- The maximum length for a contact connection field is 60 characters.

# 🌟 Sponsors
<table border="1">
    <tr>
        <td style="text-align: center; padding: 10px;">
            <img src="https://cdn.vexhub.dev/assets/files/newlogo.png" alt="Vexhub Hosting" style="width: 150px; height: auto;">
            <br>
            <p align="center"><a href="https://vexhub.dev/">Vexhub Hosting</a></p>
        </td>
    </tr>
</table>