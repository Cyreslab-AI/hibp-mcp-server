# Have I Been Pwned MCP Server

A Model Context Protocol (MCP) server that provides integration with the [Have I Been Pwned](https://haveibeenpwned.com/) API to check if your accounts or passwords have been compromised in data breaches.

## Features

This MCP server provides four main tools:

1. **check_email**: Check if an email address has been found in data breaches
2. **check_password**: Check if a password has been exposed in data breaches (using k-anonymity)
3. **get_breach_details**: Get detailed information about a specific data breach
4. **list_all_breaches**: List all breaches in the system, optionally filtered by domain

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)
- A Have I Been Pwned API key (get one at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key))

### Setup

1. Clone this repository:

   ```bash
   git clone https://github.com/Cyreslab-AI/hibp-mcp-server.git
   cd hibp-mcp-server
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Build the server:

   ```bash
   npm run build
   ```

4. Configure the server in your MCP settings file:

   For Claude VSCode extension, add to `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`:

   ```json
   {
     "mcpServers": {
       "hibp": {
         "command": "node",
         "args": ["/path/to/hibp-mcp-server/build/index.js"],
         "env": {
           "HIBP_API_KEY": "YOUR_API_KEY_HERE"
         },
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

   For Claude desktop app, add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or similar path on other platforms.

## Usage Examples

Once the server is configured, you can use it with Claude to check for data breaches:

### Check Email

```
User: Has my email address example@gmail.com been pwned?

Claude: Good news! This email address has not been found in any known data breaches.
```

Or if the email was found in breaches:

```
User: Has my email address breached@example.com been pwned?

Claude: ⚠️ This email address was found in 3 data breaches.

Breach details:

1. Adobe (2013-10-04)
   Domain: adobe.com
   Description: In October 2013, 153 million Adobe accounts were breached...
   Compromised data: Email addresses, Password hints, Passwords, Usernames

2. LinkedIn (2012-05-05)
   Domain: linkedin.com
   Description: In May 2016, LinkedIn had 164 million email addresses and passwords exposed...
   Compromised data: Email addresses, Passwords

3. Dropbox (2012-07-01)
   Domain: dropbox.com
   Description: In mid-2012, Dropbox suffered a data breach which exposed...
   Compromised data: Email addresses, Passwords

Recommendations:
- Change your password for these services immediately
- If you used the same password elsewhere, change those too
- Enable two-factor authentication where available
- Consider using a password manager
```

### Check Password

```
User: Has the password "password123" been exposed in any breaches?

Claude: ⚠️ This password has been exposed in data breaches 123,456 times!

Recommendations:
- Stop using this password immediately
- Change it on any site where you use it
- Use a unique, strong password for each account
- Consider using a password manager
```

### Get Breach Details

```
User: Tell me about the LinkedIn data breach

Claude: # LinkedIn Data Breach

**Date:** 2012-05-05
**Domain:** linkedin.com
**Accounts affected:** 164,611,595
**Verified:** Yes
**Data leaked:** Email addresses, Passwords

**Description:**
In May 2016, LinkedIn had 164 million email addresses and passwords exposed. Originally hacked in 2012, the data remained out of sight until being offered for sale on a dark market site 4 years later. The passwords in the breach were stored as SHA1 hashes without salt, the vast majority of which were quickly cracked in the days following the release of the data.

**Recommendations:**
- If you had an account on this service, change your password
- If you used the same password elsewhere, change those too
- Monitor your accounts for suspicious activity
- Be cautious of phishing attempts that may use this leaked information
```

### List All Breaches

```
User: List all Adobe data breaches

Claude: Found 1 breaches for domain adobe.com:

1. Adobe (2013-10-04)
   Domain: adobe.com
   Accounts affected: 152,445,165
   Compromised data: Email addresses, Password hints, Passwords, Usernames
```

## Security Notes

- The password checking feature uses k-anonymity to check passwords without sending the full password to the Have I Been Pwned API
- Only the first 5 characters of the SHA-1 hash of the password are sent to the API
- The API returns a list of hash suffixes that match the prefix, and the check is completed locally

## API Key Configuration

This server requires a Have I Been Pwned API key to function for most features (except password checking). You can get an API key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key).

The API key should be provided as an environment variable named `HIBP_API_KEY` in your MCP settings configuration.

## License

MIT
