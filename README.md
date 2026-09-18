# Have I Been Pwned MCP Server

[![smithery badge](https://smithery.ai/badge/@Cyreslab-AI/hibp-mcp-server)](https://smithery.ai/server/@Cyreslab-AI/hibp-mcp-server)

A Model Context Protocol (MCP) server that provides integration with the [Have I Been Pwned](https://haveibeenpwned.com/) API to check if your accounts or passwords have been compromised in data breaches.

## Features

This MCP server provides the following tools:

### Free (no API key required)

1. **check_password**: Check if a password has been exposed in data breaches (using k-anonymity)
2. **get_breach_details**: Get detailed information about a specific data breach
3. **list_all_breaches**: List all breaches in the system, optionally filtered by domain
4. **get_data_classes**: List all the types of data (data classes) that can appear in a breach
5. **get_latest_breach**: Get the most recently added breach in the system

### Requires a paid HIBP API key

6. **check_email**: Check if an email address has been found in data breaches
7. **get_pastes_for_account**: Check if an email address has appeared in a paste (e.g. Pastebin)
8. **check_stealer_logs_by_email**: Check which website domains had credentials for an email address captured by info-stealer malware (Pro-tier or higher)
9. **check_stealer_logs_by_website_domain**: Check which email aliases had credentials for a website domain captured by info-stealer malware (Pro-tier or higher)
10. **check_stealer_logs_by_email_domain**: Check which email aliases at a verified email domain had credentials captured by info-stealer malware, and for which websites (Pro-tier or higher)

Stealer logs are a different, higher-fidelity threat category than classic breach lists: they show credentials that info-stealer malware captured directly off a victim's device (for example, from a browser's saved passwords), rather than credentials leaked when a company's database was hacked.

## Installation

### Installing via Smithery

To install hibp-mcp-server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@Cyreslab-AI/hibp-mcp-server):

```bash
npx -y @smithery/cli install @Cyreslab-AI/hibp-mcp-server --client claude
```

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

### Get Data Classes

```
User: What types of data does HIBP track?

Claude: Have I Been Pwned tracks 165 types of compromised data:

- Academic records
- Account balances
- ...
```

### Get Latest Breach

```
User: What's the most recent breach added to HIBP?

Claude: # Latest Breach: Chess2026

**Date:** 2026-08-03
**Domain:** chess.com
**Accounts affected:** 4,653,212
**Data leaked:** Email addresses, Geographic locations, Names, Usernames
```

### Get Pastes for Account (requires API key)

```
User: Has my email been found in any pastes?

Claude: ⚠️ This email address was found in 1 paste.

1. Source: Pastebin
   Date: 2014-03-04T19:14:54Z
   Email addresses in paste: 139
```

### Check Stealer Logs by Email (requires Pro-tier API key or higher)

```
User: Has my email shown up in any stealer logs?

Claude: ⚠️ This email address's credentials were found in stealer logs for 2 websites.

Websites: netflix.com, spotify.com

Recommendations:
- Change your password on these websites immediately
- Run an up-to-date malware scan on any device you use to log in
- Enable two-factor authentication where available
```

### Check Stealer Logs by Website Domain (requires Pro-tier API key or higher)

```
User: Which of our users had credentials for netflix.com captured by stealer malware?

Claude: ⚠️ Found 2 email aliases with credentials for netflix.com captured in stealer logs.

Email aliases: andy@gmail.com, jane@gmail.com
```

### Check Stealer Logs by Email Domain (requires Pro-tier API key or higher, verified domain)

```
User: Have any of our employees at example.com shown up in stealer logs?

Claude: ⚠️ Found 2 email aliases at example.com with credentials captured in stealer logs.

1. andy@example.com: netflix.com
2. jane@example.com: netflix.com, spotify.com
```

## Security Notes

- The password checking feature uses k-anonymity to check passwords without sending the full password to the Have I Been Pwned API
- Only the first 5 characters of the SHA-1 hash of the password are sent to the API
- The API returns a list of hash suffixes that match the prefix, and the check is completed locally

## API Key Configuration

Per the [HIBP API](https://haveibeenpwned.com/API/v3), some endpoints are free and public, while others require a paid API key:

- **Free, no key needed:** `check_password`, `get_breach_details`, `list_all_breaches`, `get_data_classes`, `get_latest_breach`
- **Requires a paid API key:** `check_email`, `get_pastes_for_account` (Core, Pro, or High RPM tier)
- **Requires a paid API key with Pro-tier access or higher:** `check_stealer_logs_by_email`, `check_stealer_logs_by_website_domain`, `check_stealer_logs_by_email_domain` (the email/domain-scoped stealer logs endpoints also need the domain to be verified with HIBP)

You can get an API key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key).

The API key should be provided as an environment variable named `HIBP_API_KEY` in your MCP settings configuration. If it is not set, the free tools above still work; the tools that require a key return a clear error message instead of failing silently.

## License

MIT
