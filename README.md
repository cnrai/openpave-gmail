# openpave-gmail

📧 Gmail skill for OpenPAVE - Read and manage Gmail messages securely using OAuth.

## Installation

```bash
# From local directory
pave install ~/pave-apps/openpave-gmail

# From GitHub (coming soon)
pave install openpave/openpave-gmail
```

## Setup

### 1. Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the **Gmail API**
4. Go to **Credentials** → **Create Credentials** → **OAuth 2.0 Client ID**
5. Application type: **Desktop app**
6. Download the credentials

### 2. Get Refresh Token

Use the [OAuth Playground](https://developers.google.com/oauthplayground/) or run the Gmail auth flow to get a refresh token.

### 3. Set Environment Variables

Add to your `.env` file:

```bash
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-client-secret
GMAIL_REFRESH_TOKEN=your-refresh-token
```

The skill will automatically obtain and refresh access tokens.

## Usage

```bash
# Get profile info
gmail profile --summary

# List recent messages
gmail list --max 10 --summary

# List unread messages
gmail unread --summary

# Search messages
gmail list -q "from:someone@example.com" --summary

# Read a specific message
gmail read <messageId> --summary

# Mark messages as read
gmail mark-read <messageId1> <messageId2>

# Mark message as unread
gmail mark-unread <messageId>

# Move messages to trash
gmail trash <messageId1> <messageId2>
```

## Commands

| Command | Description |
|---------|-------------|
| `profile` | Get Gmail profile info (email, message count) |
| `list` | List recent messages with optional search query |
| `unread` | Show unread messages |
| `read <id>` | Read a specific message by ID |
| `mark-read <id...>` | Mark one or more messages as read |
| `mark-unread <id>` | Mark a message as unread |
| `trash <id...>` | Move one or more messages to trash |

## Options

| Option | Description |
|--------|-------------|
| `--max <n>` | Maximum number of results (default: 10) |
| `--summary` | Human-readable output |
| `--json` | Raw JSON output |
| `--full` | Include full message content |
| `-q, --query` | Gmail search query |

## Security

This skill uses the PAVE sandbox secure token system:
- Tokens are **never exposed** to the skill code
- OAuth refresh is handled automatically by the sandbox
- Network access is restricted to Gmail API domains only

## License

MIT
