#!/usr/bin/env node
/**
 * Gmail CLI - Secure Token Version
 * 
 * Uses the PAVE sandbox secure token system for authentication.
 * Tokens are never visible to sandbox code - they're injected by the host.
 * 
 * Token configuration in ~/.pave/permissions.yaml:
 * {
 *   "tokens": {
 *     "gmail": {
 *       "env": "GMAIL_ACCESS_TOKEN",
 *       "type": "oauth",
 *       "domains": ["gmail.googleapis.com", "*.googleapis.com"],
 *       "placement": { "type": "header", "name": "Authorization", "format": "Bearer {token}" },
 *       "refreshEnv": "GMAIL_REFRESH_TOKEN",
 *       "refreshUrl": "https://oauth2.googleapis.com/token",
 *       "clientIdEnv": "GMAIL_CLIENT_ID",
 *       "clientSecretEnv": "GMAIL_CLIENT_SECRET"
 *     }
 *   }
 * }
 */

// Parse command line arguments  
const args = process.argv.slice(2);

function parseArgs() {
  const parsed = {
    command: null,
    positional: [],
    options: {}
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('-')) {
      if (arg.startsWith('--')) {
        const [key, value] = arg.slice(2).split('=', 2);
        if (value !== undefined) {
          parsed.options[key] = value;
        } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
          parsed.options[key] = args[i + 1];
          i++;
        } else {
          parsed.options[key] = true;
        }
      } else {
        const flag = arg.slice(1);
        if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
          parsed.options[flag] = args[i + 1];
          i++;
        } else {
          parsed.options[flag] = true;
        }
      }
    } else {
      if (parsed.command === null) {
        parsed.command = arg;
      } else {
        parsed.positional.push(arg);
      }
    }
  }
  
  return parsed;
}

// URL encoding function for sandbox compatibility
function encodeFormData(data) {
  const params = [];
  for (const [key, value] of Object.entries(data)) {
    params.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  }
  return params.join('&');
}

// Gmail Client Class - Uses secure token system
class GmailClient {
  constructor() {
    // Check if gmail token is available via secure token system
    if (typeof hasToken === 'function' && !hasToken('gmail')) {
      console.error('Gmail token not configured.');
      console.error('');
      console.error('Add to ~/.config/opencode-lite/permissions.json:');
      console.error(JSON.stringify({
        gmail: {
          env: 'GMAIL_ACCESS_TOKEN',
          type: 'oauth',
          domains: ['gmail.googleapis.com', '*.googleapis.com'],
          placement: { type: 'header', name: 'Authorization', format: 'Bearer {token}' },
          refreshEnv: 'GMAIL_REFRESH_TOKEN',
          refreshUrl: 'https://oauth2.googleapis.com/token',
          clientIdEnv: 'GMAIL_CLIENT_ID',
          clientSecretEnv: 'GMAIL_CLIENT_SECRET'
        }
      }, null, 2));
      console.error('');
      console.error('Then set environment variables:');
      console.error('  GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN');
      throw new Error('Gmail token not configured');
    }
    
    this.baseUrl = 'https://gmail.googleapis.com/gmail/v1';
  }
  
  request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    
    // Use authenticatedFetch - token injection and OAuth refresh handled by sandbox
    const response = authenticatedFetch('gmail', url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: options.timeout || 15000
    });
    
    if (!response.ok) {
      const error = response.json();
      const err = new Error(error.error?.message || `HTTP ${response.status}`);
      err.status = response.status;
      err.data = error;
      throw err;
    }
    
    return response.json();
  }
  
  listMessages(options = {}) {
    const paramData = {};
    
    if (options.q) paramData.q = options.q;
    if (options.maxResults) paramData.maxResults = options.maxResults;
    if (options.pageToken) paramData.pageToken = options.pageToken;
    if (options.labelIds && Array.isArray(options.labelIds)) {
      paramData.labelIds = options.labelIds.join(',');
    }
    
    const queryString = Object.keys(paramData).length > 0 ? `?${encodeFormData(paramData)}` : '';
    return this.request(`/users/me/messages${queryString}`);
  }
  
  getMessage(messageId, format = 'full') {
    const paramData = {};
    if (format) paramData.format = format;
    
    const queryString = Object.keys(paramData).length > 0 ? `?${encodeFormData(paramData)}` : '';
    return this.request(`/users/me/messages/${messageId}${queryString}`);
  }
  
  getMessages(messageIds, format = 'full') {
    const messages = [];
    for (const id of messageIds) {
      try {
        const message = this.getMessage(id, format);
        messages.push(message);
      } catch (error) {
        messages.push({ id, error: error.message });
      }
    }
    return messages;
  }
  
  getProfile() {
    return this.request('/users/me/profile');
  }
  
  modifyMessage(messageId, options = {}) {
    const body = {};
    if (options.addLabelIds) body.addLabelIds = options.addLabelIds;
    if (options.removeLabelIds) body.removeLabelIds = options.removeLabelIds;
    
    return this.request(`/users/me/messages/${messageId}/modify`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }
  
  markAsRead(messageId) {
    return this.modifyMessage(messageId, {
      removeLabelIds: ['UNREAD']
    });
  }
  
  markAsUnread(messageId) {
    return this.modifyMessage(messageId, {
      addLabelIds: ['UNREAD']
    });
  }
  
  trashMessage(messageId) {
    return this.request(`/users/me/messages/${messageId}/trash`, {
      method: 'POST'
    });
  }
  
  // Format message for human-readable output
  static formatMessage(message) {
    const headers = message.payload?.headers || [];
    const getHeader = (name) => headers.find(h => h.name === name)?.value || '';
    
    return {
      id: message.id,
      threadId: message.threadId,
      subject: getHeader('Subject') || 'No subject',
      from: getHeader('From') || 'Unknown sender',
      to: getHeader('To') || '',
      date: getHeader('Date') || '',
      isUnread: message.labelIds?.includes('UNREAD') || false,
      labels: message.labelIds || [],
      snippet: message.snippet || ''
    };
  }
}

// Print functions
function printMessagesSummary(messages) {
  console.log(`Found ${messages.length} message(s):\n`);
  
  messages.forEach((msg, index) => {
    if (msg.error) {
      console.log(`${index + 1}. [Error: ${msg.error}]`);
      return;
    }
    
    const formatted = GmailClient.formatMessage(msg);
    const unreadMarker = formatted.isUnread ? '[UNREAD] ' : '';
    const fromShort = formatted.from.split('<')[0].trim() || formatted.from;
    
    console.log(`${index + 1}. ${unreadMarker}${formatted.subject}`);
    console.log(`   From: ${fromShort}`);
    
    // Format date
    if (formatted.date) {
      try {
        const d = new Date(formatted.date);
        console.log(`   Date: ${d.toLocaleDateString()} ${d.toLocaleTimeString()}`);
      } catch (e) {
        console.log(`   Date: ${formatted.date.substring(0, 30)}`);
      }
    }
    
    if (formatted.snippet) {
      console.log(`   Preview: ${formatted.snippet.substring(0, 100)}...`);
    }
    console.log();
  });
}

function printHelp() {
  console.log(`
Gmail CLI - Secure Token Version

USAGE:
  node gmail.js <command> [options]

COMMANDS:
  profile                     Get Gmail profile info
  list [options]             List recent messages  
  unread [options]           Show unread messages
  read <messageId>           Read specific message
  mark-read <id1> [id2...]   Mark messages as read
  mark-unread <id>           Mark message as unread
  trash <id1> [id2...]       Move messages to trash

OPTIONS:
  --max <number>             Maximum results (default: 10)
  --summary                  Human-readable output
  --json                     Raw JSON output
  --full                     Include full message content
  -q, --query <query>        Search query

EXAMPLES:
  node gmail.js profile --summary
  node gmail.js list --max 5 --summary
  node gmail.js unread --summary
  node gmail.js list -q "from:someone@example.com"
  node gmail.js read 1234567890abcdef
  node gmail.js mark-read 1234567890abcdef

TOKEN SETUP:
  Tokens are configured in ~/.config/opencode-lite/permissions.json
  Environment variables needed:
    GMAIL_CLIENT_ID       - OAuth client ID
    GMAIL_CLIENT_SECRET   - OAuth client secret  
    GMAIL_REFRESH_TOKEN   - OAuth refresh token
    GMAIL_ACCESS_TOKEN    - (optional) Current access token
`);
}

// Main execution function
function main() {
  const parsed = parseArgs();
  
  if (!parsed.command || parsed.command === 'help' || parsed.options.help) {
    printHelp();
    return;
  }
  
  try {
    const client = new GmailClient();
    
    switch (parsed.command) {
      case 'profile': {
        const result = client.getProfile();
        
        if (parsed.options.summary) {
          console.log(`Gmail Account: ${result.emailAddress}`);
          console.log(`Total messages: ${result.messagesTotal}`);
          console.log(`Total threads: ${result.threadsTotal}`);
          console.log(`History ID: ${result.historyId}`);
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }
      
      case 'list': {
        const options = {
          maxResults: parseInt(parsed.options.max) || parseInt(parsed.options.maxResults) || 10,
          q: parsed.options.q || parsed.options.query
        };
        
        const result = client.listMessages(options);
        
        if (!result.messages || result.messages.length === 0) {
          if (parsed.options.summary) {
            console.log('No messages found.');
          } else {
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }, null, 2));
          }
          break;
        }
        
        if (parsed.options.summary || parsed.options.full) {
          const messages = client.getMessages(result.messages.map(m => m.id), 'full');
          
          if (parsed.options.summary) {
            printMessagesSummary(messages);
          } else {
            const formatted = messages.map(m => m.error ? m : GmailClient.formatMessage(m));
            console.log(JSON.stringify(formatted, null, 2));
          }
        } else {
          console.log(JSON.stringify(result, null, 2));
        }
        break;
      }
      
      case 'unread': {
        const result = client.listMessages({
          q: 'is:unread',
          maxResults: parseInt(parsed.options.max) || 50
        });
        
        if (!result.messages || result.messages.length === 0) {
          if (parsed.options.summary) {
            console.log('No unread messages - inbox is clear!');
          } else {
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }, null, 2));
          }
          break;
        }
        
        const messages = client.getMessages(result.messages.map(m => m.id), 'full');
        
        if (parsed.options.summary) {
          printMessagesSummary(messages);
        } else {
          const formatted = messages.map(m => m.error ? m : GmailClient.formatMessage(m));
          console.log(JSON.stringify(formatted, null, 2));
        }
        break;
      }
      
      case 'read': {
        const messageId = parsed.positional[0];
        if (!messageId) {
          console.error('Error: Message ID required');
          console.error('Usage: node gmail.js read <messageId>');
          process.exit(1);
        }
        
        const message = client.getMessage(messageId, 'full');
        
        if (parsed.options.summary) {
          const formatted = GmailClient.formatMessage(message);
          console.log(`Subject: ${formatted.subject}`);
          console.log(`From: ${formatted.from}`);
          console.log(`Date: ${formatted.date}`);
          console.log(`Labels: ${formatted.labels.join(', ')}`);
          console.log(`\nContent:\n${message.snippet}`);
        } else {
          console.log(JSON.stringify(message, null, 2));
        }
        break;
      }
      
      case 'mark-read': {
        const messageIds = parsed.positional;
        if (messageIds.length === 0) {
          console.error('Error: At least one message ID required');
          console.error('Usage: node gmail.js mark-read <messageId1> [messageId2...]');
          process.exit(1);
        }
        
        const results = [];
        for (const messageId of messageIds) {
          try {
            client.markAsRead(messageId);
            results.push({ id: messageId, success: true });
            if (parsed.options.summary) {
              console.log(`Marked as read: ${messageId}`);
            }
          } catch (error) {
            results.push({ id: messageId, success: false, error: error.message });
            if (parsed.options.summary) {
              console.log(`Failed to mark as read: ${messageId} - ${error.message}`);
            }
          }
        }
        
        if (!parsed.options.summary) {
          console.log(JSON.stringify(results, null, 2));
        }
        break;
      }
      
      case 'mark-unread': {
        const messageId = parsed.positional[0];
        if (!messageId) {
          console.error('Error: Message ID required');
          console.error('Usage: node gmail.js mark-unread <messageId>');
          process.exit(1);
        }
        
        try {
          client.markAsUnread(messageId);
          if (parsed.options.summary) {
            console.log(`Marked as unread: ${messageId}`);
          } else {
            console.log(JSON.stringify({ success: true, messageId }, null, 2));
          }
        } catch (error) {
          if (parsed.options.summary) {
            console.log(`Failed to mark as unread: ${error.message}`);
          } else {
            console.log(JSON.stringify({ success: false, error: error.message }, null, 2));
          }
          process.exit(1);
        }
        break;
      }
      
      case 'trash': {
        const messageIds = parsed.positional;
        if (messageIds.length === 0) {
          console.error('Error: At least one message ID required');
          console.error('Usage: node gmail.js trash <messageId1> [messageId2...]');
          process.exit(1);
        }
        
        const results = [];
        for (const messageId of messageIds) {
          try {
            client.trashMessage(messageId);
            results.push({ id: messageId, success: true });
            if (parsed.options.summary) {
              console.log(`Moved to trash: ${messageId}`);
            }
          } catch (error) {
            results.push({ id: messageId, success: false, error: error.message });
            if (parsed.options.summary) {
              console.log(`Failed to trash: ${messageId} - ${error.message}`);
            }
          }
        }
        
        if (!parsed.options.summary) {
          console.log(JSON.stringify(results, null, 2));
        }
        break;
      }
      
      default:
        console.error(`Error: Unknown command '${parsed.command}'`);
        console.error('\nRun: node gmail.js help');
        process.exit(1);
    }
    
  } catch (error) {
    if (parsed.options.summary) {
      console.error(`Gmail Error: ${error.message}`);
      if (process.env.DEBUG) {
        console.error('Stack trace:', error.stack);
      }
    } else {
      console.error(JSON.stringify({
        error: error.message,
        status: error.status,
        data: error.data
      }, null, 2));
    }
    process.exit(1);
  }
}

// Execute
main();
