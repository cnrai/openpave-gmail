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
  
  // Get attachment metadata from a message
  getAttachment(messageId, attachmentId) {
    return this.request(`/users/me/messages/${messageId}/attachments/${attachmentId}`);
  }
  
  // Extract attachment info from message parts (recursive for multipart)
  static extractAttachments(parts, result) {
    result = result || [];
    if (!parts) return result;
    
    for (const part of parts) {
      if (part.filename && part.filename.length > 0) {
        result.push({
          partId: part.partId,
          filename: part.filename,
          mimeType: part.mimeType,
          size: part.body?.size || 0,
          attachmentId: part.body?.attachmentId || null
        });
      }
      // Recurse into nested parts (multipart/mixed, multipart/related, etc.)
      if (part.parts) {
        GmailClient.extractAttachments(part.parts, result);
      }
    }
    return result;
  }
  
  // Download attachment and return base64 data
  downloadAttachment(messageId, attachmentId) {
    const att = this.getAttachment(messageId, attachmentId);
    return att.data; // base64url encoded
  }
  
  // Create a draft
  createDraft(options) {
    const raw = GmailClient.buildRawMessage(options);
    const body = {
      message: { raw: raw }
    };
    if (options.threadId) {
      body.message.threadId = options.threadId;
    }
    return this.request('/users/me/drafts', {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }
  
  // Send a message directly
  sendMessage(options) {
    const raw = GmailClient.buildRawMessage(options);
    const body = { raw: raw };
    if (options.threadId) {
      body.threadId = options.threadId;
    }
    return this.request('/users/me/messages/send', {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }
  
  // List drafts
  listDrafts(options) {
    const paramData = {};
    if (options.maxResults) paramData.maxResults = options.maxResults;
    if (options.q) paramData.q = options.q;
    const queryString = Object.keys(paramData).length > 0 ? '?' + encodeFormData(paramData) : '';
    return this.request('/users/me/drafts' + queryString);
  }
  
  // Get a specific draft
  getDraft(draftId) {
    return this.request('/users/me/drafts/' + draftId + '?format=full');
  }
  
  // Send an existing draft
  sendDraft(draftId) {
    return this.request('/users/me/drafts/send', {
      method: 'POST',
      body: JSON.stringify({ id: draftId })
    });
  }
  
  // Delete a draft
  deleteDraft(draftId) {
    const url = this.baseUrl + '/users/me/drafts/' + draftId;
    const response = authenticatedFetch('gmail', url, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000
    });
    if (!response.ok && response.status !== 204) {
      const error = response.json();
      const err = new Error(error.error?.message || 'HTTP ' + response.status);
      err.status = response.status;
      throw err;
    }
    return { success: true };
  }
  
  // Build RFC 2822 raw message (base64url encoded)
  static buildRawMessage(options) {
    var lines = [];
    
    if (options.from) lines.push('From: ' + options.from);
    if (options.to) lines.push('To: ' + options.to);
    if (options.cc) lines.push('Cc: ' + options.cc);
    if (options.bcc) lines.push('Bcc: ' + options.bcc);
    if (options.subject) lines.push('Subject: ' + options.subject);
    if (options.inReplyTo) lines.push('In-Reply-To: ' + options.inReplyTo);
    if (options.references) lines.push('References: ' + options.references);
    
    lines.push('MIME-Version: 1.0');
    lines.push('Content-Type: text/plain; charset=UTF-8');
    lines.push('Content-Transfer-Encoding: 7bit');
    lines.push('');
    lines.push(options.body || '');
    
    var message = lines.join('\r\n');
    
    // Base64url encode
    var encoded = GmailClient.base64UrlEncode(message);
    return encoded;
  }
  
  // Base64url encode (sandbox compatible - no Buffer)
  static base64UrlEncode(str) {
    // Use btoa which is available in SpiderMonkey
    var b64 = btoa(unescape(encodeURIComponent(str)));
    // Convert to base64url: replace + with -, / with _, remove =
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  
  // Base64url decode
  static base64UrlDecode(str) {
    // Convert from base64url to base64
    var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    // Pad with =
    while (b64.length % 4 !== 0) b64 += '=';
    try {
      return decodeURIComponent(escape(atob(b64)));
    } catch (e) {
      // Binary data - return raw decoded
      return atob(b64);
    }
  }
  
  // Extract plain text body from message parts
  static extractBody(payload) {
    if (!payload) return '';
    
    // Simple message with body directly
    if (payload.body && payload.body.data) {
      return GmailClient.base64UrlDecode(payload.body.data);
    }
    
    // Multipart message - look for text/plain first, then text/html
    if (payload.parts) {
      // First pass: look for text/plain
      for (var i = 0; i < payload.parts.length; i++) {
        var part = payload.parts[i];
        if (part.mimeType === 'text/plain' && part.body && part.body.data) {
          return GmailClient.base64UrlDecode(part.body.data);
        }
      }
      // Second pass: recurse into multipart sub-parts
      for (var j = 0; j < payload.parts.length; j++) {
        var subPart = payload.parts[j];
        if (subPart.parts) {
          var body = GmailClient.extractBody(subPart);
          if (body) return body;
        }
      }
      // Third pass: fallback to text/html
      for (var k = 0; k < payload.parts.length; k++) {
        var htmlPart = payload.parts[k];
        if (htmlPart.mimeType === 'text/html' && htmlPart.body && htmlPart.body.data) {
          var html = GmailClient.base64UrlDecode(htmlPart.body.data);
          // Strip HTML tags for plain text display
          return html.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
        }
      }
    }
    
    return '';
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
  list [options]              List recent messages  
  unread [options]            Show unread messages
  read <messageId>            Read specific message (full body)
  mark-read <id1> [id2...]    Mark messages as read
  mark-unread <id>            Mark message as unread
  trash <id1> [id2...]        Move messages to trash
  attachments <messageId>     List attachments on a message
  download <messageId> <attachmentId>  Download an attachment
  draft [options]             Create a new draft email
  drafts [options]            List drafts
  send-draft <draftId>        Send an existing draft
  delete-draft <draftId>      Delete a draft
  send [options]              Send an email directly
  reply <messageId> [options] Reply to a message

OPTIONS:
  --max <number>              Maximum results (default: 10)
  --summary                   Human-readable output
  --json                      Raw JSON output
  --full                      Include full message content
  -q, --query <query>         Search query
  --to <email>                Recipient(s) (comma-separated)
  --cc <email>                CC recipient(s)
  --bcc <email>               BCC recipient(s)
  --subject <text>            Email subject
  --body <text>               Email body text
  --input <file>              Read body from file
  -o, --output <file>         Output file for downloads

EXAMPLES:
  node gmail.js profile --summary
  node gmail.js list --max 5 --summary
  node gmail.js unread --summary
  node gmail.js list -q "from:someone@example.com"
  node gmail.js read 1234567890abcdef
  node gmail.js attachments 1234567890abcdef
  node gmail.js download 1234567890abcdef ATT_ID -o /tmp/file.pdf
  node gmail.js draft --to "user@example.com" --subject "Hello" --body "Hi there"
  node gmail.js send --to "user@example.com" --subject "Hello" --body "Hi there"
  node gmail.js reply 1234567890abcdef --body "Thanks for your email"
  node gmail.js drafts --summary
  node gmail.js send-draft DRAFT_ID

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
        } else if (parsed.options.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          // Default: summary format
          console.log(`Gmail Account: ${result.emailAddress}`);
          console.log(`Total messages: ${result.messagesTotal}`);
          console.log(`Total threads: ${result.threadsTotal}`);
          console.log(`History ID: ${result.historyId}`);
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
          } else if (parsed.options.json) {
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }, null, 2));
          } else {
            console.log('No messages found.');
          }
          break;
        }
        
        if (parsed.options.json) {
          // JSON output requested - get full messages and format them
          const messages = client.getMessages(result.messages.map(m => m.id), 'full');
          
          // Check if sandbox issue is fixed via environment variable
          const sandboxFixed = process.env.PAVE_SANDBOX_FIXED === 'true';
          
          if (sandboxFixed) {
            // Future: When sandbox issue is fixed, output proper JSON array
            const formatted = messages.map(m => {
              if (m.error) return m;
              return GmailClient.formatMessage(m);
            });
            console.log(JSON.stringify(formatted, null, 2));
          } else {
            // Current: Output each message as separate JSON line to avoid sandbox conversion
            messages.forEach(m => {
              if (m.error) {
                console.log(JSON.stringify(m));
              } else {
                const msgData = GmailClient.formatMessage(m);
                const simplified = {
                  id: msgData.id,
                  threadId: msgData.threadId,
                  subject: msgData.subject,
                  from: msgData.from,
                  to: msgData.to,
                  date: msgData.date,
                  isUnread: msgData.isUnread,
                  labels: msgData.labels.join(','),
                  snippet: msgData.snippet
                };
                console.log(JSON.stringify(simplified));
              }
            });
          }
        } else {
          // Default: show detailed summary (either explicitly requested or default)
          const messages = client.getMessages(result.messages.map(m => m.id), 'full');
          printMessagesSummary(messages);
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
          } else if (parsed.options.json) {
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }, null, 2));
          } else {
            console.log('No unread messages - inbox is clear!');
          }
          break;
        }
        
        const messages = client.getMessages(result.messages.map(m => m.id), 'full');
        
        if (parsed.options.json) {
          const sandboxFixed = process.env.PAVE_SANDBOX_FIXED === 'true';
          
          if (sandboxFixed) {
            // Future: When sandbox issue is fixed, output proper JSON array
            const formatted = messages.map(m => {
              if (m.error) return m;
              return GmailClient.formatMessage(m);
            });
            console.log(JSON.stringify(formatted, null, 2));
          } else {
            // Current: Output each message as separate JSON line
            messages.forEach(m => {
              if (m.error) {
                console.log(JSON.stringify(m));
              } else {
                const msgData = GmailClient.formatMessage(m);
                const simplified = {
                  id: msgData.id,
                  threadId: msgData.threadId,
                  subject: msgData.subject,
                  from: msgData.from,
                  to: msgData.to,
                  date: msgData.date,
                  isUnread: msgData.isUnread,
                  labels: msgData.labels.join(','),
                  snippet: msgData.snippet
                };
                console.log(JSON.stringify(simplified));
              }
            });
          }
        } else {
          // Default: summary format (covers --summary flag and no flags)
          printMessagesSummary(messages);
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
        const formatted = GmailClient.formatMessage(message);
        const bodyText = GmailClient.extractBody(message.payload);
        const attachments = GmailClient.extractAttachments(message.payload?.parts);
        
        if (parsed.options.json) {
          console.log(JSON.stringify(message, null, 2));
        } else {
          console.log('Subject: ' + formatted.subject);
          console.log('From: ' + formatted.from);
          console.log('To: ' + formatted.to);
          console.log('Date: ' + formatted.date);
          console.log('Labels: ' + formatted.labels.join(', '));
          
          if (attachments.length > 0) {
            console.log('\nAttachments (' + attachments.length + '):');
            attachments.forEach(function(att, idx) {
              var sizeStr = att.size > 1024 ? Math.round(att.size / 1024) + 'KB' : att.size + 'B';
              console.log('  ' + (idx + 1) + '. ' + att.filename + ' (' + att.mimeType + ', ' + sizeStr + ')');
            });
          }
          
          console.log('\nContent:\n' + (bodyText || message.snippet));
        }
        break;
      }
      
      case 'attachments': {
        const messageId = parsed.positional[0];
        if (!messageId) {
          console.error('Error: Message ID required');
          console.error('Usage: node gmail.js attachments <messageId>');
          process.exit(1);
        }
        
        const message = client.getMessage(messageId, 'full');
        const formatted = GmailClient.formatMessage(message);
        const attachments = GmailClient.extractAttachments(message.payload?.parts);
        
        if (parsed.options.json) {
          console.log(JSON.stringify({ messageId: messageId, subject: formatted.subject, attachments: attachments }, null, 2));
        } else {
          console.log('Message: ' + formatted.subject);
          console.log('From: ' + formatted.from);
          console.log('');
          
          if (attachments.length === 0) {
            console.log('No attachments found.');
          } else {
            console.log('Attachments (' + attachments.length + '):');
            console.log('');
            attachments.forEach(function(att, idx) {
              var sizeStr = att.size > 1024 ? Math.round(att.size / 1024) + 'KB' : att.size + 'B';
              console.log('  ' + (idx + 1) + '. ' + att.filename);
              console.log('     Type: ' + att.mimeType + ' | Size: ' + sizeStr);
              console.log('     Attachment ID: ' + (att.attachmentId || 'inline'));
              console.log('');
            });
          }
        }
        break;
      }
      
      case 'download': {
        var msgId = parsed.positional[0];
        var attId = parsed.positional[1];
        
        if (!msgId || !attId) {
          console.error('Error: Message ID and Attachment ID required');
          console.error('Usage: node gmail.js download <messageId> <attachmentId> [-o output_file]');
          console.error('');
          console.error('Tip: Use "gmail.js attachments <messageId>" to find attachment IDs');
          process.exit(1);
        }
        
        var outputPath = parsed.options.o || parsed.options.output;
        
        // If no output path, get the filename from the message
        if (!outputPath) {
          var msg = client.getMessage(msgId, 'full');
          var atts = GmailClient.extractAttachments(msg.payload?.parts);
          var matchingAtt = null;
          for (var ai = 0; ai < atts.length; ai++) {
            if (atts[ai].attachmentId === attId) {
              matchingAtt = atts[ai];
              break;
            }
          }
          outputPath = '/tmp/' + (matchingAtt ? matchingAtt.filename : 'attachment_' + Date.now());
        }
        
        var data = client.downloadAttachment(msgId, attId);
        
        // Convert base64url to regular base64
        var b64 = data.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) b64 += '=';
        
        // Decode base64 to binary string and write as bytes
        var binary = atob(b64);
        var bytes = [];
        for (var bi = 0; bi < binary.length; bi++) {
          bytes.push(binary.charCodeAt(bi));
        }
        
        // Write binary data - use IPC if available, otherwise try fs
        var fs = require('fs');
        // Write as latin1/binary encoded string
        fs.writeFileSync(outputPath, binary, 'binary');
        
        if (parsed.options.json) {
          console.log(JSON.stringify({ success: true, path: outputPath, size: binary.length }));
        } else {
          console.log('Downloaded: ' + outputPath + ' (' + binary.length + ' bytes)');
        }
        break;
      }
      
      case 'draft': {
        var to = parsed.options.to;
        if (!to) {
          console.error('Error: --to is required');
          console.error('Usage: node gmail.js draft --to "user@example.com" --subject "Subject" --body "Body"');
          process.exit(1);
        }
        
        var draftBody = parsed.options.body || '';
        if (parsed.options.input) {
          var fs2 = require('fs');
          draftBody = fs2.readFileSync(parsed.options.input, 'utf8');
        }
        
        var draftOpts = {
          to: to,
          cc: parsed.options.cc || '',
          bcc: parsed.options.bcc || '',
          subject: parsed.options.subject || '',
          body: draftBody
        };
        
        // If replying as draft (--reply-to <messageId>)
        if (parsed.options['reply-to']) {
          var origMsg = client.getMessage(parsed.options['reply-to'], 'full');
          var origHeaders = origMsg.payload?.headers || [];
          var origMsgId = '';
          var origRefs = '';
          for (var hi = 0; hi < origHeaders.length; hi++) {
            if (origHeaders[hi].name === 'Message-ID' || origHeaders[hi].name === 'Message-Id') origMsgId = origHeaders[hi].value;
            if (origHeaders[hi].name === 'References') origRefs = origHeaders[hi].value;
          }
          draftOpts.inReplyTo = origMsgId;
          draftOpts.references = origRefs ? origRefs + ' ' + origMsgId : origMsgId;
          draftOpts.threadId = origMsg.threadId;
          
          if (!draftOpts.subject) {
            var origSubject = '';
            for (var si = 0; si < origHeaders.length; si++) {
              if (origHeaders[si].name === 'Subject') origSubject = origHeaders[si].value;
            }
            if (origSubject && !origSubject.match(/^Re:/i)) {
              draftOpts.subject = 'Re: ' + origSubject;
            } else {
              draftOpts.subject = origSubject;
            }
          }
        }
        
        var draft = client.createDraft(draftOpts);
        
        if (parsed.options.json) {
          console.log(JSON.stringify(draft, null, 2));
        } else {
          console.log('Draft created successfully');
          console.log('  Draft ID: ' + draft.id);
          console.log('  Message ID: ' + (draft.message?.id || 'N/A'));
          console.log('  To: ' + to);
          console.log('  Subject: ' + (draftOpts.subject || '(no subject)'));
        }
        break;
      }
      
      case 'drafts': {
        var draftsList = client.listDrafts({
          maxResults: parseInt(parsed.options.max) || 10,
          q: parsed.options.q || parsed.options.query
        });
        
        if (!draftsList.drafts || draftsList.drafts.length === 0) {
          console.log('No drafts found.');
          break;
        }
        
        if (parsed.options.json) {
          // Get full details for each draft
          var fullDrafts = [];
          for (var di = 0; di < draftsList.drafts.length; di++) {
            try {
              var d = client.getDraft(draftsList.drafts[di].id);
              fullDrafts.push(d);
            } catch (e) {
              fullDrafts.push({ id: draftsList.drafts[di].id, error: e.message });
            }
          }
          console.log(JSON.stringify(fullDrafts, null, 2));
        } else {
          console.log('Found ' + draftsList.drafts.length + ' draft(s):\n');
          for (var dj = 0; dj < draftsList.drafts.length; dj++) {
            try {
              var draftDetail = client.getDraft(draftsList.drafts[dj].id);
              var draftFormatted = GmailClient.formatMessage(draftDetail.message);
              console.log((dj + 1) + '. ' + draftFormatted.subject);
              console.log('   To: ' + draftFormatted.to);
              console.log('   Draft ID: ' + draftsList.drafts[dj].id);
              console.log('');
            } catch (e) {
              console.log((dj + 1) + '. [Error loading draft: ' + e.message + ']');
              console.log('');
            }
          }
        }
        break;
      }
      
      case 'send-draft': {
        var draftId = parsed.positional[0];
        if (!draftId) {
          console.error('Error: Draft ID required');
          console.error('Usage: node gmail.js send-draft <draftId>');
          process.exit(1);
        }
        
        var sentResult = client.sendDraft(draftId);
        
        if (parsed.options.json) {
          console.log(JSON.stringify(sentResult, null, 2));
        } else {
          console.log('Draft sent successfully!');
          console.log('  Message ID: ' + (sentResult.id || 'N/A'));
          console.log('  Thread ID: ' + (sentResult.threadId || 'N/A'));
        }
        break;
      }
      
      case 'delete-draft': {
        var delDraftId = parsed.positional[0];
        if (!delDraftId) {
          console.error('Error: Draft ID required');
          console.error('Usage: node gmail.js delete-draft <draftId>');
          process.exit(1);
        }
        
        client.deleteDraft(delDraftId);
        
        if (parsed.options.json) {
          console.log(JSON.stringify({ success: true, draftId: delDraftId }));
        } else {
          console.log('Draft deleted: ' + delDraftId);
        }
        break;
      }
      
      case 'send': {
        var sendTo = parsed.options.to;
        if (!sendTo) {
          console.error('Error: --to is required');
          console.error('Usage: node gmail.js send --to "user@example.com" --subject "Subject" --body "Body"');
          process.exit(1);
        }
        
        var sendBody = parsed.options.body || '';
        if (parsed.options.input) {
          var fs3 = require('fs');
          sendBody = fs3.readFileSync(parsed.options.input, 'utf8');
        }
        
        var sendOpts = {
          to: sendTo,
          cc: parsed.options.cc || '',
          bcc: parsed.options.bcc || '',
          subject: parsed.options.subject || '',
          body: sendBody
        };
        
        var sent = client.sendMessage(sendOpts);
        
        if (parsed.options.json) {
          console.log(JSON.stringify(sent, null, 2));
        } else {
          console.log('Email sent successfully!');
          console.log('  Message ID: ' + (sent.id || 'N/A'));
          console.log('  Thread ID: ' + (sent.threadId || 'N/A'));
          console.log('  To: ' + sendTo);
          console.log('  Subject: ' + (sendOpts.subject || '(no subject)'));
        }
        break;
      }
      
      case 'reply': {
        var replyMsgId = parsed.positional[0];
        if (!replyMsgId) {
          console.error('Error: Message ID required');
          console.error('Usage: node gmail.js reply <messageId> --body "Reply text"');
          process.exit(1);
        }
        
        var replyBodyText = parsed.options.body || '';
        if (parsed.options.input) {
          var fs4 = require('fs');
          replyBodyText = fs4.readFileSync(parsed.options.input, 'utf8');
        }
        
        if (!replyBodyText) {
          console.error('Error: --body or --input is required');
          process.exit(1);
        }
        
        // Get original message for threading headers
        var origMessage = client.getMessage(replyMsgId, 'full');
        var replyHeaders = origMessage.payload?.headers || [];
        var origMessageId = '';
        var origReferences = '';
        var origSubject2 = '';
        var origFrom = '';
        var origTo2 = '';
        
        for (var rhi = 0; rhi < replyHeaders.length; rhi++) {
          var hdr = replyHeaders[rhi];
          if (hdr.name === 'Message-ID' || hdr.name === 'Message-Id') origMessageId = hdr.value;
          if (hdr.name === 'References') origReferences = hdr.value;
          if (hdr.name === 'Subject') origSubject2 = hdr.value;
          if (hdr.name === 'From') origFrom = hdr.value;
          if (hdr.name === 'To') origTo2 = hdr.value;
        }
        
        // Determine reply-to address
        var replyTo = parsed.options.to || origFrom;
        var replyCc = parsed.options.cc || '';
        
        // Build subject
        var replySubject = parsed.options.subject || '';
        if (!replySubject) {
          if (origSubject2 && !origSubject2.match(/^Re:/i)) {
            replySubject = 'Re: ' + origSubject2;
          } else {
            replySubject = origSubject2;
          }
        }
        
        var replyOpts = {
          to: replyTo,
          cc: replyCc,
          bcc: parsed.options.bcc || '',
          subject: replySubject,
          body: replyBodyText,
          inReplyTo: origMessageId,
          references: origReferences ? origReferences + ' ' + origMessageId : origMessageId,
          threadId: origMessage.threadId
        };
        
        // Send or create as draft
        var replyResult;
        if (parsed.options.draft) {
          replyResult = client.createDraft(replyOpts);
          if (parsed.options.json) {
            console.log(JSON.stringify(replyResult, null, 2));
          } else {
            console.log('Reply draft created');
            console.log('  Draft ID: ' + replyResult.id);
            console.log('  To: ' + replyTo);
            console.log('  Subject: ' + replySubject);
          }
        } else {
          replyResult = client.sendMessage(replyOpts);
          if (parsed.options.json) {
            console.log(JSON.stringify(replyResult, null, 2));
          } else {
            console.log('Reply sent!');
            console.log('  Message ID: ' + (replyResult.id || 'N/A'));
            console.log('  To: ' + replyTo);
            console.log('  Subject: ' + replySubject);
          }
        }
        break;
      }
      
      case 'mark-read': {
        var markReadIds = parsed.positional;
        if (markReadIds.length === 0) {
          console.error('Error: At least one message ID required');
          console.error('Usage: node gmail.js mark-read <messageId1> [messageId2...]');
          process.exit(1);
        }
        
        var markReadResults = [];
        for (var mri = 0; mri < markReadIds.length; mri++) {
          try {
            client.markAsRead(markReadIds[mri]);
            markReadResults.push({ id: markReadIds[mri], success: true });
            if (!parsed.options.json) {
              console.log('Marked as read: ' + markReadIds[mri]);
            }
          } catch (error) {
            markReadResults.push({ id: markReadIds[mri], success: false, error: error.message });
            if (!parsed.options.json) {
              console.log('Failed to mark as read: ' + markReadIds[mri] + ' - ' + error.message);
            }
          }
        }
        
        if (parsed.options.json) {
          console.log(JSON.stringify(markReadResults, null, 2));
        }
        break;
      }
      
      case 'mark-unread': {
        var markUnreadId = parsed.positional[0];
        if (!markUnreadId) {
          console.error('Error: Message ID required');
          console.error('Usage: node gmail.js mark-unread <messageId>');
          process.exit(1);
        }
        
        try {
          client.markAsUnread(markUnreadId);
          if (parsed.options.json) {
            console.log(JSON.stringify({ success: true, messageId: markUnreadId }, null, 2));
          } else {
            console.log('Marked as unread: ' + markUnreadId);
          }
        } catch (error) {
          if (parsed.options.json) {
            console.log(JSON.stringify({ success: false, error: error.message }, null, 2));
          } else {
            console.log('Failed to mark as unread: ' + error.message);
          }
          process.exit(1);
        }
        break;
      }
      
      case 'trash': {
        var trashIds = parsed.positional;
        if (trashIds.length === 0) {
          console.error('Error: At least one message ID required');
          console.error('Usage: node gmail.js trash <messageId1> [messageId2...]');
          process.exit(1);
        }
        
        var trashResults = [];
        for (var tri = 0; tri < trashIds.length; tri++) {
          try {
            client.trashMessage(trashIds[tri]);
            trashResults.push({ id: trashIds[tri], success: true });
            if (!parsed.options.json) {
              console.log('Moved to trash: ' + trashIds[tri]);
            }
          } catch (error) {
            trashResults.push({ id: trashIds[tri], success: false, error: error.message });
            if (!parsed.options.json) {
              console.log('Failed to trash: ' + trashIds[tri] + ' - ' + error.message);
            }
          }
        }
        
        if (parsed.options.json) {
          console.log(JSON.stringify(trashResults, null, 2));
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
    } else if (parsed.options.json) {
      console.error(JSON.stringify({
        error: error.message,
        status: error.status,
        data: error.data
      }, null, 2));
    } else {
      console.error(`Gmail Error: ${error.message}`);
      if (process.env.DEBUG) {
        console.error('Stack trace:', error.stack);
      }
    }
    process.exit(1);
  }
}

// Execute
main();
