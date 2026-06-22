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

// ── PAVE Auth Proxy (replaces deprecated authenticatedFetch global) ──
// Direct HTTP calls to the PAVE auth proxy at /proxy/:tokenName/*path
var PAVE_PROXY_BASE = process.env.PAVE_PROXY_URL || '';

function _shellQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function proxyHasToken(tokenName) {
  if (!PAVE_PROXY_BASE) return false;
  try {
    var url = PAVE_PROXY_BASE.replace(/\/$/, '') + '/_tokens/' + encodeURIComponent(tokenName);
    var out = require('child_process').execSync(
      'curl -sS --max-time 5 ' + _shellQuote(url),
      { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    var r = JSON.parse(out);
    return r.has === true;
  } catch (e) {
    return false;
  }
}

function proxyFetch(tokenName, url, options) {
  options = options || {};
  if (!PAVE_PROXY_BASE) {
    throw new Error('PAVE_PROXY_URL not set - cannot reach auth proxy');
  }

  // Build proxy URL: strip origin from upstream URL, prepend proxy base
  var parsed = new URL(url);
  var proxyUrl = PAVE_PROXY_BASE.replace(/\/$/, '') + '/' + encodeURIComponent(tokenName) + parsed.pathname + parsed.search;

  // _mode=json: proxy returns { ok, status, headers, body } for sync parsing
  proxyUrl += (proxyUrl.indexOf('?') !== -1 ? '&' : '?') + '_mode=json';

  // _saveTo: binary-safe file download (proxy writes response to file)
  if (options.saveTo) {
    proxyUrl += '&_saveTo=' + encodeURIComponent(options.saveTo);
  }

  // Build curl command for synchronous HTTP
  var method = options.method || 'GET';
  var timeout = options.timeout || 30000;
  var cmd = 'curl -sS -X ' + method + ' --max-time ' + Math.ceil(timeout / 1000);

  var headers = Object.assign({}, options.headers || {});
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  for (var k in headers) {
    cmd += ' -H ' + _shellQuote(k + ': ' + headers[k]);
  }

  if (options.body) {
    var bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
    cmd += ' -d ' + _shellQuote(bodyStr);
  }

  cmd += ' ' + _shellQuote(proxyUrl);

  // Execute synchronously
  var out;
  try {
    out = require('child_process').execSync(cmd, {
      encoding: 'utf8',
      timeout: timeout + 5000,
      maxBuffer: 10 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    var stdout = err.stdout ? err.stdout.toString() : '';
    var stderr = err.stderr ? err.stderr.toString() : '';
    if (stdout) {
      out = stdout;
    } else {
      throw new Error('Proxy request failed: ' + (stderr.trim() || err.message));
    }
  }

  // Parse _mode=json response
  var resp;
  try {
    resp = JSON.parse(out);
  } catch (e) {
    return {
      ok: true, status: 200,
      headers: { get: function() { return null; } },
      text: function() { return out; },
      json: function() { return JSON.parse(out || '{}'); }
    };
  }

  if (resp.error) throw new Error(resp.error);

  // saveTo response: { ok, status, savedTo, size }
  if (resp.savedTo) {
    return {
      ok: resp.ok || false, status: resp.status || 200, savedTo: resp.savedTo,
      headers: { get: function() { return null; } },
      text: function() { return ''; },
      json: function() { return {}; }
    };
  }

  // Normal response: { ok, status, headers, body }
  return {
    ok: resp.ok || false, status: resp.status || 200,
    headers: {
      get: function(name) {
        var hs = resp.headers || {};
        var ln = name.toLowerCase();
        for (var key in hs) {
          if (key.toLowerCase() === ln) return Array.isArray(hs[key]) ? hs[key][0] : hs[key];
        }
        return null;
      }
    },
    text: function() { return resp.body || ''; },
    json: function() { return JSON.parse(resp.body || '{}'); }
  };
}

// Gmail Client Class - Uses secure token system
class GmailClient {
  constructor() {
    // Check if gmail token is available via secure token system
    if (!proxyHasToken('gmail')) {
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
    
    // Use proxyFetch - token injection and OAuth refresh handled by auth proxy
    const response = proxyFetch('gmail', url, {
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
      err.code = error.error?.code || null;
      err.data = error;
      
      // Provide more helpful messages for common errors
      if (response.status === 404) {
        err.message = 'Message not found - it may have been deleted or moved';
      }
      
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
  
  // Get all messages in a thread
  getThread(threadId, format) {
    var paramData = {};
    if (format) paramData.format = format;
    var queryString = Object.keys(paramData).length > 0 ? '?' + encodeFormData(paramData) : '';
    return this.request('/users/me/threads/' + threadId + queryString);
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
    const response = proxyFetch('gmail', url, {
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
  // Supports optional file attachments via options.attachments array
  // Each attachment: { filename, mimeType, content (Buffer or base64 string) }
  static buildRawMessage(options) {
    var headerLines = [];
    
    if (options.from) headerLines.push('From: ' + options.from);
    if (options.to) headerLines.push('To: ' + options.to);
    if (options.cc) headerLines.push('Cc: ' + options.cc);
    if (options.bcc) headerLines.push('Bcc: ' + options.bcc);
    if (options.subject) headerLines.push('Subject: ' + options.subject);
    if (options.inReplyTo) headerLines.push('In-Reply-To: ' + options.inReplyTo);
    if (options.references) headerLines.push('References: ' + options.references);
    
    headerLines.push('MIME-Version: 1.0');
    
    // Convert plain text to HTML if the body doesn't already contain HTML tags
    var bodyText = options.body || '';
    if (!bodyText.match(/<[a-z][\s\S]*>/i)) {
      // Escape HTML entities, then convert newlines to <br>
      bodyText = bodyText
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>\n');
      bodyText = '<p>' + bodyText + '</p>';
    }
    
    var hasAttachments = options.attachments && options.attachments.length > 0;
    var message;
    
    if (!hasAttachments) {
      // Simple single-part message (no attachments)
      headerLines.push('Content-Type: text/html; charset=UTF-8');
      headerLines.push('Content-Transfer-Encoding: 7bit');
      headerLines.push('');
      headerLines.push(bodyText);
      message = headerLines.join('\r\n');
    } else {
      // Multipart MIME message with attachments
      var boundary = 'pave_boundary_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      headerLines.push('Content-Type: multipart/mixed; boundary="' + boundary + '"');
      headerLines.push('');
      headerLines.push('--' + boundary);
      headerLines.push('Content-Type: text/html; charset=UTF-8');
      headerLines.push('Content-Transfer-Encoding: 7bit');
      headerLines.push('');
      headerLines.push(bodyText);
      
      // Add each attachment
      for (var ai = 0; ai < options.attachments.length; ai++) {
        var att = options.attachments[ai];
        var attBase64 = att.base64 || '';
        
        // Split base64 into 76-char lines per RFC 2045
        var wrappedBase64 = attBase64.match(/.{1,76}/g).join('\r\n');
        
        headerLines.push('');
        headerLines.push('--' + boundary);
        headerLines.push('Content-Type: ' + (att.mimeType || 'application/octet-stream') + '; name="' + att.filename + '"');
        headerLines.push('Content-Disposition: attachment; filename="' + att.filename + '"');
        headerLines.push('Content-Transfer-Encoding: base64');
        headerLines.push('');
        headerLines.push(wrappedBase64);
      }
      
      headerLines.push('');
      headerLines.push('--' + boundary + '--');
      message = headerLines.join('\r\n');
    }
    
    // Base64url encode the entire message
    var encoded = GmailClient.base64UrlEncode(message);
    return encoded;
  }
  
  // Base64url encode (sandbox compatible)
  static base64UrlEncode(str) {
    // Use Buffer (Node.js) first, fall back to manual encoding
    var b64;
    if (typeof Buffer !== 'undefined') {
      b64 = Buffer.from(str, 'utf-8').toString('base64');
    } else if (typeof btoa !== 'undefined') {
      b64 = btoa(unescape(encodeURIComponent(str)));
    } else {
      // Manual base64 encode for environments without Buffer or btoa
      var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      var bytes = unescape(encodeURIComponent(str));
      var result = '';
      for (var i = 0; i < bytes.length; i += 3) {
        var b1 = bytes.charCodeAt(i);
        var b2 = i + 1 < bytes.length ? bytes.charCodeAt(i + 1) : 0;
        var b3 = i + 2 < bytes.length ? bytes.charCodeAt(i + 2) : 0;
        result += chars.charAt(b1 >> 2);
        result += chars.charAt(((b1 & 3) << 4) | (b2 >> 4));
        result += i + 1 < bytes.length ? chars.charAt(((b2 & 15) << 2) | (b3 >> 6)) : '=';
        result += i + 2 < bytes.length ? chars.charAt(b3 & 63) : '=';
      }
      b64 = result;
    }
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
      // For text, try to decode as UTF-8
      return decodeURIComponent(escape(GmailClient.base64DecodeBinary(b64)));
    } catch (e) {
      // Binary data - return raw decoded
      return GmailClient.base64DecodeBinary(b64);
    }
  }
  
  // Base64 decode for binary data (sandbox compatible)
  static base64DecodeBinary(str) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    let i = 0;
    
    // Remove padding
    str = str.replace(/=/g, '');
    
    while (i < str.length) {
      const a = chars.indexOf(str.charAt(i++));
      const b = chars.indexOf(str.charAt(i++));
      const c = chars.indexOf(str.charAt(i++));
      const d = chars.indexOf(str.charAt(i++));
      
      const bitmap = (a << 18) | (b << 12) | (c << 6) | d;
      
      result += String.fromCharCode((bitmap >> 16) & 255);
      if (c !== -1) result += String.fromCharCode((bitmap >> 8) & 255);
      if (d !== -1) result += String.fromCharCode(bitmap & 255);
    }
    
    return result;
  }
  
  // Guess MIME type from filename extension
  static guessMimeType(filename) {
    var ext = (filename || '').split('.').pop().toLowerCase();
    var types = {
      'pdf': 'application/pdf',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'ppt': 'application/vnd.ms-powerpoint',
      'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
      'svg': 'image/svg+xml',
      'webp': 'image/webp',
      'mp4': 'video/mp4',
      'mp3': 'audio/mpeg',
      'wav': 'audio/wav',
      'zip': 'application/zip',
      'gz': 'application/gzip',
      'tar': 'application/x-tar',
      'txt': 'text/plain',
      'csv': 'text/csv',
      'html': 'text/html',
      'json': 'application/json',
      'xml': 'application/xml'
    };
    return types[ext] || 'application/octet-stream';
  }
  
  // Load file attachment from path, returns { filename, mimeType, content (Buffer) }
  static loadAttachment(filePath) {
    var fs = require('fs');
    var path = require('path');
    
    if (!fs.existsSync(filePath)) {
      throw new Error('Attachment file not found: ' + filePath);
    }
    
    var stat = fs.statSync(filePath);
    // Gmail API limit: ~25 MB for the entire message including base64 overhead
    // Warn if file is over 20 MB (base64 adds ~33% overhead)
    if (stat.size > 20 * 1024 * 1024) {
      throw new Error('Attachment too large (' + Math.round(stat.size / 1024 / 1024) + ' MB). Gmail limit is ~25 MB total message size. Use Google Drive for large files.');
    }
    
    var filename = path.basename(filePath);
    var mimeType = GmailClient.guessMimeType(filename);
    // Read file as base64 directly — avoids Buffer/binary issues in sandbox
    var base64Content;
    try {
      // Try reading as buffer and converting to base64
      var rawContent = fs.readFileSync(filePath);
      if (rawContent && typeof rawContent.toString === 'function') {
        base64Content = rawContent.toString('base64');
      } else {
        throw new Error('Cannot convert to base64');
      }
    } catch (e) {
      // Fallback: use system command to base64 encode
      throw new Error('Failed to read attachment: ' + e.message);
    }
    
    return { filename: filename, mimeType: mimeType, base64: base64Content };
  }
  
  // Extract HTML body from message parts (for quoting in replies)
  static extractHtmlBody(payload) {
    if (!payload) return '';
    
    // Simple message with body directly
    if (payload.body && payload.body.data) {
      // Check if it's HTML
      if (payload.mimeType === 'text/html') {
        return GmailClient.base64UrlDecode(payload.body.data);
      }
      // Plain text - wrap in basic HTML
      var text = GmailClient.base64UrlDecode(payload.body.data);
      return '<p>' + text.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>') + '</p>';
    }
    
    // Multipart - look for text/html first
    if (payload.parts) {
      for (var i = 0; i < payload.parts.length; i++) {
        var part = payload.parts[i];
        if (part.mimeType === 'text/html' && part.body && part.body.data) {
          return GmailClient.base64UrlDecode(part.body.data);
        }
      }
      // Recurse into multipart sub-parts
      for (var j = 0; j < payload.parts.length; j++) {
        var subPart = payload.parts[j];
        if (subPart.parts) {
          var html = GmailClient.extractHtmlBody(subPart);
          if (html) return html;
        }
      }
      // Fallback to text/plain wrapped in HTML
      for (var k = 0; k < payload.parts.length; k++) {
        var plainPart = payload.parts[k];
        if (plainPart.mimeType === 'text/plain' && plainPart.body && plainPart.body.data) {
          var plainText = GmailClient.base64UrlDecode(plainPart.body.data);
          return '<p>' + plainText.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>') + '</p>';
        }
      }
    }
    
    return '';
  }
  
  // Extract plain text body from message parts
  static extractBody(payload) {
    if (!payload) return '';
    
    // Simple message with body directly
    if (payload.body && payload.body.data) {
      var rawBody = GmailClient.base64UrlDecode(payload.body.data);
      // Clean HTML if mimeType is text/html or content looks like HTML
      if (payload.mimeType === 'text/html') {
        return GmailClient.htmlToText(rawBody);
      }
      var trimmedBody = rawBody.trimLeft();
      if (trimmedBody.charAt(0) === '<' && /<(html|!doctype|head|body|style|table|div)\b/i.test(trimmedBody)) {
        return GmailClient.htmlToText(rawBody);
      }
      return rawBody;
    }
    
    // Multipart message - look for text/plain first, then text/html
    if (payload.parts) {
      // First pass: look for text/plain
      for (var i = 0; i < payload.parts.length; i++) {
        var part = payload.parts[i];
        if (part.mimeType === 'text/plain' && part.body && part.body.data) {
          var plainText = GmailClient.base64UrlDecode(part.body.data);
          // Some senders (e.g. Wrike) put raw HTML in text/plain parts — detect and clean
          var trimmed = plainText.trimLeft();
          if (trimmed.charAt(0) === '<' && /<(html|!doctype|head|body|style|table|div)\b/i.test(trimmed)) {
            return GmailClient.htmlToText(plainText);
          }
          return plainText;
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
          return GmailClient.htmlToText(html);
        }
      }
    }
    
    return '';
  }

  // Convert HTML to clean plain text (strips style/script/head, preserves line breaks)
  static htmlToText(html) {
    if (!html) return '';
    var text = html;
    // Remove entire blocks that should never appear as text
    text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
    text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    text = text.replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '');
    text = text.replace(/<title[^>]*>[\s\S]*?<\/title>/gi, '');
    text = text.replace(/<!--[\s\S]*?-->/g, '');
    // Convert block-level tags to newlines before stripping
    text = text.replace(/<\/?(p|div|br|tr|li|h[1-6])[^>]*>/gi, '\n');
    text = text.replace(/<td[^>]*>/gi, '\t');
    // Strip all remaining HTML tags
    text = text.replace(/<[^>]+>/g, '');
    // Decode common HTML entities
    text = text.replace(/&nbsp;/g, ' ');
    text = text.replace(/&amp;/g, '&');
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&apos;/g, "'");
    text = text.replace(/&hellip;/g, '...');
    text = text.replace(/&mdash;/g, '\u2014');
    text = text.replace(/&ndash;/g, '\u2013');
    text = text.replace(/&#(\d+);/g, function(m, code) { return String.fromCharCode(parseInt(code, 10)); });
    // Collapse runs of spaces/tabs (preserve newlines)
    text = text.replace(/[ \t]+/g, ' ');
    // Remove whitespace-only lines (common in HTML table layouts)
    text = text.replace(/\n[ \t]+\n/g, '\n\n');
    // Remove trailing spaces on each line
    text = text.replace(/ +\n/g, '\n');
    // Remove lines that are empty or whitespace-only
    text = text.split('\n').filter(function(line) { return line.trim() !== ''; }).join('\n');
    // Trim leading/trailing whitespace
    return text.trim();
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
  --attach <file>             Attach file(s), comma-separated for multiple

EXAMPLES:
  node gmail.js profile --summary
  node gmail.js list --max 5 --summary
  node gmail.js unread --summary
  node gmail.js list -q "from:someone@example.com"
  node gmail.js read 1234567890abcdef
  node gmail.js attachments 1234567890abcdef
  node gmail.js download 1234567890abcdef ATT_ID -o /tmp/file.pdf
  node gmail.js draft --to "user@example.com" --subject "Hello" --body "Hi there"
  node gmail.js draft --to "user@example.com" --subject "Hello" --body "Hi" --attach /tmp/file.pdf
  node gmail.js send --to "user@example.com" --subject "Hello" --body "Hi there"
  node gmail.js send --to "user@example.com" --body "See attached" --attach /tmp/a.pdf,/tmp/b.png
  node gmail.js reply 1234567890abcdef --body "Thanks for your email"
  node gmail.js reply 1234567890abcdef --body "See attached" --attach /tmp/report.pdf
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
        } else {
          console.log(JSON.stringify(result));
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
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }));
          }
          break;
        }
        
        const messages = client.getMessages(result.messages.map(m => m.id), 'full');
        const formatted = messages.map(m => {
          if (m.error) return m;
          return GmailClient.formatMessage(m);
        });
        
        if (parsed.options.summary) {
          printMessagesSummary(messages);
        } else {
          console.log(JSON.stringify(formatted));
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
            console.log(JSON.stringify({ messages: [], resultSizeEstimate: 0 }));
          }
          break;
        }
        
        const messages = client.getMessages(result.messages.map(m => m.id), 'full');
        const formatted = messages.map(m => {
          if (m.error) return m;
          return GmailClient.formatMessage(m);
        });
        
        if (parsed.options.summary) {
          printMessagesSummary(messages);
        } else {
          console.log(JSON.stringify(formatted));
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
        
        let message;
        try {
          message = client.getMessage(messageId, 'full');
        } catch (error) {
          if (error.status === 404) {
            console.error('[ERROR] Message not found: ' + messageId);
            console.error('The message may have been deleted, moved to trash, or the ID is invalid.');
            process.exit(1);
          }
          throw error;
        }
        
        const formatted = GmailClient.formatMessage(message);
        const bodyText = GmailClient.extractBody(message.payload);
        const attachments = GmailClient.extractAttachments(message.payload?.parts);
        
        // Write full content to file to avoid context explosion
        // LLM can use the read tool with offset/limit (40 lines/page) to paginate
        var fs_read = require('fs');
        var filePath = '/tmp/gmail_msg_' + messageId + '.md';
        var fullContent = '';
        fullContent += 'Subject: ' + formatted.subject + '\n';
        fullContent += 'From: ' + formatted.from + '\n';
        fullContent += 'To: ' + formatted.to + '\n';
        fullContent += 'Date: ' + formatted.date + '\n';
        fullContent += 'Labels: ' + formatted.labels.join(', ') + '\n';
        if (attachments.length > 0) {
          fullContent += '\nAttachments (' + attachments.length + '):\n';
          attachments.forEach(function(att, idx) {
            var sizeStr = att.size > 1024 ? Math.round(att.size / 1024) + 'KB' : att.size + 'B';
            fullContent += (idx + 1) + '. ' + att.filename + ' (' + att.mimeType + ', ' + sizeStr + ')\n';
          });
        }
        fullContent += '\n---\n\n' + (bodyText || message.snippet || '');
        fs_read.writeFileSync(filePath, fullContent, 'utf8');
        var lineCount = fullContent.split('\n').length;
        
        if (parsed.options.summary) {
          console.log('Subject: ' + formatted.subject);
          console.log('From: ' + formatted.from);
          console.log('Date: ' + formatted.date);
          if (attachments.length > 0) {
            console.log('Attachments (' + attachments.length + '):');
            attachments.forEach(function(att, idx) {
              console.log('  ' + (idx + 1) + '. ' + att.filename);
            });
          }
          console.log('');
          console.log('Full content (' + lineCount + ' lines) written to: ' + filePath);
        } else {
          // JSON mode (default) - compact reference with file path
          console.log(JSON.stringify({
            messageId: messageId,
            threadId: formatted.threadId,
            subject: formatted.subject,
            from: formatted.from,
            to: formatted.to,
            date: formatted.date,
            labels: formatted.labels,
            snippet: formatted.snippet,
            isUnread: formatted.isUnread,
            attachments: attachments.map(function(a) {
              return { filename: a.filename, mimeType: a.mimeType, size: a.size, attachmentId: a.attachmentId };
            }),
            contentFile: filePath,
            contentLines: lineCount
          }));
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
        
        if (parsed.options.summary) {
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
        } else {
          console.log(JSON.stringify({ messageId: messageId, subject: formatted.subject, attachments: attachments }));
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
        
        // Use custom base64 decode for binary data
        var binary = GmailClient.base64DecodeBinary(b64);
        
        // Write binary data
        var fs = require('fs');
        fs.writeFileSync(outputPath, binary, 'binary');
        
        if (parsed.options.summary) {
          console.log('Downloaded: ' + outputPath + ' (' + binary.length + ' bytes)');
        } else {
          console.log(JSON.stringify({ success: true, path: outputPath, size: binary.length }));
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
        
        // Handle file attachments (--attach path1,path2,... or --attach path)
        if (parsed.options.attach) {
          var attachPaths = parsed.options.attach.split(',');
          draftOpts.attachments = [];
          for (var api = 0; api < attachPaths.length; api++) {
            var att = GmailClient.loadAttachment(attachPaths[api].trim());
            draftOpts.attachments.push(att);
          }
        }
        
        // If replying as draft (--reply-to <messageId>)
        if (parsed.options['reply-to']) {
          var origMsg = client.getMessage(parsed.options['reply-to'], 'full');
          var origHeaders = origMsg.payload?.headers || [];
          var origMsgId = '';
          var origRefs = '';
          var origFrom = '';
          var origDate = '';
          for (var hi = 0; hi < origHeaders.length; hi++) {
            if (origHeaders[hi].name === 'Message-ID' || origHeaders[hi].name === 'Message-Id') origMsgId = origHeaders[hi].value;
            if (origHeaders[hi].name === 'References') origRefs = origHeaders[hi].value;
            if (origHeaders[hi].name === 'From') origFrom = origHeaders[hi].value;
            if (origHeaders[hi].name === 'Date') origDate = origHeaders[hi].value;
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
          
          // Convert reply text to HTML before appending quoted thread
          // (must happen here so buildRawMessage sees the full body as HTML)
          var replyHtml = draftBody;
          if (!replyHtml.match(/<[a-z][\s\S]*>/i)) {
            replyHtml = replyHtml
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/\n\n/g, '</p><p>')
              .replace(/\n/g, '<br>\n');
            replyHtml = '<p>' + replyHtml + '</p>';
          }
          
          // Append quoted original message (same as reply command)
          var origHtml = GmailClient.extractHtmlBody(origMsg.payload);
          if (origHtml) {
            var quotedThread = '<br><br><div class="gmail_quote">' +
              '<div dir="ltr" class="gmail_attr">On ' + (origDate || 'unknown date') + ', ' + (origFrom || 'unknown sender') + ' wrote:<br></div>' +
              '<blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">' +
              origHtml +
              '</blockquote></div>';
            draftOpts.body = replyHtml + quotedThread;
          } else {
            draftOpts.body = replyHtml;
          }
        }
        
        var draft = client.createDraft(draftOpts);
        
        if (parsed.options.summary) {
          console.log('Draft created successfully');
          console.log('  Draft ID: ' + draft.id);
          console.log('  Message ID: ' + (draft.message?.id || 'N/A'));
          console.log('  To: ' + to);
          console.log('  Subject: ' + (draftOpts.subject || '(no subject)'));
        } else {
          console.log(JSON.stringify(draft));
        }
        break;
      }
      
      case 'drafts': {
        var draftsList = client.listDrafts({
          maxResults: parseInt(parsed.options.max) || 10,
          q: parsed.options.q || parsed.options.query
        });
        
        if (!draftsList.drafts || draftsList.drafts.length === 0) {
          if (parsed.options.summary) {
            console.log('No drafts found.');
          } else {
            console.log(JSON.stringify({ drafts: [] }));
          }
          break;
        }
        
        if (parsed.options.summary) {
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
        } else {
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
          console.log(JSON.stringify(fullDrafts));
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
        
        if (parsed.options.summary) {
          console.log('Draft sent successfully!');
          console.log('  Message ID: ' + (sentResult.id || 'N/A'));
          console.log('  Thread ID: ' + (sentResult.threadId || 'N/A'));
        } else {
          console.log(JSON.stringify(sentResult));
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
        
        if (parsed.options.summary) {
          console.log('Draft deleted: ' + delDraftId);
        } else {
          console.log(JSON.stringify({ success: true, draftId: delDraftId }));
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
        
        // Handle file attachments (--attach path1,path2,... or --attach path)
        if (parsed.options.attach) {
          var sendAttachPaths = parsed.options.attach.split(',');
          sendOpts.attachments = [];
          for (var sai = 0; sai < sendAttachPaths.length; sai++) {
            var sendAtt = GmailClient.loadAttachment(sendAttachPaths[sai].trim());
            sendOpts.attachments.push(sendAtt);
          }
        }
        
        var sent = client.sendMessage(sendOpts);
        
        if (parsed.options.summary) {
          console.log('Email sent successfully!');
          console.log('  Message ID: ' + (sent.id || 'N/A'));
          console.log('  Thread ID: ' + (sent.threadId || 'N/A'));
          console.log('  To: ' + sendTo);
          console.log('  Subject: ' + (sendOpts.subject || '(no subject)'));
        } else {
          console.log(JSON.stringify(sent));
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
        var origCc = '';
        var origDate = '';
        
        for (var rhi = 0; rhi < replyHeaders.length; rhi++) {
          var hdr = replyHeaders[rhi];
          if (hdr.name === 'Message-ID' || hdr.name === 'Message-Id') origMessageId = hdr.value;
          if (hdr.name === 'References') origReferences = hdr.value;
          if (hdr.name === 'Subject') origSubject2 = hdr.value;
          if (hdr.name === 'From') origFrom = hdr.value;
          if (hdr.name === 'To') origTo2 = hdr.value;
          if (hdr.name === 'Cc') origCc = hdr.value;
          if (hdr.name === 'Date') origDate = hdr.value;
        }
        
        // Reply All: To = original sender, Cc = all participants from thread minus yourself and reply-to
        var myProfile = client.getProfile();
        var myEmail = (myProfile.emailAddress || '').toLowerCase();
        
        var replyTo = parsed.options.to || origFrom;
        
        // Collect all participants from the entire thread for Reply All
        var allRecipients = [];
        try {
          var thread = client.getThread(origMessage.threadId, 'metadata');
          var threadMessages = thread.messages || [];
          for (var tmi = 0; tmi < threadMessages.length; tmi++) {
            var tmHeaders = threadMessages[tmi].payload?.headers || [];
            for (var thi = 0; thi < tmHeaders.length; thi++) {
              var tmHdr = tmHeaders[thi];
              if (tmHdr.name === 'To' || tmHdr.name === 'Cc') {
                var addrs = tmHdr.value.split(',').map(function(s) { return s.trim(); });
                for (var ai = 0; ai < addrs.length; ai++) {
                  if (addrs[ai]) allRecipients.push(addrs[ai]);
                }
              }
            }
          }
        } catch (e) {
          // Fallback to single message recipients
          if (origTo2) allRecipients = allRecipients.concat(origTo2.split(',').map(function(s) { return s.trim(); }));
          if (origCc) allRecipients = allRecipients.concat(origCc.split(',').map(function(s) { return s.trim(); }));
        }
        
        // Deduplicate and filter out self and the reply-to address
        var replyToEmail = (origFrom.match(/<([^>]+)>/) || [])[1] || origFrom;
        var seenEmails = {};
        var filteredCc = [];
        for (var fi = 0; fi < allRecipients.length; fi++) {
          var addr = allRecipients[fi];
          var email = ((addr.match(/<([^>]+)>/) || [])[1] || addr).toLowerCase().trim();
          if (email && !seenEmails[email] && email !== myEmail && email !== replyToEmail.toLowerCase()) {
            seenEmails[email] = true;
            filteredCc.push(addr);
          }
        }
        
        var replyCc = parsed.options.cc || (filteredCc.length > 0 ? filteredCc.join(', ') : '');
        
        // Build subject
        var replySubject = parsed.options.subject || '';
        if (!replySubject) {
          if (origSubject2 && !origSubject2.match(/^Re:/i)) {
            replySubject = 'Re: ' + origSubject2;
          } else {
            replySubject = origSubject2;
          }
        }
        
        // Extract original message body (HTML) for quoting
        var origHtmlBody = GmailClient.extractHtmlBody(origMessage.payload);
        var quotedHtml = '';
        if (origHtmlBody) {
          var dateStr = origDate || 'unknown date';
          var fromStr = origFrom || 'unknown sender';
          quotedHtml = '<br><br><div class="gmail_quote">' +
            '<div dir="ltr" class="gmail_attr">On ' + dateStr + ', ' + fromStr + ' wrote:<br></div>' +
            '<blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">' +
            origHtmlBody +
            '</blockquote></div>';
        }
        
        // Convert reply text to HTML before combining with quoted thread
        var replyHtmlBody = replyBodyText;
        if (!replyHtmlBody.match(/<[a-z][\s\S]*>/i)) {
          replyHtmlBody = replyHtmlBody
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>\n');
          replyHtmlBody = '<p>' + replyHtmlBody + '</p>';
        }
        
        // Combine reply body with quoted original
        var fullBody = replyHtmlBody + quotedHtml;
        
        var replyOpts = {
          to: replyTo,
          cc: replyCc,
          bcc: parsed.options.bcc || '',
          subject: replySubject,
          body: fullBody,
          inReplyTo: origMessageId,
          references: origReferences ? origReferences + ' ' + origMessageId : origMessageId,
          threadId: origMessage.threadId
        };
        
        // Handle file attachments (--attach path1,path2,... or --attach path)
        if (parsed.options.attach) {
          var replyAttachPaths = parsed.options.attach.split(',');
          replyOpts.attachments = [];
          for (var rai = 0; rai < replyAttachPaths.length; rai++) {
            var replyAtt = GmailClient.loadAttachment(replyAttachPaths[rai].trim());
            replyOpts.attachments.push(replyAtt);
          }
        }
        
        // Send or create as draft
        var replyResult;
        if (parsed.options.draft) {
          replyResult = client.createDraft(replyOpts);
          if (parsed.options.summary) {
            console.log('Reply draft created');
            console.log('  Draft ID: ' + replyResult.id);
            console.log('  To: ' + replyTo);
            if (replyCc) console.log('  Cc: ' + replyCc);
            console.log('  Subject: ' + replySubject);
            console.log('  Quoted thread: ' + (quotedHtml ? 'yes' : 'no'));
          } else {
            console.log(JSON.stringify(replyResult));
          }
        } else {
          replyResult = client.sendMessage(replyOpts);
          if (parsed.options.summary) {
            console.log('Reply sent!');
            console.log('  Message ID: ' + (replyResult.id || 'N/A'));
            console.log('  To: ' + replyTo);
            console.log('  Subject: ' + replySubject);
          } else {
            console.log(JSON.stringify(replyResult));
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
            if (parsed.options.summary) {
              console.log('Marked as read: ' + markReadIds[mri]);
            }
          } catch (error) {
            markReadResults.push({ id: markReadIds[mri], success: false, error: error.message });
            if (parsed.options.summary) {
              console.log('Failed to mark as read: ' + markReadIds[mri] + ' - ' + error.message);
            }
          }
        }
        
        if (!parsed.options.summary) {
          console.log(JSON.stringify(markReadResults));
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
          if (parsed.options.summary) {
            console.log('Marked as unread: ' + markUnreadId);
          } else {
            console.log(JSON.stringify({ success: true, messageId: markUnreadId }));
          }
        } catch (error) {
          if (parsed.options.summary) {
            console.log('Failed to mark as unread: ' + error.message);
          } else {
            console.log(JSON.stringify({ success: false, error: error.message }));
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
            if (parsed.options.summary) {
              console.log('Moved to trash: ' + trashIds[tri]);
            }
          } catch (error) {
            trashResults.push({ id: trashIds[tri], success: false, error: error.message });
            if (parsed.options.summary) {
              console.log('Failed to trash: ' + trashIds[tri] + ' - ' + error.message);
            }
          }
        }
        
        if (!parsed.options.summary) {
          console.log(JSON.stringify(trashResults));
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
      }));
    }
    process.exit(1);
  }
}

// Execute
main();
