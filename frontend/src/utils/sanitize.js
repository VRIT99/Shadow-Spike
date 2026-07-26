/**
 * Shadow Spike - Input Sanitization Utility
 * Sabhi input fields ke liye centralized sanitization functions
 */

/**
 * General purpose sanitizer - HTML injection aur dangerous characters strip karta hai
 * Normal text inputs ke liye (username, email, etc.)
 * @param {string} value
 * @returns {string}
 */
export const sanitizeText = (value) => {
  if (typeof value !== 'string') return ''
  return value
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/&(?!lt;|gt;|amp;|quot;|#\d+;)/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim()
}

/**
 * URL sanitizer - target URL fields ke liye
 * Script injection rokta hai, lekin valid URL characters allow karta hai
 * @param {string} value
 * @returns {string}
 */
export const sanitizeUrl = (value) => {
  if (typeof value !== 'string') return ''
  // Remove null bytes, carriage returns (except in context), and dangerous JS schemes
  let sanitized = value
    .replace(/\0/g, '')           // Null bytes
    .replace(/javascript:/gi, '') // JS injection
    .replace(/vbscript:/gi, '')   // VBScript injection
    .replace(/data:/gi, '')       // Data URI injection
    .trim()
  return sanitized
}

/**
 * Domain sanitizer - subdomain/hostname fields ke liye
 * Sirf valid domain characters allow karta hai
 * @param {string} value
 * @returns {string}
 */
export const sanitizeDomain = (value) => {
  if (typeof value !== 'string') return ''
  // Allow only valid hostname characters: letters, numbers, dots, hyphens
  return value
    .replace(/[^a-zA-Z0-9.\-_]/g, '')
    .trim()
    .toLowerCase()
}

/**
 * Port range sanitizer - port scanner custom ports field ke liye
 * Sirf numbers, commas, hyphens allow karta hai
 * @param {string} value
 * @returns {string}
 */
export const sanitizePorts = (value) => {
  if (typeof value !== 'string') return ''
  return value
    .replace(/[^0-9,\-\s]/g, '')
    .trim()
}

/**
 * Email sanitizer - email input fields ke liye
 * @param {string} value
 * @returns {string}
 */
export const sanitizeEmail = (value) => {
  if (typeof value !== 'string') return ''
  return value
    .replace(/[<>'"\\]/g, '')
    .replace(/\0/g, '')
    .trim()
    .toLowerCase()
}

/**
 * Password sanitizer - sirf null bytes aur control characters remove karta hai
 * Password ka structure change nahi karta
 * @param {string} value
 * @returns {string}
 */
export const sanitizePassword = (value) => {
  if (typeof value !== 'string') return ''
  return value
    .replace(/\0/g, '')  // Null bytes only
}

/**
 * Free-text / multiline sanitizer - textarea fields ke liye (headers, body, etc.)
 * Script tags aur dangerous injection patterns remove karta hai
 * lekin newlines aur JSON structure preserve karta hai
 * @param {string} value
 * @returns {string}
 */
export const sanitizeMultiline = (value) => {
  if (typeof value !== 'string') return ''
  return value
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '') // Script tags
    .replace(/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, '') // Iframe tags
    .replace(/javascript:/gi, '')                        // JS protocol
    .replace(/\0/g, '')                                  // Null bytes
}

/**
 * TOTP code sanitizer - 2FA code fields ke liye
 * Sirf digits allow karta hai
 * @param {string} value
 * @returns {string}
 */
export const sanitizeTotp = (value) => {
  if (typeof value !== 'string') return ''
  return value.replace(/[^0-9]/g, '').slice(0, 6)
}
