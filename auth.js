/*
 * Clipper authentication UI.
 *
 * Important: this static-only demo cannot provide production authentication.
 * Anything stored in browser storage can be inspected or deleted by the user.
 * For production, move registration/login to a server or managed auth provider
 * and keep only a short-lived, secure session token in the browser.
 */

const AUTH_KEYS = {
  users: 'clipper_users_v2',
  session: 'clipper_session_v2'
};

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 120000;

const textEncoder = new TextEncoder();

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

function createSalt() {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return bytesToBase64(salt);
}

async function derivePasswordHash(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: base64ToBytes(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return bytesToBase64(new Uint8Array(bits));
}

function safeJsonParse(value, fallback) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function validatePassword(password) {
  if (password.length < 10) return 'Use at least 10 characters.';
  if (!/[A-Z]/.test(password)) return 'Add at least one uppercase letter.';
  if (!/[a-z]/.test(password)) return 'Add at least one lowercase letter.';
  if (!/[0-9]/.test(password)) return 'Add at least one number.';
  return null;
}

class AuthManager {
  constructor() {
    this.users = safeJsonParse(localStorage.getItem(AUTH_KEYS.users), []);
    this.currentUser = this.readSession();
  }

  saveUsers() {
    localStorage.setItem(AUTH_KEYS.users, JSON.stringify(this.users));
  }

  readSession() {
    const session = safeJsonParse(localStorage.getItem(AUTH_KEYS.session), null);
    if (!session || !session.user || Date.now() >= session.expiresAt) {
      localStorage.removeItem(AUTH_KEYS.session);
      return null;
    }
    return session.user;
  }

  saveSession(user) {
    this.currentUser = user;
    localStorage.setItem(AUTH_KEYS.session, JSON.stringify({
      user,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS
    }));
  }

  async register(email, password, displayName) {
    const normalizedEmail = normalizeEmail(email);
    const name = displayName.trim();

    if (!normalizedEmail || !password || !name) {
      return { success: false, message: 'All fields are required.' };
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return { success: false, message: 'Enter a valid email address.' };
    }
    if (name.length < 2 || name.length > 40) {
      return { success: false, message: 'Display name must be 2–40 characters.' };
    }

    const passwordError = validatePassword(password);
    if (passwordError) return { success: false, message: passwordError };
    if (this.users.some(user => user.email === normalizedEmail)) {
      return { success: false, message: 'An account with that email already exists.' };
    }

    const salt = createSalt();
    const user = {
      id: crypto.randomUUID(),
      email: normalizedEmail,
      displayName: name,
      avatar: this.generateAvatar(name),
      passwordHash: await derivePasswordHash(password, salt),
      passwordSalt: salt,
      createdAt: new Date().toISOString(),
      subscriptions: [],
      savedVideos: []
    };

    this.users.push(user);
    this.saveUsers();

    // Do not automatically create a session after registration.
    return { success: true, message: 'Account created. You can now sign in.' };
  }

  async login(email, password) {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !password) {
      return { success: false, message: 'Email and password are required.' };
    }

    const user = this.users.find(candidate => candidate.email === normalizedEmail);
    if (!user || !user.passwordHash || !user.passwordSalt) {
      return { success: false, message: 'Email or password is incorrect.' };
    }

    const passwordHash = await derivePasswordHash(password, user.passwordSalt);
    if (passwordHash !== user.passwordHash) {
      return { success: false, message: 'Email or password is incorrect.' };
    }

    const safeUser = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      avatar: user.avatar
    };
    this.saveSession(safeUser);
    return { success: true, user: safeUser, message: 'Welcome back!' };
  }

  logout() {
    this.currentUser = null;
    localStorage.removeItem(AUTH_KEYS.session);
  }

  isLoggedIn() {
    this.currentUser = this.readSession();
    return Boolean(this.currentUser);
  }

  getCurrentUser() {
    return this.isLoggedIn() ? this.currentUser : null;
  }

  generateAvatar(name) {
    const colors = ['#ff8fab', '#7cc7ff', '#9ad8ff', '#ffc1cd', '#c9a0ff'];
    return colors[name.codePointAt(0) % colors.length];
  }
}

const authManager = new AuthManager();

class UIManager {
  static showAuthModal(mode = 'login') {
    const modal = document.getElementById('auth-modal');
    const form = document.getElementById('auth-form');
    const title = document.getElementById('auth-title');
    const toggle = document.getElementById('auth-toggle');
    const displayName = document.getElementById('display-name-input');

    if (!modal || !form || !title || !toggle || !displayName) return;

    const registering = mode === 'register';
    title.textContent = registering ? 'Create your Clipper account' : 'Sign in to Clipper';
    displayName.hidden = !registering;
    displayName.required = registering;
    form.dataset.mode = registering ? 'register' : 'login';
    toggle.innerHTML = registering
      ? 'Already have an account? <a href="#" data-auth-mode="login">Sign in</a>'
      : 'Need an account? <a href="#" data-auth-mode="register">Sign up</a>';
    modal.style.display = 'flex';
    document.getElementById('email-input')?.focus();
  }

  static hideAuthModal() {
    const modal = document.getElementById('auth-modal');
    if (modal) modal.style.display = 'none';
  }

  static updateAuthUI() {
    const user = authManager.getCurrentUser();
    const avatar = document.getElementById('avatar-btn');
    const upload = document.querySelector('.upload-btn');
    if (!avatar) return;

    avatar.textContent = user ? user.displayName.charAt(0).toUpperCase() : '?';
    avatar.title = user ? user.displayName : 'Sign in';
    avatar.onclick = () => user ? this.toggleUserMenu() : this.showAuthModal('login');
    if (upload) upload.style.display = user ? 'block' : 'none';
  }

  static toggleUserMenu() {
    const menu = document.getElementById('user-menu');
    if (menu) menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
  }

  static showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.setAttribute('role', 'status');
    notification.textContent = message;
    document.body.appendChild(notification);
    window.setTimeout(() => notification.remove(), 3500);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  UIManager.updateAuthUI();

  const form = document.getElementById('auth-form');
  const modal = document.getElementById('auth-modal');
  const toggle = document.getElementById('auth-toggle');
  const close = document.getElementById('close-auth');
  const logout = document.getElementById('logout-btn');

  form?.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;

    const email = document.getElementById('email-input')?.value || '';
    const password = document.getElementById('password-input')?.value || '';
    const displayName = document.getElementById('display-name-input')?.value || '';
    const result = form.dataset.mode === 'register'
      ? await authManager.register(email, password, displayName)
      : await authManager.login(email, password);

    UIManager.showNotification(result.message, result.success ? 'success' : 'error');
    if (result.success) {
      if (form.dataset.mode === 'register') {
        form.reset();
        UIManager.showAuthModal('login');
      } else {
        form.reset();
        UIManager.hideAuthModal();
        UIManager.updateAuthUI();
      }
    }
    if (submit) submit.disabled = false;
  });

  toggle?.addEventListener('click', event => {
    const link = event.target.closest('[data-auth-mode]');
    if (!link) return;
    event.preventDefault();
    UIManager.showAuthModal(link.dataset.authMode);
  });

  close?.addEventListener('click', () => UIManager.hideAuthModal());
  modal?.addEventListener('click', event => {
    if (event.target === modal) UIManager.hideAuthModal();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') UIManager.hideAuthModal();
  });

  logout?.addEventListener('click', event => {
    event.preventDefault();
    authManager.logout();
    UIManager.updateAuthUI();
    const menu = document.getElementById('user-menu');
    if (menu) menu.style.display = 'none';
    UIManager.showNotification('You have been signed out.', 'success');
  });
});
