// Authentication Module
class AuthManager {
  constructor() {
    this.users = this.loadUsers();
    this.currentUser = this.loadCurrentUser();
  }

  loadUsers() {
    const stored = localStorage.getItem('clipper_users');
    return stored ? JSON.parse(stored) : [];
  }

  saveUsers() {
    localStorage.setItem('clipper_users', JSON.stringify(this.users));
  }

  loadCurrentUser() {
    const stored = localStorage.getItem('clipper_current_user');
    return stored ? JSON.parse(stored) : null;
  }

  saveCurrentUser() {
    localStorage.setItem('clipper_current_user', JSON.stringify(this.currentUser));
  }

  register(email, password, displayName) {
    // Validate inputs
    if (!email || !password || !displayName) {
      return { success: false, message: 'All fields are required' };
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { success: false, message: 'Invalid email format' };
    }

    if (password.length < 8) {
      return { success: false, message: 'Password must be at least 8 characters' };
    }

    if (this.users.find(u => u.email === email)) {
      return { success: false, message: 'Email already registered' };
    }

    // Create new user
    const newUser = {
      id: Date.now().toString(),
      email,
      password: this.hashPassword(password),
      displayName,
      createdAt: new Date().toISOString(),
      avatar: this.generateAvatar(displayName),
      subscriptions: [],
      savedVideos: []
    };

    this.users.push(newUser);
    this.saveUsers();

    return { success: true, message: 'Registration successful' };
  }

  login(email, password) {
    if (!email || !password) {
      return { success: false, message: 'Email and password are required' };
    }

    const user = this.users.find(u => u.email === email);
    if (!user) {
      return { success: false, message: 'Email not found' };
    }

    if (!this.verifyPassword(password, user.password)) {
      return { success: false, message: 'Incorrect password' };
    }

    // Create session
    this.currentUser = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      avatar: user.avatar,
      loginTime: new Date().toISOString()
    };

    this.saveCurrentUser();
    return { success: true, user: this.currentUser };
  }

  logout() {
    this.currentUser = null;
    localStorage.removeItem('clipper_current_user');
    return { success: true };
  }

  isLoggedIn() {
    return this.currentUser !== null;
  }

  getCurrentUser() {
    return this.currentUser;
  }

  hashPassword(password) {
    // Simple hash (for production, use bcrypt or similar)
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
      const char = password.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  verifyPassword(password, hash) {
    return this.hashPassword(password) === hash;
  }

  generateAvatar(name) {
    const colors = ['#ff8fab', '#7cc7ff', '#9ad8ff', '#ffc1cd', '#c9a0ff'];
    const index = name.charCodeAt(0) % colors.length;
    return colors[index];
  }

  updateProfile(updates) {
    if (!this.currentUser) return { success: false, message: 'Not logged in' };

    const userIndex = this.users.findIndex(u => u.id === this.currentUser.id);
    if (userIndex !== -1) {
      this.users[userIndex] = { ...this.users[userIndex], ...updates };
      this.currentUser = { ...this.currentUser, ...updates };
      this.saveUsers();
      this.saveCurrentUser();
      return { success: true };
    }

    return { success: false, message: 'User not found' };
  }
}

// Initialize Auth Manager
const authManager = new AuthManager();

// UI Manager
class UIManager {
  static showAuthModal(mode = 'login') {
    const modal = document.getElementById('auth-modal');
    const form = document.getElementById('auth-form');
    const title = document.getElementById('auth-title');
    const toggleBtn = document.getElementById('auth-toggle');
    const displayNameInput = document.getElementById('display-name-input');

    if (mode === 'login') {
      title.textContent = 'Sign in to Clipper';
      displayNameInput.style.display = 'none';
      toggleBtn.innerHTML = 'Need an account? <a href="#">Sign up</a>';
      form.dataset.mode = 'login';
    } else {
      title.textContent = 'Create your Clipper account';
      displayNameInput.style.display = 'block';
      toggleBtn.innerHTML = 'Already have an account? <a href="#">Sign in</a>';
      form.dataset.mode = 'register';
    }

    modal.style.display = 'flex';
  }

  static hideAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
  }

  static updateAuthUI() {
    const user = authManager.getCurrentUser();
    const avatarBtn = document.getElementById('avatar-btn');
    const userMenu = document.getElementById('user-menu');
    const uploadBtn = document.querySelector('.upload-btn');

    if (user) {
      avatarBtn.textContent = user.displayName.charAt(0).toUpperCase();
      avatarBtn.title = user.displayName;
      uploadBtn.style.display = 'block';
      avatarBtn.addEventListener('click', () => this.toggleUserMenu());
    } else {
      uploadBtn.style.display = 'none';
      avatarBtn.textContent = '?';
      avatarBtn.title = 'Sign in';
      avatarBtn.addEventListener('click', () => this.showAuthModal('login'));
    }
  }

  static toggleUserMenu() {
    const userMenu = document.getElementById('user-menu');
    userMenu.style.display = userMenu.style.display === 'block' ? 'none' : 'block';
  }

  static showNotification(message, type = 'info') {
    const notif = document.createElement('div');
    notif.className = `notification notification-${type}`;
    notif.textContent = message;
    document.body.appendChild(notif);

    setTimeout(() => notif.remove(), 3000);
  }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  // Initialize UI
  UIManager.updateAuthUI();

  // Auth Modal
  const authForm = document.getElementById('auth-form');
  const closeAuthBtn = document.getElementById('close-auth');
  const toggleBtn = document.getElementById('auth-toggle');

  if (authForm) {
    authForm.addEventListener('submit', (e) => {
      e.preventDefault();

      const email = document.getElementById('email-input').value;
      const password = document.getElementById('password-input').value;
      const displayName = document.getElementById('display-name-input').value;
      const mode = authForm.dataset.mode;

      let result;
      if (mode === 'register') {
        result = authManager.register(email, password, displayName);
      } else {
        result = authManager.login(email, password);
      }

      if (result.success) {
        UIManager.showNotification(result.message || 'Success!', 'success');
        setTimeout(() => {
          UIManager.hideAuthModal();
          UIManager.updateAuthUI();
          authForm.reset();
        }, 500);
      } else {
        UIManager.showNotification(result.message, 'error');
      }
    });
  }

  if (closeAuthBtn) {
    closeAuthBtn.addEventListener('click', UIManager.hideAuthModal);
  }

  if (toggleBtn) {
    toggleBtn.addEventListener('click', (e) => {
      if (e.target.tagName === 'A') {
        e.preventDefault();
        const currentMode = document.getElementById('auth-form').dataset.mode;
        UIManager.showAuthModal(currentMode === 'login' ? 'register' : 'login');
      }
    });
  }

  // Logout
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      authManager.logout();
      UIManager.hideAuthModal();
      UIManager.updateAuthUI();
      UIManager.showNotification('Logged out successfully', 'success');
    });
  }

  // Close modal on outside click
  const modal = document.getElementById('auth-modal');
  if (modal) {
    window.addEventListener('click', (e) => {
      if (e.target === modal) {
        UIManager.hideAuthModal();
      }
    });
  }
});
