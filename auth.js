(function() {
  const USERS_KEY = 'hutech-auth-users-v1';
  const SESSION_KEY = 'hutech-auth-session-v1';
  const USERNAME_PATTERN = /^[a-zA-Z0-9._-]{3,24}$/;

  function safeParse(value, fallback) {
    try {
      return value ? JSON.parse(value) : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
  }

  function hashPassword(password) {
    const rawPassword = String(password || '');

    if (window.CryptoJS && window.CryptoJS.SHA256) {
      return window.CryptoJS.SHA256(rawPassword).toString();
    }

    return rawPassword;
  }

  function getStoredUsers() {
    return safeParse(localStorage.getItem(USERS_KEY), []);
  }

  function saveStoredUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  function sanitizeUser(user) {
    if (!user) {
      return null;
    }

    return {
      username: user.username,
      displayName: user.displayName || user.username,
      role: user.role === 'admin' ? 'admin' : 'user'
    };
  }

  function getSessionUser() {
    return sanitizeUser(safeParse(sessionStorage.getItem(SESSION_KEY), null));
  }

  function setSessionUser(user) {
    if (!user) {
      sessionStorage.removeItem(SESSION_KEY);
      return;
    }

    sessionStorage.setItem(SESSION_KEY, JSON.stringify(sanitizeUser(user)));
  }

  function findUser(username) {
    const normalizedUsername = normalizeUsername(username);
    return getStoredUsers().find(function(user) {
      return user.username === normalizedUsername;
    }) || null;
  }

  function hasAdminAccount() {
    return !!findUser('admin');
  }

  function validateRegisterPayload(payload) {
    const username = normalizeUsername(payload.username);
    const password = String(payload.password || '');

    if (!payload.displayName || !String(payload.displayName).trim()) {
      return 'Vui lòng nhập tên hiển thị.';
    }

    if (!USERNAME_PATTERN.test(username)) {
      return 'Tên đăng nhập cần 3-24 ký tự và chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang.';
    }

    if (password.length < 6) {
      return 'Mật khẩu cần tối thiểu 6 ký tự.';
    }

    if (findUser(username)) {
      return 'Tên đăng nhập này đã tồn tại.';
    }

    return '';
  }

  function registerUser(payload) {
    const validationMessage = validateRegisterPayload(payload);

    if (validationMessage) {
      return {
        ok: false,
        message: validationMessage
      };
    }

    const username = normalizeUsername(payload.username);
    const users = getStoredUsers();
    const createdUser = {
      username: username,
      displayName: String(payload.displayName || '').trim(),
      passwordHash: hashPassword(payload.password),
      role: username === 'admin' ? 'admin' : 'user',
      createdAt: new Date().toISOString()
    };

    users.push(createdUser);
    saveStoredUsers(users);
    setSessionUser(createdUser);

    return {
      ok: true,
      user: sanitizeUser(createdUser),
      message: createdUser.role === 'admin'
        ? 'Tạo tài khoản admin thành công. Đang chuyển về trang chính...'
        : 'Đăng ký thành công. Đang chuyển về trang chính...'
    };
  }

  function loginUser(payload) {
    const username = normalizeUsername(payload.username);
    const password = String(payload.password || '');

    if (!username || !password) {
      return {
        ok: false,
        message: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.'
      };
    }

    const user = findUser(username);
    if (!user) {
      return {
        ok: false,
        message: 'Không tìm thấy tài khoản phù hợp.'
      };
    }

    if (user.passwordHash !== hashPassword(password)) {
      return {
        ok: false,
        message: 'Mật khẩu không chính xác.'
      };
    }

    setSessionUser(user);

    return {
      ok: true,
      user: sanitizeUser(user),
      message: 'Đăng nhập thành công. Đang chuyển về trang chính...'
    };
  }

  function logout() {
    setSessionUser(null);
  }

  function isAdmin(user) {
    return !!(user && user.role === 'admin');
  }

  window.HutechAuth = {
    getStoredUsers: getStoredUsers,
    getSessionUser: getSessionUser,
    registerUser: registerUser,
    loginUser: loginUser,
    logout: logout,
    isAdmin: isAdmin,
    hasAdminAccount: hasAdminAccount
  };
})();
