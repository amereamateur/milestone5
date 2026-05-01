/* global window */
// Shared validation helpers used by secure.html (client-side validation)
(function () {
  'use strict';

  const patterns = {
    username: /^[a-zA-Z0-9_]{3,20}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    password: /^.{8,}$/,
  };

  const sqlInjectionIndicators = [
    "'", '"', '--', ';', '/*', '*/',
    'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
    'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE',
    ' OR 1=1', " OR '1'='1", ' OR "1"="1"',
  ];

  function detectSqlLike(input) {
    const upper = String(input || '').toUpperCase();
    return sqlInjectionIndicators.some((p) => upper.includes(p.toUpperCase()));
  }

  function validateSecureInputs({ username, email, password, feedback }) {
    const errors = [];

    if (!patterns.username.test(username)) {
      errors.push('Username must be 3-20 characters and contain only letters, numbers, and underscores.');
    }
    if (detectSqlLike(username)) {
      errors.push('🚫 SQL Injection detected in username (client-side).');
    }
    if (!patterns.email.test(email)) {
      errors.push('Please enter a valid email address.');
    }
    if (!patterns.password.test(password)) {
      errors.push('Password must be at least 8 characters long.');
    }
    if (!feedback || feedback.trim().length === 0) {
      errors.push('Feedback cannot be empty.');
    }
    if (String(feedback || '').length > 1000) {
      errors.push('Feedback is too long. Maximum 1000 characters allowed.');
    }
    if (detectSqlLike(feedback)) {
      errors.push('🚫 Potentially malicious patterns detected in feedback (client-side).');
    }

    return { ok: errors.length === 0, errors };
  }

  window.CyberDemoValidation = {
    patterns,
    detectSqlLike,
    validateSecureInputs,
  };
})();

