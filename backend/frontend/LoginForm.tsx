// LoginForm.tsx - Component for user login

import React, { useState } from 'react';
import '../styles/components.css';

interface LoginFormProps {
  onLogin: (username: string, password: string) => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onLogin }) => {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [localError, setLocalError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setLocalError('Please enter both username and password.');
      return;
    }
    setLocalError(null);
    onLogin(username, password);
  };

  return (
    <div className="login-form-container">
      <h2>Login to ECOBOT</h2>
      <form onSubmit={handleSubmit} className="login-form">
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter your username"
            autoComplete="username"
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            autoComplete="current-password"
          />
        </div>
        {localError && <p className="error-text">{localError}</p>}
        <button type="submit" className="login-button">Login</button>
      </form>
      <p className="signup-prompt">
        Don’t have an account? <a href="#">Sign up</a> (Coming soon!)
      </p>
    </div>
  );
};

export default LoginForm;
