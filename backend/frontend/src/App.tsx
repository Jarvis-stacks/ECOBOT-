// App.tsx - Main application component orchestrating all features and UI

import React, { useState, useEffect } from 'react';
import './styles/App.css';
import LoginForm from './components/LoginForm';
import Conversation from './components/Conversation';
import Brainstorm from './components/Brainstorm';
import Think from './components/Think';
import Search from './components/Search';
import History from './components/History';
import Profile from './components/Profile';
import Navbar from './components/Navbar';
import LoadingSpinner from './components/LoadingSpinner';
import { login, logout } from './utils/api';
import { User, Session } from './types';

const App: React.FC = () => {
  // State management for user authentication and UI
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('conversation');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Check for existing token/session on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedSessionId = localStorage.getItem('sessionId');
    if (storedToken && storedSessionId) {
      setToken(storedToken);
      setSessionId(storedSessionId);
      // Fetch user profile to verify token
      setIsLoading(true);
      fetchProfile(storedToken).then((profile) => {
        setUser({ username: profile.username, email: profile.email, fullName: profile.full_name });
        setIsLoading(false);
      }).catch(() => {
        localStorage.clear();
        setIsLoading(false);
      });
    }
  }, []);

  // Handle login submission
  const handleLogin = async (username: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await login(username, password);
      setToken(response.access_token);
      setSessionId(response.session_id);
      setUser({ username, email: '', fullName: '' }); // Placeholder; fetch full profile later
      localStorage.setItem('token', response.access_token);
      localStorage.setItem('sessionId', response.session_id);
      const profile = await fetchProfile(response.access_token);
      setUser({ username: profile.username, email: profile.email, fullName: profile.full_name });
    } catch (err: any) {
      setError(err.message || 'Login failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch user profile
  const fetchProfile = async (token: string): Promise<any> => {
    const response = await fetch('http://localhost:8000/profile', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch profile');
    return response.json();
  };

  // Handle logout
  const handleLogout = async () => {
    if (!token || !sessionId) return;
    setIsLoading(true);
    try {
      await logout(token, sessionId);
      setToken(null);
      setSessionId(null);
      setUser(null);
      localStorage.clear();
      setActiveTab('conversation');
    } catch (err: any) {
      setError('Logout failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Render active tab content
  const renderTabContent = () => {
    if (!token || !sessionId || !user) return null;
    switch (activeTab) {
      case 'conversation':
        return <Conversation token={token} sessionId={sessionId} />;
      case 'brainstorm':
        return <Brainstorm token={token} />;
      case 'think':
        return <Think token={token} />;
      case 'search':
        return <Search token={token} />;
      case 'history':
        return <History token={token} />;
      case 'profile':
        return <Profile token={token} />;
      default:
        return <div>Select a tab to get started</div>;
    }
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <h1>ECOBOT</h1>
        <p>Your AI-Powered Assistant</p>
      </header>

      {/* Navigation */}
      {token && (
        <Navbar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          onLogout={handleLogout}
          username={user?.username || 'User'}
        />
      )}

      {/* Main Content */}
      <main className="app-main">
        {isLoading && <LoadingSpinner />}
        {error && (
          <div className="error-message">
            <p>{error}</p>
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}

        {!token ? (
          <LoginForm onLogin={handleLogin} />
        ) : (
          <section className="tab-content">
            {renderTabContent()}
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <p>&copy; 2025 ECOBOT. All rights reserved.</p>
        <p>Built with ❤️ by [Your Name]</p>
      </footer>
    </div>
  );
};

export default App;
