import React, { useState } from 'react';
import QueryForm from './QueryForm';
import ResultDisplay from './ResultDisplay';
import ConversationTab from './ConversationTab';
import LoginForm from './LoginForm';  // New component
import './App.css';

function App() {
  const [result, setResult] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'single' | 'converse'>('single');
  const [token, setToken] = useState<string | null>(null);  // Manage JWT token

  const handleQuery = async (query: string) => {
    try {
      const response = await fetch(`http://localhost:8000/process?query=${encodeURIComponent(query)}`);
      if (!response.ok) throw new Error('Network response was not ok');
      const data: { result: string } = await response.json();
      setResult(data.result);
    } catch (error) {
      setResult('Error processing query. Please try again.');
    }
  };

  const handleLogin = async (username: string, password: string) => {
    try {
      const response = await fetch('http://localhost:8000/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      });
      if (!response.ok) throw new Error('Login failed');
      const data: { access_token: string } = await response.json();
      setToken(data.access_token);
    } catch (error) {
      alert('Login failed. Please check your credentials.');
    }
  };

  return (
    <div className="App">
      <h1>ECOBOT</h1>
      {token ? (
        <>
          <div className="tabs">
            <button onClick={() => setActiveTab('single')} className={activeTab === 'single' ? 'active' : ''}>
              Single Query
            </button>
            <button onClick={() => setActiveTab('converse')} className={activeTab === 'converse' ? 'active' : ''}>
              Conversation
            </button>
          </div>
          {activeTab === 'single' ? (
            <>
              <QueryForm onSubmit={handleQuery} />
              <ResultDisplay result={result} />
            </>
          ) : (
            <ConversationTab token={token} />
          )}
        </>
      ) : (
        <LoginForm onLogin={handleLogin} />
      )}
    </div>
  );
}

export default App;
