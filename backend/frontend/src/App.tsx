import React, { useState } from 'react';
import './App.css';
import LoginForm from './LoginForm';
import QueryForm from './QueryForm';
import ResultDisplay from './ResultDisplay';
import ConversationTab from './ConversationTab';

const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'single' | 'converse'>('single');
  const [result, setResult] = useState<string>('');

  const handleLogin = (newToken: string) => setToken(newToken);
  const handleQuery = (response: string) => setResult(response);

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
          <button onClick={() => setToken(null)}>Logout</button> {/* New logout button */}
        </>
      ) : (
        <LoginForm onLogin={handleLogin} />
      )}
    </div>
  );
};

export default App;
