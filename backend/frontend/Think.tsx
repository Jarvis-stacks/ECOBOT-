// Think.tsx - Component for thoughtful analysis

import React, { useState } from 'react';
import '../styles/components.css';
import { think } from '../utils/api';

interface ThinkProps {
  token: string;
}

const Think: React.FC<ThinkProps> = ({ token }) => {
  const [topic, setTopic] = useState<string>('');
  const [thought, setThought] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!topic.trim()) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await think(token, topic);
      setThought(response.thought);
    } catch (err: any) {
      setError(err.message || 'Failed to generate thought');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="feature-container">
      <h2>Think</h2>
      <div className="input-group">
        <input
          type="text"
          value={topic}
          onChange={(e) => setTopic(e.target.value)}
          placeholder="Enter a topic to analyze (e.g., future of AI)"
          disabled={isLoading}
        />
        <button onClick={handleSubmit} disabled={isLoading}>
          {isLoading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>
      {error && <p className="error-text">{error}</p>}
      {thought && (
        <div className="result-box">
          <h3>Analysis:</h3>
          <p>{thought}</p>
        </div>
      )}
    </div>
  );
};

export default Think;
