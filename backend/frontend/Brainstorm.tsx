// Brainstorm.tsx - Component for generating brainstorming ideas

import React, { useState } from 'react';
import '../styles/components.css';
import { brainstorm } from '../utils/api';

interface BrainstormProps {
  token: string;
}

const Brainstorm: React.FC<BrainstormProps> = ({ token }) => {
  const [query, setQuery] = useState<string>('');
  const [ideas, setIdeas] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!query.trim()) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await brainstorm(token, query);
      setIdeas(response.ideas);
    } catch (err: any) {
      setError(err.message || 'Failed to generate ideas');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="feature-container">
      <h2>Brainstorm</h2>
      <div className="input-group">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter a topic to brainstorm (e.g., sustainable energy)"
          disabled={isLoading}
        />
        <button onClick={handleSubmit} disabled={isLoading}>
          {isLoading ? 'Generating...' : 'Generate Ideas'}
        </button>
      </div>
      {error && <p className="error-text">{error}</p>}
      {ideas && (
        <div className="result-box">
          <h3>Ideas:</h3>
          <p>{ideas}</p>
        </div>
      )}
    </div>
  );
};

export default Brainstorm;
