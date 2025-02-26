// Search.tsx - Component for web search

import React, { useState } from 'react';
import '../styles/components.css';
import { search } from '../utils/api';

interface SearchProps {
  token: string;
}

interface SearchResult {
  title: string;
  link: string;
  snippet: string;
}

const Search: React.FC<SearchProps> = ({ token }) => {
  const [query, setQuery] = useState<string>('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await search(token, query);
      setResults(response.results);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch search results');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="feature-container">
      <h2>Web Search</h2>
      <div className="input-group">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the web (e.g., latest tech trends)"
          disabled={isLoading}
        />
        <button onClick={handleSearch} disabled={isLoading}>
          {isLoading ? 'Searching...' : 'Search'}
        </button>
      </div>
      {error && <p className="error-text">{error}</p>}
      {results.length > 0 && (
        <div className="search-results">
          <h3>Results:</h3>
          <ul>
            {results.map((result, index) => (
              <li key={index} className="search-result-item">
                <a href={result.link} target="_blank" rel="noopener noreferrer">
                  {result.title}
                </a>
                <p>{result.snippet}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default Search;
