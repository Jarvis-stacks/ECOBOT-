// History.tsx - Component to display conversation history

import React, { useState, useEffect } from 'react';
import '../styles/components.css';
import { getHistory } from '../utils/api';

interface HistoryProps {
  token: string;
}

interface HistoryItem {
  role: string;
  content: string;
  timestamp: string;
}

const History: React.FC<HistoryProps> = ({ token }) => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await getHistory(token);
        setHistory(response.history);
      } catch (err: any) {
        setError(err.message || 'Failed to fetch history');
      } finally {
        setIsLoading(false);
      }
    };
    fetchHistory();
  }, [token]);

  return (
    <div className="feature-container">
      <h2>Conversation History</h2>
      {isLoading ? (
        <p>Loading history...</p>
      ) : error ? (
        <p className="error-text">{error}</p>
      ) : history.length === 0 ? (
        <p>No conversation history available.</p>
      ) : (
        <ul className="history-list">
          {history.map((item, index) => (
            <li key={index} className={`history-item ${item.role}`}>
              <span className="history-role">{item.role}:</span>
              <span className="history-content">{item.content}</span>
              <span className="history-timestamp">
                {new Date(item.timestamp).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default History;
