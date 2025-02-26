// Conversation.tsx - Component for multi-turn chat interface

import React, { useState, useEffect, useRef } from 'react';
import '../styles/Conversation.css';
import { sendMessage } from '../utils/api';

interface ConversationProps {
  token: string;
  sessionId: string;
}

const Conversation: React.FC<ConversationProps> = ({ token, sessionId }) => {
  const [messages, setMessages] = useState<{ role: string; content: string; timestamp: string }[]>([]);
  const [input, setInput] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const handleSend = async () => {
    if (!input.trim()) return;
    setIsLoading(true);
    setError(null);
    const userMessage = { role: 'user', content: input, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    try {
      const response = await sendMessage(token, sessionId, input);
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: response.response,
        timestamp: response.timestamp
      }]);
    } catch (err: any) {
      setError(err.message || 'Failed to send message');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div className="conversation-container">
      <h2>Conversation</h2>
      <div className="chat-window">
        {messages.map((msg, index) => (
          <div key={index} className={`message ${msg.role}`}>
            <span className="message-role">{msg.role}:</span>
            <span className="message-content">{msg.content}</span>
            <span className="message-timestamp">{new Date(msg.timestamp).toLocaleTimeString()}</span>
          </div>
        ))}
        <div ref={chatEndRef} />
      </div>
      {error && <p className="error-text">{error}</p>}
      <div className="input-area">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Type your message..."
          disabled={isLoading}
          rows={3}
        />
        <button onClick={handleSend} disabled={isLoading}>
          {isLoading ? 'Sending...' : 'Send'}
        </button>
      </div>
    </div>
  );
};

export default Conversation;
