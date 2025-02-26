import React, { useState, useEffect } from 'react';

interface ConversationTabProps {
  token: string;
}

const ConversationTab: React.FC<ConversationTabProps> = ({ token }) => {
  const [messages, setMessages] = useState<{ role: string; content: string }[]>([]);
  const [input, setInput] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const response = await fetch('http://localhost:8000/history', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!response.ok) throw new Error('Failed to fetch history');
        const data = await response.json();
        setMessages(data.history);
      } catch (error) {
        console.error('Error fetching history:', error);
      }
    };
    fetchHistory();
  }, [token]);

  const handleSendMessage = async () => {
    if (!input.trim()) return;
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/converse', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ message: input }),
      });
      if (!response.ok) throw new Error('Network response was not ok');
      const data: { response: string } = await response.json();
      setMessages((prev) => [
        ...prev,
        { role: 'user', content: input },
        { role: 'assistant', content: data.response },
      ]);
      setInput('');
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'Error: Could not connect to the server.' },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="conversation-tab">
      <div className="chat-window">
        {messages.length === 0 ? (
          <p>Start the conversation by typing a message.</p>
        ) : (
          messages.map((msg, index) => (
            <p key={index} className={msg.role}>
              <strong>{msg.role}:</strong> {msg.content}
            </p>
          ))
        )}
      </div>
      {isLoading && <p>Loading...</p>}
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Type your message..."
      />
      <button onClick={handleSendMessage} disabled={isLoading}>
        {isLoading ? 'Sending...' : 'Send'}
      </button>
    </div>
  );
};

export default ConversationTab;
