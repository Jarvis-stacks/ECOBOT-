import React, { useState } from 'react';

const ConversationTab: React.FC = () => {
  const [messages, setMessages] = useState<{ role: string; content: string }[]>([]);
  const [input, setInput] = useState<string>('');

  const handleSendMessage = async () => {
    if (!input.trim()) return;
    try {
      const response = await fetch('http://localhost:8000/converse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: input }),
      });
      if (!response.ok) throw new Error('Network response was not ok');
      const data: { response: string } = await response.json();
      setMessages((prev) => [
        ...prev,
        { role: 'user', content: input },
        { role: 'assistant', content: data.response },
      ]);
      setInput('');  // Clear input field
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'Error: Could not connect to the server.' },
      ]);
    }
  };

  return (
    <div className="conversation-tab">
      <div className="chat-window">
        {messages.map((msg, index) => (
          <p key={index} className={msg.role}>
            <strong>{msg.role}:</strong> {msg.content}
          </p>
        ))}
      </div>
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Type your message..."
      />
      <button onClick={handleSendMessage}>Send</button>
    </div>
  );
};

export default ConversationTab;
