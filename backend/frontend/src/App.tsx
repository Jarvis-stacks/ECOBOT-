import React, { useState } from 'react';
import QueryForm from './QueryForm';
import ResultDisplay from './ResultDisplay';
import './App.css';  // Optional: Add styles if desired

function App() {
  const [result, setResult] = useState<string>('');

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

  return (
    <div className="App">
      <h1>ECOBOT</h1>
      <QueryForm onSubmit={handleQuery} />
      <ResultDisplay result={result} />
    </div>
  );
}

export default App;
