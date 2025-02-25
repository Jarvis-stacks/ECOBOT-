import React from 'react';

interface ResultDisplayProps {
  result: string;
}

const ResultDisplay: React.FC<ResultDisplayProps> = ({ result }) => {
  return <p>{result || 'Enter a query to see results.'}</p>;
};

export default ResultDisplay;
