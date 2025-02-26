// LoadingSpinner.tsx - Simple loading spinner component

import React from 'react';
import '../styles/components.css';

const LoadingSpinner: React.FC = () => {
  return (
    <div className="loading-spinner">
      <div className="spinner"></div>
      <p>Loading...</p>
    </div>
  );
};

export default LoadingSpinner;
