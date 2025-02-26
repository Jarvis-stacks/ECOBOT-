// Navbar.tsx - Navigation bar component

import React from 'react';
import '../styles/components.css';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
  username: string;
}

const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onLogout, username }) => {
  const tabs = [
    { id: 'conversation', label: 'Chat' },
    { id: 'brainstorm', label: 'Brainstorm' },
    { id: 'think', label: 'Think' },
    { id: 'search', label: 'Search' },
    { id: 'history', label: 'History' },
    { id: 'profile', label: 'Profile' },
  ];

  return (
    <nav className="navbar">
      <div className="nav-left">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`nav-button ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="nav-right">
        <span className="nav-username">Welcome, {username}</span>
        <button className="logout-button" onClick={onLogout}>Logout</button>
      </div>
    </nav>
  );
};

export default Navbar;
