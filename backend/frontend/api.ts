// api.ts - Utility functions for API requests

import { LoginResponse, HistoryItem } from '../types';

export const login = async (username: string, password: string): Promise<LoginResponse> => {
  const response = await fetch('http://localhost:8000/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Login failed');
  }
  return response.json();
};

export const logout = async (token: string, sessionId: string): Promise<void> => {
  const response = await fetch('http://localhost:8000/logout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ session_id: sessionId })
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Logout failed');
  }
};

export const sendMessage = async (token: string, sessionId: string, message: string): Promise<any> => {
  const response = await fetch('http://localhost:8000/converse', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ message, session_id: sessionId })
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to send message');
  }
  return response.json();
};

export const brainstorm = async (token: string, query: string): Promise<any> => {
  const response = await fetch('http://localhost:8000/brainstorm', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ query })
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to brainstorm');
  }
  return response.json();
};

export const think = async (token: string, topic: string): Promise<any> => {
  const response = await fetch('http://localhost:8000/think', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ topic })
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to think');
  }
  return response.json();
};

export const search = async (token: string, query: string): Promise<any> => {
  const response = await fetch('http://localhost:8000/search', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ query })
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to search');
  }
  return response.json();
};

export const getHistory = async (token: string): Promise<{ history: HistoryItem[] }> => {
  const response = await fetch('http://localhost:8000/history', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to fetch history');
  }
  return response.json();
};
