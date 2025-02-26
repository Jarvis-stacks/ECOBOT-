// index.ts - TypeScript type definitions

export interface User {
  username: string;
  email: string;
  fullName: string;
}

export interface Session {
  id: string;
  userId: number;
  createdAt: string;
  expiresAt: string;
  lastActivity: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  session_id: string;
}

export interface HistoryItem {
  role: string;
  content: string;
  timestamp: string;
  metadata?: any;
}
