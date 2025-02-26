// Profile.tsx - Component to display user profile

import React, { useState, useEffect } from 'react';
import '../styles/components.css';

interface ProfileProps {
  token: string;
}

interface ProfileData {
  username: string;
  email: string;
  full_name: string;
  disabled: boolean;
  created_at: string;
  last_login: string | null;
}

const Profile: React.FC<ProfileProps> = ({ token }) => {
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await fetch('http://localhost:8000/profile', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) throw new Error('Failed to fetch profile');
        const data = await response.json();
        setProfile(data);
      } catch (err: any) {
        setError(err.message || 'Failed to load profile');
      } finally {
        setIsLoading(false);
      }
    };
    fetchProfile();
  }, [token]);

  return (
    <div className="feature-container">
      <h2>Your Profile</h2>
      {isLoading ? (
        <p>Loading profile...</p>
      ) : error ? (
        <p className="error-text">{error}</p>
      ) : profile ? (
        <div className="profile-details">
          <p><strong>Username:</strong> {profile.username}</p>
          <p><strong>Email:</strong> {profile.email}</p>
          <p><strong>Full Name:</strong> {profile.full_name}</p>
          <p><strong>Account Status:</strong> {profile.disabled ? 'Disabled' : 'Active'}</p>
          <p><strong>Joined:</strong> {new Date(profile.created_at).toLocaleDateString()}</p>
          <p><strong>Last Login:</strong> {profile.last_login ? new Date(profile.last_login).toLocaleString() : 'Never'}</p>
        </div>
      ) : (
        <p>No profile data available.</p>
      )}
    </div>
  );
};

export default Profile;
