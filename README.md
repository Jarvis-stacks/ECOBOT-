# ECOBOT-
Sustainable , reliable , cheap and intelligent Ai bot that can reason , brainstorm and search the web

Setup Instructions
1. Backend Setup
Prerequisites: Python 3.8+, pip
Install Dependencies:

pip install fastapi uvicorn requests python-dotenv

Create .env File: In the backend directory, create a .env file with your API keys:
SERP_API_KEY=your_serpapi_key_here
HF_TOKEN=your_huggingface_token_here

Obtain SERP_API_KEY from SerpAPI.
Obtain HF_TOKEN from Hugging Face.

Run the Backend:
cd backend
uvicorn main:app --reload

The backend will run at http://localhost:8000.
2. Frontend Setup
Prerequisites: Node.js, npm
Initialize React Project:

npx create-react-app frontend --template typescript
cd frontend

Replace src Files: Copy the App.tsx, QueryForm.tsx, and ResultDisplay.tsx files into frontend/src/.
Run the Frontend:

npm start

The frontend will run at http://localhost:3000.

How to Use
Start the backend server (uvicorn main:app --reload).
Start the frontend (npm start).
Open your browser to http://localhost:3000.
Enter a query (e.g., "sustainable energy solutions") in the input field and click "Submit".
The frontend sends the query to the backend, which fetches search results via SerpAPI, processes them with the Hugging Face model, and returns brainstorming ideas displayed on the page.

Error Handling
Backend: Returns "No search results found" or "Failed to generate ideas" if APIs fail.
Frontend: Displays "Error processing query" if the API call fails.
