
# ECOBOT

Welcome to **ECOBOT**, an open-source, AI-powered chatbot designed to be cost-effective, reliable, and sustainable. Built with FastAPI on Python, ECOBOT leverages external APIs like Hugging Face for natural language processing and SerpAPI for web search capabilities. Whether you need to brainstorm ideas, search the web, or engage in thoughtful conversations, ECOBOT has you covered—all while keeping resource usage low by offloading heavy computation to cloud services.

This project is modular and future-ready, with plans to integrate the GORK open-source API or a custom API down the line. Contributions are welcome—fork the repo, explore the code, and help make ECOBOT even better!

---

## Features

- **User Authentication**: Secure login with JWT tokens and password hashing.
- **Multi-Turn Conversations**: Engage in context-aware chats with persistent history stored in SQLite.
- **Web Search**: Fetch real-time results using SerpAPI, integrated into brainstorming and responses.
- **Brainstorming**: Generate creative ideas by combining web search data with AI insights.
- **Thoughtful Analysis**: Get detailed, thoughtful responses on any topic.
- **Rate Limiting**: Protects the backend with configurable limits (e.g., 50 conversation messages per hour per IP).
- **Health Monitoring**: Check backend status with the `/health` endpoint.
- **Scalability**: Modular design supports future API integrations (e.g., GORK).
- **Open-Source**: All code and tools are freely available under [insert license, e.g., MIT].
- **Cost-Effective & Sustainable**: Uses cloud APIs to minimize local hardware needs.

---

## Project Structure

```
ECOBOT/
├── backend/
│   ├── main.py           # FastAPI backend code
│   ├── requirements.txt  # Python dependencies
│   ├── .env.example      # Template for environment variables
│   └── eco_bot.db        # SQLite database (created on first run)
└── frontend/             # (Optional) React/TypeScript frontend (not included here)
```

---

## Prerequisites

Before setting up ECOBOT, ensure you have:
- **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/).
- **Git**: Install from [git-scm.com](https://git-scm.com/).
- **API Keys**:
  - Hugging Face API Token: Get from [Hugging Face](https://huggingface.co/settings/tokens).
  - SerpAPI Key: Get from [SerpAPI](https://serpapi.com/).

---

## Setup Instructions

Follow these steps to set up the ECOBOT backend on your local machine:

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/ECOBOT.git
cd ECOBOT/backend
```

### 2. Set Up a Virtual Environment
Using a virtual environment keeps dependencies isolated:
```bash
python -m venv venv
```
- Activate it:
  - **Windows**: `venv\Scripts\activate`
  - **Linux/Mac**: `source venv/bin/activate`
- You’ll see `(venv)` in your terminal prompt.

### 3. Install Dependencies
Install all required Python packages listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```
This installs:
- `fastapi`: Web framework
- `uvicorn`: ASGI server
- `requests`: HTTP client for API calls
- `python-dotenv`: Environment variable management
- `python-jose[cryptography]`: JWT authentication
- `passlib[bcrypt]`: Password hashing
- `sqlalchemy`: Database ORM
- `slowapi`: Rate limiting

If you encounter issues, ensure `pip` matches your Python version (e.g., `pip3`).

### 4. Configure Environment Variables
Create a `.env` file in the `backend/` directory to store API keys:
```bash
echo "HF_TOKEN=your_huggingface_token_here" > .env
echo "SERP_API_KEY=your_serpapi_key_here" >> .env
```
- Replace `your_huggingface_token_here` and `your_serpapi_key_here` with your actual keys.
- **Note**: Do not commit `.env` to GitHub; use `.env.example` as a template instead.

### 5. Run the Application
Start the FastAPI server:
```bash
uvicorn main:app --reload
```
- The `--reload` flag enables auto-reloading during development.
- Access the API at `http://localhost:8000`.

---

## Usage

Once the backend is running, you can interact with ECOBOT via HTTP requests (e.g., using curl, Postman, or a frontend).

### Endpoints
- **Login**: Authenticate and get a JWT token
  - `POST /token`
  - Body: `username=johndoe&password=secret`
  - Response: `{"access_token": "...", "token_type": "bearer"}`
- **Conversation**: Chat with ECOBOT
  - `POST /converse`
  - Headers: `Authorization: Bearer <token>`
  - Body: `{"message": "Hello, how are you?"}`
- **Brainstorm**: Generate ideas
  - `POST /brainstorm`
  - Body: `{"query": "sustainable energy solutions"}`
- **Think**: Get a thoughtful response
  - `POST /think`
  - Body: `{"topic": "future of AI"}`
- **Search**: Fetch web results
  - `POST /search`
  - Body: `{"query": "latest tech trends"}`
- **History**: View conversation history
  - `GET /history`
- **Profile**: Get user info
  - `GET /profile`
- **Health**: Check backend status
  - `GET /health`

### Example with curl
```bash
# Get token
curl -X POST "http://localhost:8000/token" -d "username=johndoe&password=secret"

# Converse (replace <token> with the returned access_token)
curl -X POST "http://localhost:8000/converse" -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"message": "Tell me about space exploration"}'
```

### Rate Limits
- `/token`: 10/minute
- `/converse`: 50/hour
- `/brainstorm`: 20/hour
- `/think`: 15/hour
- `/search`: 25/hour
- `/history`: 30/hour
- `/profile`: 50/hour
- `/health`: 100/hour
- Default: 100/hour
- Exceeding limits returns a `429 Too Many Requests` error.

---

## Troubleshooting

- **"pip not found"**: Use `pip3` or ensure Python is installed correctly.
- **Module Not Found**: Verify the virtual environment is active and `requirements.txt` was installed.
- **API Errors**: Check `.env` for correct API keys.
- **Port Conflict**: Change the port with `uvicorn main:app --port 8001 --reload`.

---

## Future Plans

- **GORK API Integration**: Replace Hugging Face with GORK when available.
- **Custom API**: Develop an ECOBOT-specific API for advanced features.
- **Frontend**: Add a React/TypeScript UI (in progress).
- **Database Upgrade**: Switch to PostgreSQL for production scalability.
- **Caching**: Implement Redis for faster responses.

---

## Contributing

We’d love your help! Here’s how:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

Report bugs or suggest features via [Issues](https://github.com/your-username/ECOBOT/issues).

---


## Contact

- **Author**: Pavan Sai (Jarvis)
- **GitHub**: https://github.com/Jarvis-stacks


Happy coding with ECOBOT!
```

-

