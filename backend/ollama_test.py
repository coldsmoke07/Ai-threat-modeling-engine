import requests

try:
    from ollama_utils import select_model
except ImportError:
    def select_model():
        return "qwen3:4b"

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = select_model()

payload = {
    "model": MODEL_NAME,
    "messages": [
        {
            "role": "user",
            "content": "Reply only with: PYTHON OLLAMA CONNECTION WORKING"
        }
    ],
    "stream": False
}

try:
    print(f"Connecting to Ollama (model: {MODEL_NAME})...")

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()
    answer = data["message"]["content"]

    print("\nAI Response:")
    print(answer)

    print("\nOllama connection successful!")

except requests.exceptions.ConnectionError:
    print("\nERROR: Cannot connect to Ollama.")
    print("Make sure Ollama is running.")

except requests.exceptions.Timeout:
    print("\nERROR: Ollama took too long to respond.")

except Exception as error:
    print("\nERROR:")
    print(error)