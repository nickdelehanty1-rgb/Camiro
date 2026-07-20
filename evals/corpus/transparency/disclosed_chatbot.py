"""
Customer-service chatbot with explicit AI disclosure.

Art. 50(1) EU AI Act: this chatbot correctly informs users they are interacting
with an AI at the start of every conversation. No high-severity Art. 50 finding
should be triggered.
"""
import anthropic

client = anthropic.Anthropic()

AI_DISCLOSURE = (
    "Hi! I am an AI assistant, not a human customer service agent. "
    "I can help with orders, returns, and product support. "
    "For complex issues, I can escalate to a human agent."
)

SYSTEM_PROMPT = (
    "You are an AI assistant for TechCorp customer support. "
    "Always be transparent that you are an AI and not a human. "
    "If a user asks whether you are a human, confirm you are an AI."
)


def start_session(customer_id: str) -> dict:
    """Initialise a session and return the AI disclosure message."""
    return {
        "session_id": f"sess_{customer_id}",
        "is_ai": True,
        "ai_disclosure": AI_DISCLOSURE,
        "ai_powered": True,
        "status": "active",
    }


def handle_customer_message(session_id: str, user_message: str) -> str:
    """Process an inbound customer message and return a reply."""
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


def chat(session_id: str, message: str) -> dict:
    """Handle a chat message and return the AI agent reply."""
    reply = handle_customer_message(session_id, message)
    return {
        "session_id": session_id,
        "reply": reply,
        "is_ai": True,
        "ai_flag": True,
    }
