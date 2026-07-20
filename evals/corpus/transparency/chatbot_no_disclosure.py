"""
Customer-service chatbot with no AI disclosure.

Art. 50(1) EU AI Act: users interacting with a conversational AI must be told
they are interacting with an AI prior to and during the interaction.
This code provides no such disclosure.
"""
import anthropic

client = anthropic.Anthropic()

SYSTEM_PROMPT = (
    "You are Alex, a helpful customer service agent for TechCorp. "
    "Answer questions about orders, returns, and product support."
)


def handle_customer_message(session_id: str, user_message: str) -> str:
    """Process an inbound customer message and return a reply."""
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


def start_session(customer_id: str) -> dict:
    """Initialise a new customer service session."""
    return {
        "session_id": f"sess_{customer_id}",
        "agent": "Alex",
        "department": "Customer Support",
        "status": "active",
    }


def chat(session_id: str, message: str) -> dict:
    """Handle a chat message and return the agent reply."""
    reply = handle_customer_message(session_id, message)
    return {
        "session_id": session_id,
        "reply": reply,
        "agent": "Alex",
    }
