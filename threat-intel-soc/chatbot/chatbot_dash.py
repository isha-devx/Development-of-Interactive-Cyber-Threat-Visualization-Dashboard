import dash
from dash import html, dcc, Input, Output, State, callback
import uuid
from chatbot.chatbot_service import get_bot_response

# Store chat sessions
chat_sessions = {}

def create_chatbot_component():
    """Create a Dash-compatible chatbot component"""
    
    # Generate unique ID for this chat instance
    chat_id = str(uuid.uuid4())[:8]
    chat_sessions[chat_id] = []
    
    return html.Div([
        # Floating chat button
        html.Button(
            "💬",
            id=f"chat-toggle-{chat_id}",
            className="floating-chat-btn",
            n_clicks=0
        ),
        
        # Chat container (initially hidden)
        html.Div(
            id=f"chat-container-{chat_id}",
            className="chat-popup",
            children=[
                html.Div(
                    className="chat-header",
                    children=[
                        html.Span("🤖 SOC Assistant", className="chat-title"),
                        html.Button("×", id=f"close-chat-{chat_id}", className="close-btn")
                    ]
                ),
                html.Div(
                    id=f"chat-messages-{chat_id}",
                    className="chat-messages"
                ),
                html.Div(
                    className="chat-input-area",
                    children=[
                        dcc.Input(
                            id=f"chat-input-{chat_id}",
                            type="text",
                            placeholder="Type your message...",
                            className="chat-input"
                        ),
                        html.Button("Send", id=f"send-btn-{chat_id}", className="send-btn")
                    ]
                )
            ],
            style={"display": "none"}
        )
    ])

# Callbacks for chat functionality
def register_chatbot_callbacks(app):
    """Register all chatbot callbacks with the Dash app"""
    
    @app.callback(
        Output({"type": "chat-container", "index": dash.ALL}, "style"),
        Input({"type": "chat-toggle", "index": dash.ALL}, "n_clicks"),
        State({"type": "chat-container", "index": dash.ALL}, "style"),
        prevent_initial_call=True
    )
    def toggle_chat(n_clicks, styles):
        """Toggle chat visibility"""
        if not n_clicks or n_clicks[0] % 2 == 0:
            return [{"display": "none"}]
        else:
            return [{"display": "block"}]
    
    @app.callback(
        Output({"type": "chat-messages", "index": dash.ALL}, "children"),
        Input({"type": "send-btn", "index": dash.ALL}, "n_clicks"),
        State({"type": "chat-input", "index": dash.ALL}, "value"),
        State({"type": "chat-messages", "index": dash.ALL}, "children"),
        prevent_initial_call=True
    )
    def send_message(n_clicks, user_input, current_messages):
        """Handle sending messages"""
        if not user_input or not user_input.strip():
            return [current_messages]
            
        # Get bot response
        bot_response = get_bot_response(user_input.strip())
        
        # Create message elements
        new_messages = current_messages or []
        new_messages.extend([
            html.Div([
                html.Strong("You: "),
                user_input.strip()
            ], className="user-message"),
            html.Div([
                html.Strong("Bot: "),
                bot_response
            ], className="bot-message")
        ])
        
        return [new_messages]

# Add CSS styles
def add_chatbot_styles(app):
    """Add required CSS styles for the chatbot"""
    app.css.append_css({
        "external_url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
    })
    
    # Custom CSS
    chat_css = """
    .floating-chat-btn {
        position: fixed;
        bottom: 25px;
        right: 25px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background-color: #2563eb;
        color: white;
        font-size: 26px;
        border: none;
        cursor: pointer;
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        z-index: 9999;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .chat-popup {
        position: fixed;
        bottom: 100px;
        right: 25px;
        width: 350px;
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.25);
        z-index: 9999;
        display: none;
    }
    
    .chat-header {
        padding: 15px;
        background: #2563eb;
        color: white;
        border-radius: 12px 12px 0 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .chat-title {
        font-weight: 600;
        font-size: 16px;
    }
    
    .close-btn {
        background: none;
        border: none;
        color: white;
        font-size: 20px;
        cursor: pointer;
        padding: 0;
        width: 25px;
        height: 25px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .chat-messages {
        padding: 15px;
        max-height: 300px;
        overflow-y: auto;
    }
    
    .user-message {
        margin-bottom: 10px;
        padding: 8px 12px;
        background: #f0f9ff;
        border-radius: 8px;
        font-size: 14px;
    }
    
    .bot-message {
        margin-bottom: 10px;
        padding: 8px 12px;
        background: #f1f5f9;
        border-radius: 8px;
        font-size: 14px;
    }
    
    .chat-input-area {
        padding: 15px;
        border-top: 1px solid #e2e8f0;
        display: flex;
        gap: 10px;
    }
    
    .chat-input {
        flex: 1;
        padding: 10px;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        font-size: 14px;
    }
    
    .send-btn {
        padding: 10px 15px;
        background: #2563eb;
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-size: 14px;
    }
    
    .send-btn:hover {
        background: #1d4ed8;
    }
    """
    
    app.css.append_css({"content": chat_css})