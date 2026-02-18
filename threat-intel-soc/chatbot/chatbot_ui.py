import streamlit as st
from chatbot.chatbot_service import get_bot_response

def render_floating_chatbot():

    if "chat_open" not in st.session_state:
        st.session_state.chat_open = False

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    # ---------- CSS ----------
    st.markdown("""
    <style>
    .floating-btn {
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
    }

    .chat-container {
        position: fixed;
        bottom: 100px;
        right: 25px;
        width: 330px;
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.25);
        padding: 12px;
        z-index: 9999;
    }

    .chat-header {
        font-weight: 600;
        margin-bottom: 8px;
    }

    .chat-msg {
        font-size: 14px;
        margin-bottom: 6px;
    }
    </style>
    """, unsafe_allow_html=True)

    # ---------- Floating Button ----------
    if st.button("💬", key="floating_chat_btn"):
        st.session_state.chat_open = not st.session_state.chat_open

    # ---------- Chat Window ----------
    if st.session_state.chat_open:
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)

        st.markdown("<div class='chat-header'>🤖 SOC Assistant</div>", unsafe_allow_html=True)

        user_input = st.text_input("Type your message", key="chat_input")

        if st.button("Send", key="send_chat"):
            if user_input.strip():
                reply = get_bot_response(user_input)
                st.session_state.chat_messages.append(("You", user_input))
                st.session_state.chat_messages.append(("Bot", reply))

        for sender, msg in st.session_state.chat_messages[-6:]:
            st.markdown(f"<div class='chat-msg'><b>{sender}:</b> {msg}</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)
