import streamlit as st
import time
from guardrail import HealthcareCausalGuardrail

st.set_page_config(
    page_title="Muzan Healthcare Guardrail",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Muzan Healthcare: Live Guardrail Chat")
st.markdown("Test clinical safety, prompt injections, base64 payloads, and restricted substances in real-time.")

# Initialize guardrail instance in session state
if "guard" not in st.session_state:
    st.session_state.guard = HealthcareCausalGuardrail(max_mutations=1)

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input from user
if prompt := st.chat_input("Type a clinical note, query, or attack payload here..."):
    # Append user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Inspect request through Muzan Guardrail
    with st.chat_message("assistant"):
        with st.spinner("Inspecting request through Muzan engine..."):
            start_time = time.perf_counter()
            res = st.session_state.guard.inspect_request(prompt, session_id="streamlit_chat_session")
            elapsed_us = (time.perf_counter() - start_time) * 1_000_000
            
            decision = res.get("decision", "PASS")
            status_icon = "🟢 ALLOWED (Safe)" if decision == "PASS" else "🔴 BLOCKED (Unsafe/Adversarial)"
            
            # Format response details
            response_md = f"""### Guardrail Inspection Result
* **Decision**: {status_icon}
* **Latency**: `{elapsed_us:.2f} µs`
* **Raw Response**: `{res}`
"""
            st.markdown(response_md)
            st.session_state.messages.append({"role": "assistant", "content": response_md})