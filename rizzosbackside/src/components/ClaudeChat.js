import React, { useState } from "react";
import axios from "axios";

const ClaudeChat = ({ domain, referralLink, stripeLink }) => {
  const [messages, setMessages] = useState([
    {
      sender: "claude",
      text: `👋 Welcome to RizzosAI, where your journey to wealth begins! Your domain: ${domain}. Share your link to start earning: ${referralLink}. To get paid, click your Stripe link and enter your payout details. Need help? Just ask!`
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const sendMessage = async () => {
    if (!input.trim()) return;
    setMessages([...messages, { sender: "user", text: input }]);
    setLoading(true);
    try {
      const res = await axios.post("/claude/chat", { prompt: input });
      setMessages((msgs) => [
        ...msgs,
        { sender: "claude", text: res.data.reply || "Sorry, I didn't get that." }
      ]);
    } catch (err) {
      setMessages((msgs) => [
        ...msgs,
        { sender: "claude", text: "Sorry, there was an error contacting Claude." }
      ]);
    }
    setInput("");
    setLoading(false);
  };

  return (
    <div style={{
      border: "2px solid #4f46e5",
      borderRadius: 12,
      padding: 20,
      maxWidth: 400,
      background: "#f8fafc",
      position: "relative"
    }}>
      <div style={{
        position: "absolute",
        top: 10,
        right: 20,
        fontWeight: "bold",
        color: "#4f46e5"
      }}>
        {domain}
      </div>
      <h2 style={{ color: "#4f46e5", marginBottom: 10 }}>Claude (RizzosAI Guide)</h2>
      <div style={{ minHeight: 120, marginBottom: 10 }}>
        {messages.map((msg, i) => (
          <div key={i} style={{
            textAlign: msg.sender === "user" ? "right" : "left",
            margin: "6px 0"
          }}>
            <span style={{
              background: msg.sender === "user" ? "#e0e7ff" : "#fff",
              padding: "6px 12px",
              borderRadius: 8,
              display: "inline-block"
            }}>
              {msg.text}
            </span>
          </div>
        ))}
      </div>
      <input
        type="text"
        value={input}
        disabled={loading}
        onChange={e => setInput(e.target.value)}
        onKeyDown={e => e.key === "Enter" && sendMessage()}
        placeholder="Ask Claude anything…"
        style={{
          width: "70%",
          padding: 8,
          borderRadius: 6,
          border: "1px solid #c7d2fe",
          marginRight: 8
        }}
      />
      <button
        onClick={sendMessage}
        disabled={loading}
        style={{
          background: "#4f46e5",
          color: "#fff",
          border: "none",
          borderRadius: 6,
          padding: "8px 16px",
          cursor: "pointer"
        }}
      >
        {loading ? "Sending..." : "Send"}
      </button>
      <div style={{ marginTop: 16, fontSize: 14 }}>
        <b>Your referral link:</b> <a href={referralLink}>{referralLink}</a><br />
        <b>Get paid:</b> <a href={stripeLink}>Set up Stripe payout</a>
      </div>
    </div>
  );
};

export default ClaudeChat;
