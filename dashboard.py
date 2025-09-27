import streamlit as st
import json
import email
from email import policy
from email.parser import BytesParser
import io

# ---------------------------
# Email analyzer (simplified)
# ---------------------------
def analyze_email_file(uploaded_file):
    try:
        # Read file as bytes
        raw_bytes = uploaded_file.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        # Extract metadata
        from_ = msg.get("From", "")
        to_ = msg.get("To", "")
        subject = msg.get("Subject", "")
        reply_to = msg.get("Reply-To")
        received_headers = msg.get_all("Received", [])
        attachments = []

        # Extract attachments
        for part in msg.iter_attachments():
            attachments.append(part.get_filename())

        # Naive rule-based phishing score
        suspicious_keywords = ["verify", "urgent", "update", "login", "password"]
        keyword_hits = sum(1 for kw in suspicious_keywords if kw.lower() in subject.lower())

        score = keyword_hits * 2
        verdict = "phishing" if score >= 4 else "benign"

        result = {
            "from": from_,
            "to": to_,
            "subject": subject,
            "reply_to": reply_to,
            "received_headers": received_headers,
            "attachment_names": attachments,
            "suspicious_keyword_count": keyword_hits,
            "final_score": score,
            "verdict": verdict,
            "severity": "high" if verdict == "phishing" else "low",
        }

        return result

    except Exception as e:
        st.error(f"Error parsing uploaded file: {e}")
        return None


# ---------------------------
# Streamlit App
# ---------------------------
def main():
    st.set_page_config(page_title="Phishing Email Detector", layout="wide")
    st.title("📧 Phishing Email Detector (Upload Mode)")

    st.write("Upload a `.eml` or `.txt` email file to analyze for phishing indicators.")

    uploaded_file = st.file_uploader("Choose an email file", type=["eml", "txt"])

    if uploaded_file is not None:
        st.info(f"Analyzing: {uploaded_file.name}")

        result = analyze_email_file(uploaded_file)

        if result:
            st.subheader("📊 Detection Result")
            st.json(result)

            st.subheader("📋 Summary")
            col1, col2, col3 = st.columns(3)
            col1.metric("Final Score", result["final_score"])
            col2.metric("Verdict", result["verdict"])
            col3.metric("Severity", result["severity"])

            if result["suspicious_keyword_count"] > 0:
                st.warning(f"⚠ Found {result['suspicious_keyword_count']} suspicious keyword(s) in subject")
            else:
                st.success("✅ No suspicious keywords found")

            if result["attachment_names"]:
                st.error(f"⚠ Attachments detected: {', '.join(result['attachment_names'])}")
            else:
                st.success("✅ No suspicious attachments")

    else:
        st.info("Please upload an email file to start analysis.")


if __name__ == "__main__":
    main()
