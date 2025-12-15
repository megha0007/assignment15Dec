from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import JSONResponse
from auth import verify_slack_request, check_user_permission
from snowflake_service import onboard_user, reset_password
import os

app = FastAPI()

# Set an environment variable to toggle Slack verification locally
VERIFY_SLACK = os.getenv("VERIFY_SLACK", "False").lower() == "true"

@app.post("/slack/command")
async def slack_command(
    command: str = Form(...),
    text: str = Form(""),
    user_id: str = Form(...),
    x_slack_signature: str = Header(None),
    x_slack_request_timestamp: str = Header(None)
):
    # Slack verification (optional for local testing)
    if VERIFY_SLACK:
        if not x_slack_signature or not x_slack_request_timestamp:
            return JSONResponse({"text": "Slack headers missing"}, status_code=400)

        # Reconstruct the body for signature verification manually
        from urllib.parse import urlencode
        form_dict = {
            "command": command,
            "text": text,
            "user_id": user_id
        }
        body_str = urlencode(form_dict)
        verify_slack_request(x_slack_request_timestamp, body_str, x_slack_signature)

    # Validate command
    if command != "/snowflake":
        return JSONResponse({"text": "Unknown command"}, status_code=200)

    args = text.split()
    if not args:
        return {
            "response_type": "ephemeral",
            "text": "Usage:\n/snowflake onboard_user <username> <role>\n/snowflake reset_password <username>"
        }

    action = args[0]

    # Check RBAC (skip if testing locally)
    if VERIFY_SLACK:
        check_user_permission(user_id, action)

    # Handle actions
    if action == "onboard_user" and len(args) == 3:
        username = args[1]
        role = args[2]
        temp_password = onboard_user(username, role)
        return {
            "response_type": "ephemeral",
            "text": f"User *{username}* onboarded with role *{role}*\n🔐 Temporary password: `{temp_password}`"
        }

    elif action == "reset_password" and len(args) == 2:
        username = args[1]
        new_password = reset_password(username)
        return {
            "response_type": "ephemeral",
            "text": f"Password reset triggered for *{username}*\n📌 New password: `{new_password}`"
        }

    else:
        return {
            "response_type": "ephemeral",
            "text": "Invalid command format"
        }








