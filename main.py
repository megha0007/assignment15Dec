from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import JSONResponse
from auth import verify_slack_request, check_user_permission
from snowflake_service import onboard_user, reset_password
import os

app = FastAPI()

VERIFY_SLACK = os.getenv("VERIFY_SLACK", "False").lower() == "true"


@app.get("/")
def health():
    return {"status": "running"}


@app.post("/slack/command")
async def slack_command(
    request: Request,
    command: str = Form(...),
    text: str = Form(""),
    user_id: str = Form(...),
    x_slack_signature: str = Header(None),
    x_slack_request_timestamp: str = Header(None)
):
    #  Slack request verification
    if VERIFY_SLACK:
        if not x_slack_signature or not x_slack_request_timestamp:
            return JSONResponse({"text": "Slack headers missing"}, status_code=400)

        raw_body = await request.body()
        verify_slack_request(
            x_slack_request_timestamp,
            raw_body,
            x_slack_signature
        )

    # Validate command
    if command != "/snowflake":
        return {"text": "Unknown command"}

    args = text.split()
    if not args:
        return {
            "response_type": "ephemeral",
            "text": (
                "Usage:\n"
                "/snowflake onboard_user <username> <role>\n"
                "/snowflake reset_password <username>"
            )
        }

    action = args[0]

    #  RBAC check
    if VERIFY_SLACK:
        check_user_permission(user_id, action)

    #  Command handling
    if action == "onboard_user" and len(args) == 3:
        username, role = args[1], args[2]
        temp_password = onboard_user(username, role)
        return {
            "response_type": "ephemeral",
            "text": (
                f"User *{username}* onboarded with role *{role}*\n"
                f"🔐 Temporary password: `{temp_password}`"
            )
        }

    if action == "reset_password" and len(args) == 2:
        username = args[1]
        new_password = reset_password(username)
        return {
            "response_type": "ephemeral",
            "text": (
                f"Password reset triggered for *{username}*\n"
                f" New password: `{new_password}`"
            )
        }

    return {
        "response_type": "ephemeral",
        "text": "Invalid command format"
    }
