# Flask Backoffice with Claude AI Integration

## Features
- User authentication (simple demo)
- Dashboard to send prompts to Claude (Anthropic API)
- Claude's responses displayed in the dashboard
- Basic task management UI (to be extended)

## Setup
1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Set environment variables:
   - `SECRET_KEY` (for Flask sessions)
   - `CLAUDE_API_KEY` (your Anthropic Claude API key)
3. Run the app:
   ```
   python -m app
   ```

## File Structure
- `app/__init__.py` - Main Flask app
- `app/claude.py` - Claude API integration
- `app/templates/` - HTML templates
- `app/static/` - CSS and static files

## Next Steps
- Improve authentication
- Add persistent task management
- Enhance error handling and UI

---
Replace demo credentials and add production security before deploying.
