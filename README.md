# TrancheReady — Final

**CSV in → Signed ZIP out** for AU DNFBPs (Tranche-2).  
No env vars. No credentials. Works on Render by just deploying.

## Run
- Build: `npm ci`
- Start: `npm start`
- Open: `https://<your-render-app>/`

## What you get
- Upload Clients.csv + Transactions.csv
- Validate structure & mapping
- Generate explainable risk + monitoring cases
- Evidence ZIP (clients.json, transactions.json, cases.json, program.html, manifest.json)
- Read-only verify link

## Deploy (Render)
Create a **Web Service**:
- Build Command: `npm ci`
- Start Command: `npm start`
- Node: 18–22

No environment variables required.
