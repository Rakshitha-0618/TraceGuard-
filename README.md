# TraceGuard – Separate Frontend and Backend (RBAC)

## Structure
- `client/` – Vite frontend, http://localhost:5173
- `server/` – Express API + MongoDB, http://localhost:5000
- `docs/` – RBAC test plan and architecture notes

## Requirements
Node.js 18+, MongoDB Atlas account (or local MongoDB), VS Code recommended.

## MongoDB setup
1. Create a MongoDB Atlas free cluster.
2. Create a database user and save its password.
3. Add your current IP in Network Access.
4. Copy the Node.js driver connection string.
5. Copy `server/.env.example` to `server/.env`.
6. Set `MONGODB_URI` with database name `traceguard`.
7. Set a long random `JWT_SECRET`.

## Start backend (Terminal 1)
```powershell
cd server
npm install
npm run seed
npm run dev
```
API: http://localhost:5000/api/health

## Start frontend (Terminal 2)
```powershell
cd client
npm install
```
Copy `client/.env.example` to `client/.env`, then run:
```powershell
npm run dev
```
Open http://localhost:5173. Keep both terminals open.

## Demo users
Password for all: `TraceGuard@123`
- admin@traceguard.local
- investigator@traceguard.local
- reporter@traceguard.local

## Correct RBAC flow
1. Reporter submits a complaint.
2. Admin sees it immediately.
3. Investigator does not see the complaint before assignment.
4. Admin selects an investigator and clicks **Assign / reassign**.
5. The complaint appears in that investigator's dashboard.
6. Investigator can update status and add internal notes only on assigned cases.
7. Reporter sees only their own complaints.

Backend authorization enforces role, reporter ownership and investigator assignment; hiding UI controls is not the security boundary. Evidence uploads are limited to 10 MB and SHA-256 is calculated server-side.

## Notes
Educational semester project only. Production use requires audit trails, malware scanning, secure file access, encryption, backups, rate limiting and security review.
