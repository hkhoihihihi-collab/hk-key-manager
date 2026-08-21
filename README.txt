HK Key Manager - Render

1. Upload this project to a GitHub repository.
2. On Render: New > Web Service, connect the repo.
3. Build Command: npm install
4. Start Command: npm start
5. Add Environment Variable:
   ADMIN_PASSWORD = your_private_admin_password
6. Deploy. Render gives a public onrender.com URL.

Open that URL to manage keys.
API:
POST /api/verify  {"key":"HK-..."}
