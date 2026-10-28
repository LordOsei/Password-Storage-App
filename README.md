# Password Store

A small password manager for a personal/trusted-group use case. Passwords are stored directly as
Azure Key Vault secrets (no separate database); the web UI runs on Azure App Service so it's reachable
from both desktop and mobile browsers.

## How it works

- Each saved entry is a Key Vault secret named `pw-<uuid>`. The password is the secret value; the
  site, username, notes, owner and creation time are stored as secret **tags** so the list view never
  has to fetch a password value.
- The signed-in user's identity comes from Azure App Service Authentication (Easy Auth) via the
  `X-MS-CLIENT-PRINCIPAL-NAME` header in production. Every reveal/update/delete checks that the
  secret's `owner` tag matches the signed-in user, server-side — not just in the UI.
- The app authenticates to Key Vault with `DefaultAzureCredential`, which resolves to the App
  Service's managed identity in production and to your `az login` session locally.

## Local development

1. Create a separate **dev** Key Vault so testing never touches real passwords, and grant yourself
   the `Key Vault Secrets Officer` role on it (see Azure setup below).
2. `az login`
3. Copy `.env.example` to `.env` and fill in your dev vault URL:
   ```
   KEY_VAULT_URL=https://pwstore-kv-dev.vault.azure.net/
   AUTH_MODE=dev
   LOCAL_DEV_USER=you@example.com
   ```
4. ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
5. Run the app:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   Visit `http://localhost:8000`. With `AUTH_MODE=dev`, the app treats `LOCAL_DEV_USER` as the
   signed-in identity instead of reading the Easy Auth header, so the same ownership logic runs as in
   production.
6. Run tests:
   ```bash
   pytest
   ```

## Azure resource setup

```bash
az login
RG=password-storage-rg; LOCATION=eastus
VAULT_NAME=pwstore-kv-<unique>; APP_NAME=pwstore-app-<unique>; PLAN_NAME=pwstore-plan

az group create --name $RG --location $LOCATION
az keyvault create --name $VAULT_NAME --resource-group $RG --location $LOCATION

az role assignment create --role "Key Vault Secrets Officer" \
  --assignee <your-entra-email> --scope $(az keyvault show --name $VAULT_NAME --query id -o tsv)

az appservice plan create --name $PLAN_NAME --resource-group $RG --sku B1 --is-linux
az webapp create --resource-group $RG --plan $PLAN_NAME --name $APP_NAME --runtime "PYTHON:3.12"
az webapp config set --resource-group $RG --name $APP_NAME \
  --startup-file "gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 app.main:app"

az webapp identity assign --resource-group $RG --name $APP_NAME
PRINCIPAL_ID=$(az webapp identity show --resource-group $RG --name $APP_NAME --query principalId -o tsv)
az role assignment create --role "Key Vault Secrets Officer" \
  --assignee-object-id $PRINCIPAL_ID --assignee-principal-type ServicePrincipal \
  --scope $(az keyvault show --name $VAULT_NAME --query id -o tsv)

az webapp config appsettings set --resource-group $RG --name $APP_NAME --settings \
  KEY_VAULT_URL="https://$VAULT_NAME.vault.azure.net/" AUTH_MODE=header
```

### Enable Easy Auth (Portal)

1. App Service → **Authentication** → **Add identity provider** → **Microsoft**, single-tenant,
   require authentication, unauthenticated action = redirect.
2. Restrict sign-in to specific trusted people: **Entra admin center → Enterprise Applications** →
   find the new app registration → **Properties** → "Assignment required?" = **Yes** → **Users and
   groups** → add each trusted person.
3. If a trusted person doesn't have a Microsoft account, invite them as an Entra **B2B guest** (works
   with any email, including Gmail).

## Deployment

```bash
az webapp up --resource-group $RG --name $APP_NAME --runtime "PYTHON:3.12"
```

Re-run the same command for subsequent deploys.

## Verifying end-to-end

1. `curl -I https://$APP_NAME.azurewebsites.net/` while signed out → expect a redirect to
   `login.microsoftonline.com`.
2. Sign in as an allowed user → reach the app. Sign in as a non-assigned account → expect Entra to
   block with `AADSTS50105`.
3. Add an entry, confirm it appears in the list, click Reveal to confirm the password matches.
4. Sign in as a second allowed user (or run locally with a different `LOCAL_DEV_USER`) → confirm they
   don't see the first user's entries.
5. Edit only the notes on an entry → check in the Portal that no new secret version was created;
   change the password → confirm a new version is created.
6. Delete an entry → confirm it disappears from the list and shows under Key Vault's "Deleted
   secrets".
