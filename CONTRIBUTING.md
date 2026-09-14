# Contributing to the Umbrella IT Group fork of MetaMCP

This is a maintained downstream fork of [metatool-ai/metamcp](https://github.com/metatool-ai/metamcp). The `umbrella` branch is the default and deployable line; `main` mirrors upstream and never carries our changes. [`UMBRELLA_FORK.md`](UMBRELLA_FORK.md) explains the branch model and records every patch we carry.

## Where to send things

- **Bugs and feature requests:** open a [GitHub Issue](https://github.com/Umbrella-IT-Group/metamcp/issues). Templates for both are provided.
- **Questions and ideas:** use [GitHub Discussions](https://github.com/Umbrella-IT-Group/metamcp/discussions).
- **Security vulnerabilities:** do not open a public issue. Follow [`SECURITY.md`](SECURITY.md) (private advisory or email).
- **Problems in upstream MetaMCP that are not specific to this fork:** report them to [metatool-ai/metamcp](https://github.com/metatool-ai/metamcp/issues). If you are not sure which side a problem belongs to, open it here and we will route it.

When reporting a bug, include how you are running the fork (prebuilt image tag or commit, the repo's compose file or your own), the exact error text, and what you expected. Redact secrets and internal hostnames.

## Development setup

1. Clone the repository. `umbrella` is the default branch, so a plain clone lands on the deployable line:
   ```bash
   git clone https://github.com/Umbrella-IT-Group/metamcp.git
   cd metamcp
   ```

2. Install dependencies:
   ```bash
   pnpm install
   ```

3. Set up the environment. Read the comments in `example.env` first: `POSTGRES_PASSWORD`, `BETTER_AUTH_SECRET`, and the bootstrap account have placeholders, not usable defaults.
   ```bash
   cp example.env .env
   ```

4. Start development:
   ```bash
   pnpm dev
   ```

### Docker development with hot reload

For development in Docker with hot reloading for both frontend and backend:

```bash
# Start development environment with hot reload
pnpm run dev:docker

# Stop development environment
pnpm run dev:docker:down

# Clean up development environment (removes volumes)
pnpm run dev:docker:clean
```

What you get:
- Hot reload for the frontend (Next.js) and the backend (Express) on code changes
- A full containerized environment with PostgreSQL
- Ports: frontend on 12008, backend on 12009, PostgreSQL on 9433
- All development dependencies and tools inside the container

Requirements:
- Docker and Docker Compose installed
- A `.env` file (copy from `example.env`)

The first run builds the development image and takes longer. Later runs are faster.

## OpenID Connect (OIDC) Provider Setup

MetaMCP supports OpenID Connect authentication for enterprise SSO integration. This is optional and can be configured alongside the default email/password authentication.

### Configuration

To enable OIDC authentication, add the following environment variables to your `.env` file:

#### Required Variables
```bash
OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
OIDC_DISCOVERY_URL=https://your-provider.com/.well-known/openid-configuration
```

For now full endpoints discovery is not supported, so you'll need to provide the authorization endpoint:
```bash
OIDC_AUTHORIZATION_URL=https://your-provider.com/auth/authorize
```

#### Optional Configuration
```bash
OIDC_PROVIDER_ID=oidc                    # Default: "oidc"
OIDC_SCOPES=openid email profile         # Default: "openid email profile"
OIDC_PKCE=true                          # Default: true (recommended for security)
```

### Usage

Once configured, users will see a "Login with OIDC" button on the login page. The authentication flow follows the OpenID Connect Authorization Code flow with PKCE for enhanced security.

### Security Considerations

- PKCE (Proof Key for Code Exchange) is enabled by default for enhanced security
- The redirect URI is automatically configured as `${APP_URL}/api/auth/oauth2/callback/oidc`
- Ensure your OIDC provider is configured to allow this redirect URI

### Troubleshooting

**Common Issues:**

1. **Invalid Redirect URI**: Ensure your OIDC provider allows `${APP_URL}/api/auth/oauth2/callback/oidc`
2. **Scope Issues**: Some providers require specific scopes beyond the default `openid email profile`
3. **User Creation**: Users are automatically created on first login. Ensure your provider returns email and name claims

**Debug Mode:**

Enable debug logging by setting the auth logger level in `apps/backend/src/auth.ts` to see detailed OIDC flow information.

## How to contribute

1. Fork the repository and branch off `umbrella`.
2. Make the change. Tests and documentation land in the same change as the code.
3. Run what CI runs before you push:
   ```bash
   pnpm install --frozen-lockfile
   pnpm --filter @repo/zod-types build
   pnpm --filter @repo/trpc build
   pnpm -C apps/backend test
   pnpm -C apps/frontend test
   pnpm check-types
   ```
   `pnpm lint` is not part of CI. Both apps run it with `--max-warnings 0` and the frontend currently fails on existing warnings, so treat it as advisory for now.
4. Open a pull request against `umbrella`. Say what changed, why, and how you verified it. We squash-merge, so the PR title becomes the commit subject.
5. Add a row for the change at the bottom of the patch table in [`UMBRELLA_FORK.md`](UMBRELLA_FORK.md) (the newest rows are last), or ask in the PR and we will add it.

## Pull request guidelines

- One concern per pull request.
- No secrets, internal hostnames, or credentials in code, comments, tests, or commit messages.
- Fixes that are not specific to this fork are candidates for upstream. We carry them here in the meantime and are glad to help you file them against metatool-ai/metamcp.
- Every workflow `uses:` is pinned to a commit SHA and the Dockerfile base image to a digest; a test guards this. Keep new pins in the same form.

## License

By contributing, you agree that your contributions are licensed under the MIT License, the same license as upstream MetaMCP.
