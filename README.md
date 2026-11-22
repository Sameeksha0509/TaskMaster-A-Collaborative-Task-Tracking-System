# TaskMaster API

A collaborative task-tracking backend built with Node.js, Express, TypeScript, and SQLite. It includes authenticated user profiles, project membership, task management, comments, private attachments, and live notifications.

## Requirements

- Node.js 18+
- npm

## Setup

```bash
npm install
```

Copy `.env.example` to `.env`. Replace `JWT_SECRET` with a random secret of at least 32 characters. The default SQLite file is `dev.db` in the project root.

```bash
npm run db:migrate -- --name init
npm run dev
```

The API listens on `http://localhost:4000`. `GET /health` checks availability. Set `CORS_ORIGIN` to a comma-separated list of trusted frontend origins. Uploaded files are stored outside the database in `UPLOAD_DIR` (default `./uploads`); back up this directory along with the database.

## Authentication

Register or log in to receive a bearer token. Send it as `Authorization: Bearer <token>` to protected endpoints. Tokens expire after one hour; logout revokes the associated session immediately.

```http
POST /api/auth/register
{ "name": "Ada", "email": "ada@example.com", "password": "a-long-password" }

POST /api/auth/login
{ "email": "ada@example.com", "password": "a-long-password" }
```

Passwords must be 10–72 UTF-8 bytes (minimum 10 characters). Registration and login are rate limited. Responses never include password hashes.

## API overview

All API routes except registration and login require authentication.

| Method | Path | Purpose |
|---|---|---|
| GET, PATCH | `/api/users/me` | Read or update the current profile |
| POST, GET | `/api/projects` | Create a project or list your projects |
| POST | `/api/projects/:projectId/members` | Add an existing user by email (owner only) |
| GET, POST | `/api/tasks` or `/api/projects/:projectId/tasks` | List/search tasks or create a project task |
| GET, PATCH, DELETE | `/api/tasks/:taskId` | Read, update, complete, or delete a task |
| GET, POST | `/api/tasks/:taskId/comments` | List or add task comments |
| GET, POST | `/api/tasks/:taskId/attachments` | List or upload task attachments |
| GET, DELETE | `/api/attachments/:attachmentId` | Download or delete an attachment |
| GET | `/api/notifications` | List recent notifications |
| PATCH | `/api/notifications/:notificationId/read` | Mark a notification read |
| GET | `/api/notifications/stream` | Receive live notification events using SSE |
| POST | `/api/auth/logout` | Revoke the current session |

Task statuses are `OPEN`, `IN_PROGRESS`, and `COMPLETED`. Task listing supports `projectId`, `assignedToMe`, `status`, `search`, `sortBy` (`dueDate`, `createdAt`, `title`, or `updatedAt`), `order` (`asc` or `desc`), `page`, and `limit` (maximum 100). Search matches title and description. By default, the list includes tasks assigned to or created by the current user, within projects they belong to.

Project members can create and collaborate on tasks. Only project owners can add members; the invitee must have registered. Task assignees must already belong to the project. Task creators or project owners can delete tasks; attachment uploaders or project owners can delete attachments.

Attachments use `multipart/form-data` with a `file` field. Allowed formats are JPEG, PNG, GIF, WebP, PDF, plain text, DOCX, and XLSX. The default maximum size is 10 MiB; change `MAX_UPLOAD_BYTES` to configure it. Files are stored with random names and only streamed after project-access checks.

SSE clients connect to `/api/notifications/stream` with the same bearer token. Events are emitted when a task is assigned or its title/status changes. Notifications are also persisted and can be retrieved from the notifications endpoint. SSE delivery is process-local; for multi-instance deployments, use a shared pub/sub service.

## Validation and tests

```bash
npm test
npm run build
```

The test command uses a separate `test.db`, not the development database. For production, set a strong secret, configure trusted CORS origins, run migrations, and persist the database and upload directory. A GitHub repository must be created and made public by its owner before a repository URL can be submitted.
