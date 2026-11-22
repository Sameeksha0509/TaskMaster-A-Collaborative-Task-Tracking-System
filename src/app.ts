import "dotenv/config";
import { randomUUID } from "node:crypto";
import { mkdir, unlink } from "node:fs/promises";
import path from "node:path";
import bcrypt from "bcryptjs";
import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import multer from "multer";
import { Prisma } from "@prisma/client";
import { z, ZodError } from "zod";
import { createSession, requireAuth } from "./auth";
import { prisma } from "./db";
import { publish, subscribe } from "./notifications";

const app = express();
const ProjectRole = { OWNER: "OWNER", MEMBER: "MEMBER" } as const;
const TaskStatus = { OPEN: "OPEN", IN_PROGRESS: "IN_PROGRESS", COMPLETED: "COMPLETED" } as const;
const uploadDirectory = path.resolve(process.env.UPLOAD_DIR ?? "./uploads");
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES ?? 10 * 1024 * 1024);
const allowedOrigins = (process.env.CORS_ORIGIN ?? "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim());

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(Object.assign(new Error("Origin is not allowed by CORS."), { status: 403 }));
  }
}));
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many authentication attempts. Try again later." }
});

const upload = multer({
  storage: multer.diskStorage({
    destination: async (_req, _file, callback) => {
      try {
        await mkdir(uploadDirectory, { recursive: true });
        callback(null, uploadDirectory);
      } catch (error) {
        callback(error as Error, uploadDirectory);
      }
    },
    filename: (_req, _file, callback) => callback(null, randomUUID())
  }),
  limits: { fileSize: maxUploadBytes, files: 1 },
  fileFilter: (_req, file, callback) => {
    const allowed = new Set([
      "image/jpeg", "image/png", "image/gif", "image/webp",
      "application/pdf", "text/plain",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ]);
    callback(null, allowed.has(file.mimetype));
  }
});

const registerSchema = z.object({
  name: z.string().trim().min(1).max(100),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(10).max(72).refine((value) => Buffer.byteLength(value, "utf8") <= 72)
});
const loginSchema = z.object({
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(1).max(72).refine((value) => Buffer.byteLength(value, "utf8") <= 72)
});
const projectSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(2000).optional()
});
const taskSchema = z.object({
  title: z.string().trim().min(1).max(200),
  description: z.string().trim().max(10000).optional(),
  dueDate: z.string().datetime().optional().nullable(),
  assignedToId: z.string().optional().nullable()
});
const taskUpdateSchema = taskSchema.partial().extend({
  status: z.nativeEnum(TaskStatus).optional()
});

function userIdOf(req: Request): string {
  if (!req.userId) throw new Error("Authenticated user is missing.");
  return req.userId;
}

async function getMembership(projectId: string, userId: string) {
  const membership = await prisma.projectMember.findUnique({
    where: { projectId_userId: { projectId, userId } }
  });
  if (!membership) {
    const error = new Error("Project not found.") as Error & { status: number };
    error.status = 404;
    throw error;
  }
  return membership;
}

async function getAccessibleTask(taskId: string, userId: string) {
  const task = await prisma.task.findFirst({
    where: { id: taskId, project: { members: { some: { userId } } } },
    include: { project: true }
  });
  if (!task) {
    const error = new Error("Task not found.") as Error & { status: number };
    error.status = 404;
    throw error;
  }
  return task;
}

async function notify(userId: string, taskId: string, message: string) {
  const notification = await prisma.notification.create({
    data: { userId, taskId, message },
    select: { id: true, taskId: true, message: true, createdAt: true }
  });
  publish(userId, notification);
}

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const input = registerSchema.parse(req.body);
  const passwordHash = await bcrypt.hash(input.password, 12);
  const user = await prisma.user.create({
    data: { name: input.name, email: input.email, passwordHash },
    select: { id: true, name: true, email: true, createdAt: true }
  });
  const token = await createSession(user.id);
  res.status(201).json({ user, token });
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const input = loginSchema.parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: input.email } });
  if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) {
    res.status(401).json({ error: "Invalid email or password." });
    return;
  }
  const token = await createSession(user.id);
  res.json({
    user: { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt },
    token
  });
});

app.use("/api", requireAuth);

app.post("/api/auth/logout", async (req, res) => {
  if (req.sessionId) {
    await prisma.session.updateMany({
      where: { id: req.sessionId, userId: userIdOf(req), revokedAt: null },
      data: { revokedAt: new Date() }
    });
  }
  res.status(204).end();
});

app.get("/api/users/me", async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: userIdOf(req) },
    select: { id: true, name: true, email: true, createdAt: true, updatedAt: true }
  });
  res.json({ user });
});

app.patch("/api/users/me", async (req, res) => {
  const input = z.object({
    name: z.string().trim().min(1).max(100).optional(),
    email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()).optional()
  }).refine((value) => Object.keys(value).length > 0, "Provide at least one field.").parse(req.body);
  const user = await prisma.user.update({
    where: { id: userIdOf(req) },
    data: input,
    select: { id: true, name: true, email: true, createdAt: true, updatedAt: true }
  });
  res.json({ user });
});

app.post("/api/projects", async (req, res) => {
  const input = projectSchema.parse(req.body);
  const project = await prisma.project.create({
    data: {
      ...input,
      members: { create: { userId: userIdOf(req), role: ProjectRole.OWNER } }
    },
    include: { members: { select: { userId: true, role: true } } }
  });
  res.status(201).json({ project });
});

app.get("/api/projects", async (req, res) => {
  const projects = await prisma.project.findMany({
    where: { members: { some: { userId: userIdOf(req) } } },
    include: { members: { select: { userId: true, role: true, user: { select: { name: true, email: true } } } } },
    orderBy: { updatedAt: "desc" }
  });
  res.json({ projects });
});

app.post("/api/projects/:projectId/members", async (req, res) => {
  const actorId = userIdOf(req);
  const membership = await getMembership(req.params.projectId, actorId);
  if (membership.role !== ProjectRole.OWNER) {
    res.status(403).json({ error: "Only project owners can add members." });
    return;
  }
  const input = z.object({ email: z.string().trim().email().transform((value) => value.toLowerCase()) }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: input.email }, select: { id: true, name: true, email: true } });
  if (!user) {
    res.status(404).json({ error: "Register the invited user before adding them to a project." });
    return;
  }
  const member = await prisma.projectMember.upsert({
    where: { projectId_userId: { projectId: req.params.projectId, userId: user.id } },
    create: { projectId: req.params.projectId, userId: user.id },
    update: {},
    select: { projectId: true, userId: true, role: true, user: { select: { name: true, email: true } } }
  });
  res.status(201).json({ member });
});

app.get("/api/tasks", async (req, res) => {
  const actorId = userIdOf(req);
  const query = z.object({
    projectId: z.string().optional(),
    status: z.nativeEnum(TaskStatus).optional(),
    search: z.string().trim().max(200).optional(),
    assignedToMe: z.enum(["true", "false"]).optional(),
    sortBy: z.enum(["dueDate", "createdAt", "title", "updatedAt"]).default("createdAt"),
    order: z.enum(["asc", "desc"]).default("desc"),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20)
  }).parse(req.query);
  if (query.projectId) await getMembership(query.projectId, actorId);
  const where: Prisma.TaskWhereInput = {
    project: {
      members: { some: { userId: actorId } },
      ...(query.projectId ? { id: query.projectId } : {})
    },
    ...(query.status ? { status: query.status } : {}),
    AND: [
      ...(query.search ? [{ OR: [
        { title: { contains: query.search } },
        { description: { contains: query.search } }
      ] }] : []),
      ...(query.assignedToMe === "true"
        ? [{ assignedToId: actorId }]
        : query.assignedToMe === "false"
          ? []
          : [{ OR: [{ assignedToId: actorId }, { createdById: actorId }] }])
    ]
  };
  const [tasks, total] = await prisma.$transaction([
    prisma.task.findMany({
      where,
      include: { assignedTo: { select: { id: true, name: true, email: true } }, createdBy: { select: { id: true, name: true } } },
      orderBy: { [query.sortBy]: query.order },
      skip: (query.page - 1) * query.limit,
      take: query.limit
    }),
    prisma.task.count({ where })
  ]);
  res.json({ tasks, pagination: { page: query.page, limit: query.limit, total } });
});

app.post("/api/projects/:projectId/tasks", async (req, res) => {
  const actorId = userIdOf(req);
  await getMembership(req.params.projectId, actorId);
  const input = taskSchema.parse(req.body);
  if (input.assignedToId) await getMembership(req.params.projectId, input.assignedToId);
  const task = await prisma.task.create({
    data: {
      projectId: req.params.projectId,
      createdById: actorId,
      title: input.title,
      description: input.description,
      dueDate: input.dueDate ? new Date(input.dueDate) : null,
      assignedToId: input.assignedToId ?? null
    }
  });
  if (task.assignedToId && task.assignedToId !== actorId) {
    await notify(task.assignedToId, task.id, `You were assigned "${task.title}".`);
  }
  res.status(201).json({ task });
});

app.get("/api/tasks/:taskId", async (req, res) => {
  const task = await getAccessibleTask(req.params.taskId, userIdOf(req));
  res.json({ task });
});

app.patch("/api/tasks/:taskId", async (req, res) => {
  const actorId = userIdOf(req);
  const current = await getAccessibleTask(req.params.taskId, actorId);
  const input = taskUpdateSchema.refine((value) => Object.keys(value).length > 0, "Provide at least one field.").parse(req.body);
  if (input.assignedToId) await getMembership(current.projectId, input.assignedToId);
  const task = await prisma.task.update({
    where: { id: current.id },
    data: {
      ...input,
      dueDate: input.dueDate === undefined ? undefined : input.dueDate ? new Date(input.dueDate) : null
    }
  });
  if (task.assignedToId && task.assignedToId !== actorId &&
      (task.assignedToId !== current.assignedToId ||
       task.title !== current.title ||
       task.description !== current.description ||
       task.status !== current.status ||
       task.dueDate?.getTime() !== current.dueDate?.getTime())) {
    const message = task.assignedToId !== current.assignedToId
      ? `You were assigned "${task.title}".`
      : `Task "${task.title}" was updated.`;
    await notify(task.assignedToId, task.id, message);
  }
  res.json({ task });
});

app.delete("/api/tasks/:taskId", async (req, res) => {
  const actorId = userIdOf(req);
  const task = await getAccessibleTask(req.params.taskId, actorId);
  const membership = await getMembership(task.projectId, actorId);
  if (task.createdById !== actorId && membership.role !== ProjectRole.OWNER) {
    res.status(403).json({ error: "Only the task creator or project owner can delete this task." });
    return;
  }
  await prisma.task.delete({ where: { id: task.id } });
  res.status(204).end();
});

app.get("/api/tasks/:taskId/comments", async (req, res) => {
  await getAccessibleTask(req.params.taskId, userIdOf(req));
  const comments = await prisma.comment.findMany({
    where: { taskId: req.params.taskId },
    include: { author: { select: { id: true, name: true } } },
    orderBy: { createdAt: "asc" }
  });
  res.json({ comments });
});

app.post("/api/tasks/:taskId/comments", async (req, res) => {
  await getAccessibleTask(req.params.taskId, userIdOf(req));
  const input = z.object({ body: z.string().trim().min(1).max(5000) }).parse(req.body);
  const comment = await prisma.comment.create({
    data: { taskId: req.params.taskId, authorId: userIdOf(req), body: input.body },
    include: { author: { select: { id: true, name: true } } }
  });
  res.status(201).json({ comment });
});

app.post("/api/tasks/:taskId/attachments", (req, res, next) => {
  void getAccessibleTask(req.params.taskId, userIdOf(req))
    .then(() => upload.single("file")(req, res, next))
    .catch(next);
}, async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "A supported file is required." });
    return;
  }
  try {
    const attachment = await prisma.attachment.create({
      data: {
        taskId: req.params.taskId,
        uploadedById: userIdOf(req),
        storedName: req.file.filename,
        originalName: path.basename(req.file.originalname).slice(0, 255),
        mimeType: req.file.mimetype,
        size: req.file.size
      }
    });
    res.status(201).json({ attachment });
  } catch (error) {
    await unlink(req.file.path).catch((cleanupError: NodeJS.ErrnoException) => {
      if (cleanupError.code !== "ENOENT") throw cleanupError;
    });
    throw error;
  }
});

app.get("/api/tasks/:taskId/attachments", async (req, res) => {
  await getAccessibleTask(req.params.taskId, userIdOf(req));
  const attachments = await prisma.attachment.findMany({
    where: { taskId: req.params.taskId },
    select: { id: true, originalName: true, mimeType: true, size: true, createdAt: true, uploadedById: true },
    orderBy: { createdAt: "asc" }
  });
  res.json({ attachments });
});

app.get("/api/attachments/:attachmentId", async (req, res) => {
  const attachment = await prisma.attachment.findUnique({ where: { id: req.params.attachmentId } });
  if (!attachment) {
    res.status(404).json({ error: "Attachment not found." });
    return;
  }
  await getAccessibleTask(attachment.taskId, userIdOf(req));
  res.type(attachment.mimeType);
  res.download(path.join(uploadDirectory, attachment.storedName), attachment.originalName);
});

app.delete("/api/attachments/:attachmentId", async (req, res) => {
  const actorId = userIdOf(req);
  const attachment = await prisma.attachment.findUnique({ where: { id: req.params.attachmentId } });
  if (!attachment) {
    res.status(404).json({ error: "Attachment not found." });
    return;
  }
  const task = await getAccessibleTask(attachment.taskId, actorId);
  const membership = await getMembership(task.projectId, actorId);
  if (attachment.uploadedById !== actorId && membership.role !== ProjectRole.OWNER) {
    res.status(403).json({ error: "Only the uploader or project owner can delete this attachment." });
    return;
  }
  await prisma.attachment.delete({ where: { id: attachment.id } });
  await unlink(path.join(uploadDirectory, attachment.storedName)).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
  res.status(204).end();
});

app.get("/api/notifications", async (req, res) => {
  const userId = userIdOf(req);
  const notifications = await prisma.notification.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take: 100
  });
  res.json({ notifications });
});

app.patch("/api/notifications/:notificationId/read", async (req, res) => {
  const notification = await prisma.notification.updateMany({
    where: { id: req.params.notificationId, userId: userIdOf(req), readAt: null },
    data: { readAt: new Date() }
  });
  if (notification.count === 0) {
    res.status(404).json({ error: "Unread notification not found." });
    return;
  }
  res.status(204).end();
});

app.get("/api/notifications/stream", (req, res) => {
  res.status(200);
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive"
  });
  res.flushHeaders();
  res.write("event: ready\ndata: {}\n\n");
  const unsubscribe = subscribe(userIdOf(req), res);
  const heartbeat = setInterval(() => res.write(": keep-alive\n\n"), 25000);
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

app.use((_req, res) => res.status(404).json({ error: "Route not found." }));

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof ZodError) {
    res.status(400).json({ error: "Validation failed.", details: error.issues });
    return;
  }
  if (error instanceof multer.MulterError) {
    res.status(error.code === "LIMIT_FILE_SIZE" ? 413 : 400).json({ error: error.message });
    return;
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === "P2002") {
      res.status(409).json({ error: "A record with that value already exists." });
      return;
    }
    if (error.code === "P2025") {
      res.status(404).json({ error: "Record not found." });
      return;
    }
  }
  const status = (error as Error & { status?: number }).status;
  if (status && status >= 400 && status < 500) {
    res.status(status).json({ error: (error as Error).message });
    return;
  }
  console.error(error);
  res.status(500).json({ error: "An unexpected error occurred." });
});

export { app };
