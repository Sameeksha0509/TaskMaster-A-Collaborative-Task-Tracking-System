import "dotenv/config";
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import request from "supertest";
import { app } from "../src/app";
import { prisma } from "../src/db";

let ownerToken = "";
let memberToken = "";
let outsiderToken = "";
let projectId = "";
let taskId = "";

before(async () => {
  await prisma.notification.deleteMany();
  await prisma.attachment.deleteMany();
  await prisma.comment.deleteMany();
  await prisma.task.deleteMany();
  await prisma.projectMember.deleteMany();
  await prisma.project.deleteMany();
  await prisma.session.deleteMany();
  await prisma.user.deleteMany();

  const owner = await request(app).post("/api/auth/register").send({
    name: "Owner", email: "owner@example.test", password: "correct-horse-battery"
  });
  assert.equal(owner.status, 201);
  ownerToken = owner.body.token;
  const member = await request(app).post("/api/auth/register").send({
    name: "Member", email: "member@example.test", password: "correct-horse-battery"
  });
  assert.equal(member.status, 201);
  memberToken = member.body.token;
});

after(async () => {
  await prisma.$disconnect();
});

test("validates registration and rejects duplicate accounts", async () => {
  const weak = await request(app).post("/api/auth/register").send({
    name: "Short password", email: "weak@example.test", password: "short"
  });
  assert.equal(weak.status, 400);
  const duplicate = await request(app).post("/api/auth/register").send({
    name: "Owner", email: "owner@example.test", password: "correct-horse-battery"
  });
  assert.equal(duplicate.status, 409);
});

test("supports project collaboration, task search, comments, and membership isolation", async () => {
  const project = await request(app).post("/api/projects")
    .set("Authorization", `Bearer ${ownerToken}`).send({ name: "Launch", description: "Release tasks" });
  assert.equal(project.status, 201);
  projectId = project.body.project.id;

  const added = await request(app).post(`/api/projects/${projectId}/members`)
    .set("Authorization", `Bearer ${ownerToken}`).send({ email: "member@example.test" });
  assert.equal(added.status, 201);

  const created = await request(app).post(`/api/projects/${projectId}/tasks`)
    .set("Authorization", `Bearer ${ownerToken}`)
    .send({ title: "Ship API", description: "Check endpoints", assignedToId: added.body.member.userId });
  assert.equal(created.status, 201);
  taskId = created.body.task.id;

  const tasks = await request(app).get("/api/tasks?search=Ship&assignedToMe=true")
    .set("Authorization", `Bearer ${memberToken}`);
  assert.equal(tasks.status, 200);
  assert.equal(tasks.body.pagination.total, 1);

  const comment = await request(app).post(`/api/tasks/${taskId}/comments`)
    .set("Authorization", `Bearer ${memberToken}`).send({ body: "Working on it." });
  assert.equal(comment.status, 201);

  const outsiderAccount = await request(app).post("/api/auth/register").send({
    name: "Outsider", email: "outsider@example.test", password: "correct-horse-battery"
  });
  assert.equal(outsiderAccount.status, 201);
  outsiderToken = outsiderAccount.body.token;

  const memberInvite = await request(app).post(`/api/projects/${projectId}/members`)
    .set("Authorization", `Bearer ${memberToken}`)
    .send({ email: "outsider@example.test" });
  assert.equal(memberInvite.status, 403);

  const outsiderTask = await request(app).post(`/api/projects/${projectId}/tasks`)
    .set("Authorization", `Bearer ${outsiderToken}`).send({ title: "Should not work" });
  assert.equal(outsiderTask.status, 404);

  const invalidAssignee = await request(app).patch(`/api/tasks/${taskId}`)
    .set("Authorization", `Bearer ${ownerToken}`).send({ assignedToId: "not-a-project-member" });
  assert.equal(invalidAssignee.status, 404);

  const invalidStatus = await request(app).patch(`/api/tasks/${taskId}`)
    .set("Authorization", `Bearer ${ownerToken}`).send({ status: "DONE" });
  assert.equal(invalidStatus.status, 400);
});

test("supports completion, notifications, and session revocation", async () => {
  const completed = await request(app).patch(`/api/tasks/${taskId}`)
    .set("Authorization", `Bearer ${ownerToken}`).send({ status: "COMPLETED" });
  assert.equal(completed.status, 200);

  const notifications = await request(app).get("/api/notifications")
    .set("Authorization", `Bearer ${memberToken}`);
  assert.equal(notifications.status, 200);
  assert.ok(notifications.body.notifications.length >= 1);

  const logout = await request(app).post("/api/auth/logout")
    .set("Authorization", `Bearer ${ownerToken}`);
  assert.equal(logout.status, 204);
  const profile = await request(app).get("/api/users/me")
    .set("Authorization", `Bearer ${ownerToken}`);
  assert.equal(profile.status, 401);
});
