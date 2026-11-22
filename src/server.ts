import "dotenv/config";
import { app } from "./app";
import { prisma } from "./db";

const port = Number(process.env.PORT ?? 4000);
const server = app.listen(port, () => {
  console.log(`TaskMaster API listening on port ${port}`);
});

async function shutdown() {
  server.close(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
