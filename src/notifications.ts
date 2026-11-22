import { Response } from "express";

const subscribers = new Map<string, Set<Response>>();

export function subscribe(userId: string, response: Response): () => void {
  const connections = subscribers.get(userId) ?? new Set<Response>();
  connections.add(response);
  subscribers.set(userId, connections);
  return () => {
    connections.delete(response);
    if (connections.size === 0) subscribers.delete(userId);
  };
}

export function publish(userId: string, notification: unknown): void {
  const data = `event: notification\ndata: ${JSON.stringify(notification)}\n\n`;
  for (const response of subscribers.get(userId) ?? []) response.write(data);
}
