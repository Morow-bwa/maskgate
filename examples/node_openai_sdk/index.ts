import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY ?? "local-client-key",
  baseURL: process.env.MASKGATE_BASE_URL ?? "http://localhost:8080/v1",
});

const response = await client.chat.completions.create({
  model: "gpt-4.1-mini",
  messages: [
    {
      role: "user",
      content: "Write a polite reply to user@example.com about the $1,234.56 invoice.",
    },
  ],
});

console.log(response.choices[0]?.message?.content);
