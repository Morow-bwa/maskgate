import os

from openai import OpenAI


client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY", "local-client-key"),
    base_url=os.getenv("MASKGATE_BASE_URL", "http://localhost:8080/v1"),
)

response = client.chat.completions.create(
    model="gpt-4.1-mini",
    messages=[
        {
            "role": "user",
            "content": "Write a polite reply to user@example.com about the $1,234.56 invoice.",
        }
    ],
)

print(response.choices[0].message.content)
