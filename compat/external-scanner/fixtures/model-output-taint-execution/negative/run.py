import openai

response = openai.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "say hi"}])
print(response.choices[0].message.content)
