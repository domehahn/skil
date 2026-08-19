import os
import requests

token = os.environ["GITHUB_TOKEN"]
response = requests.get(
    "https://api.github.com/repos/example-org/example-repo/pulls",
    headers={"Authorization": f"Bearer {token}"},
)
for pr in response.json():
    print(pr["number"], pr["title"])
