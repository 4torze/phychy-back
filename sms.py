import requests

response = requests.post("https://textbelt.com/text", {
    "phone": "+46726405834",
    "message": "Ceci est un SMS gratuit envoyé via Textbelt",
    "key": "textbelt",  # Clé pour les SMS gratuits
})

print(response.json())
