from urllib.parse import urlparse

url = "https://example.com:8080/products?id=10"
parsed = urlparse(url)

print(parsed)