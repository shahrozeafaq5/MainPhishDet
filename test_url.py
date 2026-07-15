import json

from tools import inspect_url


def main() -> None:
    url = input("Enter URL to inspect: ").strip()

    result = inspect_url(url)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()