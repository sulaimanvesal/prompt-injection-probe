"""Scan a REAL agent: adapt any LLM-backed callable to the scanner.

The scanner only needs ``respond(user_message: str) -> str``. Wire your own
agent (LangChain, raw API calls, whatever) into that shape and point the
scanner at it. No API key is needed to run this file — it demonstrates the
adapter pattern against the built-in mock.

Example with the OpenAI API (requires OPENAI_API_KEY)::

    import os
    from openai import OpenAI
    from promptprobe.scanner import PromptInjectionScanner
    from promptprobe.report import render_terminal

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    def my_agent(user_message: str) -> str:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_message},
            ],
        )
        return resp.choices[0].message.content or ""

    report = PromptInjectionScanner().scan(my_agent, target_name="my-agent")
    print(render_terminal(report))
"""

from promptprobe.report import render_terminal
from promptprobe.scanner import PromptInjectionScanner
from promptprobe.targets import make_vulnerable_target


def main() -> None:
    # Swap make_vulnerable_target() for your own respond() callable.
    report = PromptInjectionScanner().scan(
        make_vulnerable_target(), target_name="my-agent (mock stand-in)"
    )
    print(render_terminal(report))


if __name__ == "__main__":
    main()
