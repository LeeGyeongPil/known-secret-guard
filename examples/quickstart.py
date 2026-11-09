"""Smallest useful example: register a secret, scan outgoing data.

Practice run: the secret below is fake and assembled at run time.
Run: uv run python examples/quickstart.py
"""

import base64

from known_secret_guard import Guard, LeakDetected

# 연습용 가짜 비밀 (실행 시 조립)
api_key = "Zq7" + "Xk2Lm9Pw4Rt8Yv1Nb6Hc3Jd5"

# 실제로는 Guard.from_env(["GITHUB_TOKEN", "OPENAI_API_KEY"]) 처럼 이름만 넘긴다.
guard = Guard({"FAKE_API_KEY": api_key})

# 에이전트가 내보내려는 요청: 비밀이 base64로 바뀌어 중첩 dict 안에 들어 있다.
outgoing = {
    "url": "https://example.invalid/upload",
    "body": {"messages": [{"role": "user", "content": "hi"},
                          {"role": "tool", "content": "data=" + base64.b64encode(b"A" + api_key.encode()).decode()}]},
}

for finding in guard.scan(outgoing):
    print(finding)  # 값은 나오지 않고 이름:변형:필드만 나온다

try:
    guard.check(outgoing)
except LeakDetected as exc:
    print("blocked:", exc)
