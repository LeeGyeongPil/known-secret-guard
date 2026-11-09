# 보안 정책 / Security policy

보안 취약점을 발견하셨다면 **공개 이슈 대신** 이 레포의 **Security → Report a vulnerability**(비공개 취약점 신고)로 알려 주세요. 확인 후 답변드리고, 고친 버전을 릴리스하면서 함께 안내합니다.

If you find a security issue, please **do not open a public issue**. Use **Security → Report a vulnerability** in this repository to report it privately. We will reply after checking and announce the fix with a release.

이 라이브러리는 네트워크를 열지 않습니다. 보안 목표는 보고에 비밀값을 넣지 않는 것입니다. 비밀값이나 그 변형이 출력·예외·훅 응답에 새는 경우, 또는 훅이 오류 때 도구 호출을 통과시키는 경우(fail open)를 취약점으로 신고해 주세요.

This library opens no network connections. Its security goal is to never put secret values in reports. Please report any case where a secret or a variant leaks into output, exceptions or hook responses, or where the hook lets a tool call through on error (fail open).
