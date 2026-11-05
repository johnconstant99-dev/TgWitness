# Chromium sandbox policy

`official-seccomp.json` derives from the profile distributed with Playwright 1.64.1．
The only addition is unconditional seccomp permission for `chroot`，which Chromium needs inside its own user namespace when Docker drops every capability．The container receives no host `CAP_SYS_CHROOT` or `CAP_SYS_ADMIN` capability，and Chromium sandboxing remains enabled．
It keeps a deny-by-default syscall policy and permits the user namespaces needed
by Chromium's own sandbox，without adding host administration capabilities．

Source：<https://github.com/microsoft/playwright/blob/v1.64.1/utils/docker/seccomp_profile.json>

Original upstream SHA-256：`cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`

Copyright Microsoft Corporation，licensed under Apache License 2．0，see
[PLAYWRIGHT-LICENSE.txt](PLAYWRIGHT-LICENSE.txt)．
