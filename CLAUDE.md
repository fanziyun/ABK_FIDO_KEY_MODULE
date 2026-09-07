# ABK FIDO Key Module — project instructions

## Commit conventions（提交规范）

- 提交者（git author）只能是 **fanziyun**
  `<186413865+fanziyun@users.noreply.github.com>`。
- 提交信息**不要**包含任何 `Co-Authored-By: Claude ...` 或 `Co-authored-by: Claude ...`
  之类行；Commit body 里只写本任务的实际改动。
- `.githooks/commit-msg` 会自动删除 commit message 中的这类 Claude trailer 行；
  不要用 `git commit --no-verify` 绕过它。
- 只提交为本任务所必需的改动。

（这条规则对 Repo 里所有提交生效；请始终遵守。）
