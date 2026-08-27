# Proof agent instructions

## Work execution

- Work items in `docs/work/items/` are self-contained. Execute only the named
  item; read the item file and its `required_reading` paths. Do not browse
  `docs/product/`, `docs/architecture/`, `docs/reference/`, or the work map
  unless the item text explicitly directs it.
- Respect the item's `allowed_paths`. Never modify files outside the item's
  write scope, and never absorb adjacent work because it appears convenient.
- Before claiming an item, re-read its frontmatter and repository status.
  Commit the claim to the current branch before starting implementation.
- Run each implementation in its own `git worktree` created from the item's
  committed `base_sha` so concurrent executors do not share an index.
- Record evidence (receipt and manifest) per the work-item protocol before
  moving the item to `review`.
