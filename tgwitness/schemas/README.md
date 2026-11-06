[TgWitness](../../README.md) / [tgwitness](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Case Board schemas

JSON Schemas for the Case Board's structured operations. These files are generated
by [`build_board_schemas.py`](../../tools/build_board_schemas.py).

| Schema | Operation |
| --- | --- |
| [`board-bookmark.json`](board-bookmark.json) | Bookmark a record |
| [`board-highlight.json`](board-highlight.json) | Mark a text range |
| [`board-slice.json`](board-slice.json) | Describe a saved selection |
| [`board-collection.json`](board-collection.json) | Define a collection |
| [`board-comment.json`](board-comment.json) | Add a comment |
| [`board-status.json`](board-status.json) | Set an item's status |
| [`board-move.json`](board-move.json) | Move an item |
| [`board-remove.json`](board-remove.json) | Remove an item |

## Check generated files

Run from the repository root:

```sh
python tools/build_board_schemas.py --check
```

After changing the source models, omit `--check` to regenerate the schemas and
review the diff. See [Case Board](../../docs/CASE-BOARD.md) for the user workflow.
