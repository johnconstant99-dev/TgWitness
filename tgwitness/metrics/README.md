[TgWitness](../../README.md) / [tgwitness](../README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../../docs/assets/presentation/section-source-static.svg">
  <source media="(max-width: 640px)" srcset="../../docs/assets/presentation/section-source-mobile.svg">
  <img src="../../docs/assets/presentation/section-source.svg" width="1200" alt="TgWitness / Application">
</picture>

# Report metrics

Versioned processors that derive report statistics from saved journal events.
The registry and shared pipeline live in [`__init__.py`](__init__.py).

| Processor | Subject |
| --- | --- |
| [`first_time_posters.py`](first_time_posters.py) | First observed message activity by sender |
| [`service_ratio.py`](service_ratio.py) | Service-event share |
| [`membership_monthly.py`](membership_monthly.py) | Membership events by month |
| [`pinned_monthly.py`](pinned_monthly.py) | Pin-related events by month |

Each processor declares its version, title, methodology and controlling parameter.
Keep the result's explanation aligned with what the saved events can establish.
Processors derive statistics without rewriting signed records.

From the repository root, after [development setup](../../.github/CONTRIBUTING.md#development-setup):

```sh
python -m pytest tools/test_metrics.py -q
```

[Case reports](../../docs/CASE_REPORTS.md) · [Application source](../README.md)
