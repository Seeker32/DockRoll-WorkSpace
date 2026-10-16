---
schema_version: 1
id: authoring-guide
type: guide
title: Sprint, Milestone and Story Authoring Guide
summary: Creation rules for the delivery documents the portal indexes.
status: active
lang: en-US
owners: [Team]
tags: [portal, delivery, governance]
updated_at: 2026-09-12
order: 2
area: delivery
---

# Sprint, Milestone and Story Authoring Guide

Git is the source of truth. The portal only reads Markdown declared in `.project-portal.yaml`; it never writes content.

## File layout

| Document | Path | Template |
| --- | --- | --- |
| Sprint | `sprints/Sprint-YYYY-MM-DD.md` | `templates/Sprint-Template.md` |
| Milestone | `milestones/Milestone-N-Name.md` | `templates/Milestone-Template.md` |
| Story | `stories/Story-Name.md` | `templates/Story-Template.md` |
| Technical, guide, ADR, overview | any folder outside `templates/` | `templates/Technical-Document-Template.md` |

`templates/` and any path segment starting with `.` are never indexed.

## Shared frontmatter

Every indexed page starts with YAML frontmatter.

| Field | Rule |
| --- | --- |
| `schema_version` | must be `1` |
| `id` | lowercase letters, digits and hyphens; unique across the workspace; must not change when the file moves |
| `type` | `sprint`, `milestone`, `technical`, `guide`, `adr` or `overview` |
| `title`, `summary` | non-empty; `summary` is used as the search snippet |
| `status` | values from the per-type tables below |
| `lang` | `zh-CN` or `en-US` |
| `owners` | non-empty string array |
| `tags` | string array |
| `updated_at` | ISO date `YYYY-MM-DD` |
| `order` | integer; list sorting is ascending |

## Sprint

File name carries the start date: `sprints/Sprint-YYYY-MM-DD.md`. Extra fields:

- `start_date`, `end_date` — ISO dates
- `goal` — one measurable sentence
- `capacity_points` — team capacity for the iteration
- `milestone_ids` — stable ids of existing Milestone documents

Sprint progress is derived from independent Story documents whose `sprint_id` references the Sprint.

Status: `planned`, `active`, `completed` or `cancelled`.

Progress is derived, never written by hand. When every story declares `points`, completion is `done` points over total points; otherwise it is `done` stories over total stories.

## Milestone

Extra fields:

- `target_date` — ISO date
- `completed_date` — optional ISO date
- `related_sprint_ids` — stable ids of existing Sprint documents
- `goals` — array of `{ id, title, done }`; set `done: true` only after acceptance
- `risk_summary` — optional

Status: `planned`, `active`, `on_hold`, `completed` or `cancelled`.

Progress is derived as done goals over total goals.

## Story

A Story is an independent document in `stories/`. The portal aggregates Story documents on the Stories page and derives the owning Sprint's progress from `sprint_id`.

| Field | Rule |
| --- | --- |
| `id` | globally unique stable identifier |
| `sprint_id` | stable id of the owning Sprint document |
| `story_type` | `feature`, `technical` or `bug` |
| `title` | short and user-facing |
| `type` | `feature`, `technical` or `bug` |
| `priority` | `critical`, `high`, `medium` or `low` |
| `points` | optional positive number; keep items at 13 or below and split larger ones |
| `assignee` | owner name |
| `status` | `todo`, `in_progress`, `review`, `testing`, `done` or `blocked` |

```yaml
type: story
sprint_id: sprint-YYYY-MM-DD
story_type: feature
priority: high
points: 3
assignee: Unassigned
status: todo
```

Write the description as "As a `<role>`, I want `<capability>`, so that `<benefit>`." and list testable acceptance criteria in the Story body. Keep Story status and points in frontmatter so progress stays deterministic.

## Technical documents

Extra field `area` names the owning subsystem. Status: `draft`, `active`, `deprecated` or `archived`. Use `technical` for design, `guide` for procedures, `adr` for durable decisions and `overview` for navigation or context.

## Validation

```bash
cd portal
pnpm validate:content
```

Validation rejects invalid fields, duplicate ids, missing Sprint, Milestone, or Story references, source paths that escape the workspace and broken relative links. Fix every error before committing; an invalid runtime edit keeps the previous valid index online.
