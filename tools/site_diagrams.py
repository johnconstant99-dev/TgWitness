"""Mermaid diagrams from the Markdown docs, drawn at build time as static SVG.

Only what the docs use is supported: flowchart TD/LR with [labels], -->, -.-> and labelled
edges, subgraphs, and sequenceDiagram with participants, ->> messages and notes. The SVG is
readable without JavaScript; docs.js only adds the drawing animation.

Layouts: a short left-to-right chain stays horizontal, a long chain is folded into rows that
read like a path (a "snake"), anything wider is drawn top-down in layers.
"""
import html
import math
import re

LINE, PAD_X, PAD_Y = 18, 14, 11
CHAR = 6.9
WIDTH = 720
GAP_TD, GAP_LR, CROSS_GAP, SNAKE_COLUMNS = 44, 54, 18, 3
NODE_SPEC = r"([A-Za-z]\w*)(?:\s*\[([^\]]*)\]|\s*\(([^)]*)\))?"
EDGE_SPEC = r"\s*(?:-->\|([^|]*)\||--\s+([^>]+?)\s+-->|-\.\s+(.+?)\s+\.->|(-\.->)|-->)\s*"
NODE = re.compile(NODE_SPEC)
EDGE = re.compile(EDGE_SPEC)


def esc(value):
    return html.escape(str(value), quote=True)


def units(text):
    """Width in Latin-character units: CJK characters are about twice as wide."""
    return sum(2 if ord(c) >= 0x2E80 else 1 for c in str(text))


def wrap(text, limit):
    """Lines of at most `limit` units, breaking at spaces, or between characters in CJK text."""
    words = []
    for word in str(text).split():
        while units(word) > limit:
            cut = 1
            while cut < len(word) and units(word[:cut + 1]) <= limit:
                cut += 1
            words.append(word[:cut])
            word = word[cut:]
        words.append(word)
    lines, current = [], ""
    for word in words:
        joined = current + (" " if current and not (ord(word[0]) >= 0x2E80 and ord(current[-1]) >= 0x2E80) else "") + word
        if current and units(joined) > limit:
            lines.append(current)
            current = word
        else:
            current = joined
    return (lines + [current]) if current else lines or [""]


def text_lines(lines, x, y, cls):
    """<text> centred on x, its block vertically centred on y."""
    top = y - (len(lines) - 1) * LINE / 2
    spans = "".join(f'<tspan x="{x:.1f}" y="{top + i * LINE:.1f}">{esc(line)}</tspan>' for i, line in enumerate(lines))
    return f'<text class="{cls}" text-anchor="middle" dominant-baseline="central">{spans}</text>'


def marker(prefix):
    return (f'<defs><marker id="{prefix}-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="flow-arrowhead"/>'
            '</marker></defs>')


def parse_flowchart(source):
    lines = [line.strip() for line in source.strip().splitlines() if line.strip()]
    direction = lines[0].split()[1] if len(lines[0].split()) > 1 else "TD"
    nodes, edges, groups, stack = {}, [], [], []

    def node(match):
        key, square, round_ = match.group(1), match.group(2), match.group(3)
        label = square if square is not None else round_
        entry = nodes.setdefault(key, {"id": key, "label": key, "order": len(nodes), "group": None})
        if label is not None:
            entry["label"] = label.strip().strip('"')
        if stack and entry["group"] is None:
            entry["group"] = stack[-1]
        return key

    for line in lines[1:]:
        if line.startswith("subgraph"):
            match = re.match(r"subgraph\s+" + NODE_SPEC, line)
            groups.append({"id": match.group(1), "title": match.group(2) or match.group(3) or match.group(1)})
            stack.append(len(groups) - 1)
            continue
        if line == "end":
            stack.pop()
            continue
        if line.startswith(("classDef", "class ", "style ", "%%")):
            continue
        match = NODE.match(line)
        if not match:
            continue
        previous, position = node(match), match.end()
        while position < len(line):
            edge = EDGE.match(line, position)
            if not edge:
                break
            label = next((g for g in edge.groups()[:3] if g), None)
            match = NODE.match(line, edge.end())
            if not match:
                break
            target = node(match)
            edges.append({"from": previous, "to": target, "label": label.strip() if label else None,
                          "dotted": bool(edge.group(3) or edge.group(4))})
            previous, position = target, match.end()
    return direction, nodes, edges, groups


def layers_of(nodes, edges):
    """Longest-path layering without back edges; a source sits just before its first child."""
    children = {key: [] for key in nodes}
    for edge in edges:
        children[edge["from"]].append(edge)
    state = {}

    def visit(key):
        state[key] = "open"
        for edge in children[key]:
            if state.get(edge["to"]) == "open":
                edge["back"] = True
            elif edge["to"] not in state:
                visit(edge["to"])
        state[key] = "done"
    for key in sorted(nodes, key=lambda k: nodes[k]["order"]):
        if key not in state:
            visit(key)
    forward = [e for e in edges if not e.get("back")]
    layer = {key: 0 for key in nodes}
    for _ in range(len(nodes)):
        for edge in forward:
            layer[edge["to"]] = max(layer[edge["to"]], layer[edge["from"]] + 1)
    incoming = {e["to"] for e in forward}
    for key in nodes:
        below = [layer[e["to"]] for e in forward if e["from"] == key]
        if key not in incoming and below:
            layer[key] = min(below) - 1
    return layer, forward


def bezier_point(p, t):
    u = 1 - t
    return (u**3 * p[0][0] + 3 * u * u * t * p[1][0] + 3 * u * t * t * p[2][0] + t**3 * p[3][0],
            u**3 * p[0][1] + 3 * u * u * t * p[1][1] + 3 * u * t * t * p[2][1] + t**3 * p[3][1])


def curve(points, t=.5):
    """Cubic Bezier: SVG path, length and midpoint."""
    previous, total = points[0], 0.0
    for i in range(1, 25):
        current = bezier_point(points, i / 24)
        total += math.dist(previous, current)
        previous = current
    (sx, sy), (ax, ay), (bx, by), (ex, ey) = points
    path = f"M{sx:.1f} {sy:.1f}C{ax:.1f} {ay:.1f} {bx:.1f} {by:.1f} {ex:.1f} {ey:.1f}"
    return path, max(total, 1.0), bezier_point(points, t)


def polyline(points, radius=10):
    """Orthogonal route with rounded corners: SVG path, length and midpoint of its longest leg."""
    path, total = f"M{points[0][0]:.1f} {points[0][1]:.1f}", 0.0
    for i in range(1, len(points)):
        total += math.dist(points[i - 1], points[i])
    for i in range(1, len(points) - 1):
        (px, py), (cx, cy), (nx, ny) = points[i - 1], points[i], points[i + 1]
        r = min(radius, math.dist((px, py), (cx, cy)) / 2, math.dist((cx, cy), (nx, ny)) / 2)
        ix = cx - math.copysign(r, cx - px) if px != cx else cx
        iy = cy - math.copysign(r, cy - py) if py != cy else cy
        ox = cx + math.copysign(r, nx - cx) if nx != cx else cx
        oy = cy + math.copysign(r, ny - cy) if ny != cy else cy
        path += f"L{ix:.1f} {iy:.1f}Q{cx:.1f} {cy:.1f} {ox:.1f} {oy:.1f}"
    path += f"L{points[-1][0]:.1f} {points[-1][1]:.1f}"
    legs = [(math.dist(points[i], points[i + 1]), i) for i in range(len(points) - 1)]
    _, i = max(legs)
    mid = ((points[i][0] + points[i + 1][0]) / 2, (points[i][1] + points[i + 1][1]) / 2)
    return path, max(total, 1.0), mid


def size_nodes(nodes, limit):
    for item in nodes.values():
        item["lines"] = wrap(item["label"], limit)
        item["w"] = max(104, max(units(line) for line in item["lines"]) * CHAR + 2 * PAD_X)
        item["h"] = len(item["lines"]) * LINE + 2 * PAD_Y


def side(item, towards):
    """The point on a node's border facing another node (left/right/top/bottom)."""
    dx, dy = towards["x"] - item["x"], towards["y"] - item["y"]
    if abs(dx) * item["h"] >= abs(dy) * item["w"]:
        return item["x"] + math.copysign(item["w"] / 2, dx), item["y"]
    return item["x"], item["y"] + math.copysign(item["h"] / 2, dy)


def layered(nodes, edges, groups, layer, forward, horizontal):
    size_nodes(nodes, 17 if horizontal else 26)
    count = max(layer.values()) + 1
    main_size = (lambda n: n["w"]) if horizontal else (lambda n: n["h"])
    cross_size = (lambda n: n["h"]) if horizontal else (lambda n: n["w"])
    by_layer = [[k for k in sorted(nodes, key=lambda k: nodes[k]["order"]) if layer[k] == i] for i in range(count)]
    parents = {key: [e["from"] for e in forward if e["to"] == key] for key in nodes}
    cross = {}
    for keys in by_layer:
        desired = {}
        for key in keys:
            placed = [cross[p] for p in parents[key] if p in cross]
            desired[key] = sum(placed) / len(placed) if placed else None
        group_rank = {}
        for key in keys:
            group_rank.setdefault(nodes[key]["group"], len(group_rank))
        keys.sort(key=lambda k: (group_rank[nodes[k]["group"]],
                                 desired[k] if desired[k] is not None else math.inf, nodes[k]["order"]))
        position, centres = 0.0, {}
        for key in keys:
            size = cross_size(nodes[key])
            start = position if desired[key] is None else max(position, desired[key] - size / 2)
            centres[key] = start + size / 2
            position = start + size + CROSS_GAP
        wanted = [desired[k] - centres[k] for k in keys if desired[k] is not None]
        shift = sum(wanted) / len(wanted) if wanted else 0
        for key in keys:
            cross[key] = centres[key] + shift
    low = min(cross[k] - cross_size(nodes[k]) / 2 for k in nodes)
    margin = 22 if groups else 6
    main, offset = {}, margin + (14 if groups else 0)
    gap = GAP_LR if horizontal else GAP_TD
    for index, keys in enumerate(by_layer):
        size = max(main_size(nodes[k]) for k in keys)
        for key in keys:
            main[key] = offset + size / 2

        labelled = [label_size(e["label"])[1] for e in edges if e["label"] and layer[e["from"]] == index]
        crossing = any(nodes[k]["group"] is not None for k in keys) or (
            index + 1 < count and any(nodes[k]["group"] is not None for k in by_layer[index + 1]))
        offset += size + max([gap] + [h + 24 for h in labelled]) + (14 if groups and crossing else 0)
    for key, item in nodes.items():
        c = cross[key] - low + margin
        item["x"], item["y"] = (main[key], c) if horizontal else (c, main[key])
    if groups:

        for index in range(len(groups)):
            members = [n for n in nodes.values() if n["group"] == index]
            if not members:
                continue
            box = frame(members)
            for item in nodes.values():
                if item["group"] == index:
                    continue
                if horizontal and overlaps(box, item):
                    item["y"] = box[3] + 18 + item["h"] / 2
                elif not horizontal and overlaps(box, item):
                    item["x"] = box[2] + 18 + item["w"] / 2
    width = max(n["x"] + n["w"] / 2 for n in nodes.values()) + margin
    height = max(n["y"] + n["h"] / 2 for n in nodes.values()) + margin
    pairs = {(e["from"], e["to"]) for e in edges}
    for edge in edges:
        a, b = nodes[edge["from"]], nodes[edge["to"]]
        bend = 7 if (edge["to"], edge["from"]) in pairs else 0
        bend = -bend if edge.get("back") else bend
        if horizontal:
            sx = a["x"] + math.copysign(a["w"] / 2, b["x"] - a["x"])
            ex = b["x"] - math.copysign(b["w"] / 2, b["x"] - a["x"])
            sy, ey, mid = a["y"] + bend, b["y"] + bend, (sx + ex) / 2
            edge["path"], edge["length"], edge["mid"] = curve([(sx, sy), (mid, sy), (mid, ey), (ex, ey)], spot(edge, edges))
        else:
            sy = a["y"] + math.copysign(a["h"] / 2, b["y"] - a["y"])
            ey = b["y"] - math.copysign(b["h"] / 2, b["y"] - a["y"])
            sx, ex, mid = a["x"] + bend, b["x"] + bend, (sy + ey) / 2
            edge["path"], edge["length"], edge["mid"] = curve([(sx, sy), (sx, mid), (ex, mid), (ex, ey)], spot(edge, edges))
        if bend and edge["label"]:

            w, h = label_size(edge["label"])
            mx, my = edge["mid"]
            edge["mid"] = (mx, my + math.copysign(h / 2 + 3, bend)) if horizontal else (mx + math.copysign(w / 2 + 4, bend), my)
    return width, height


def spot(edge, edges):
    """Where along an edge its label goes: away from where several edges meet."""
    if sum(e["from"] == edge["from"] for e in edges) > 1:
        return .68
    if sum(e["to"] == edge["to"] for e in edges) > 1:
        return .32
    return .5


def label_size(label):
    lines = wrap(label, 28)
    return max(units(line) for line in lines) * 6.3 + 16, len(lines) * 15 + 8


def frame(members):
    return (min(n["x"] - n["w"] / 2 for n in members) - 14, min(n["y"] - n["h"] / 2 for n in members) - 26,
            max(n["x"] + n["w"] / 2 for n in members) + 14, max(n["y"] + n["h"] / 2 for n in members) + 12)


def overlaps(box, item):
    return not (item["x"] + item["w"] / 2 < box[0] or item["x"] - item["w"] / 2 > box[2]
                or item["y"] + item["h"] / 2 < box[1] or item["y"] - item["h"] / 2 > box[3])


def snake(nodes, edges, layer):
    """Layers left to right in rows of three; every other row runs back, so a row ends above
    the next row's start. Edges that skip ahead run along the outer margin."""
    size_nodes(nodes, 22)
    count = max(layer.values()) + 1
    margin, lane, gap, row_gap, stack_gap = 8, 22, 46, 50, 12
    column = max(n["w"] for n in nodes.values())
    column = min(column, (WIDTH - 2 * (margin + lane) - (SNAKE_COLUMNS - 1) * gap) / SNAKE_COLUMNS)
    for item in nodes.values():
        item["w"] = min(item["w"], column)
    cells = [[k for k in sorted(nodes, key=lambda k: nodes[k]["order"]) if layer[k] == i] for i in range(count)]
    rows = [list(range(start, min(start + SNAKE_COLUMNS, count))) for start in range(0, count, SNAKE_COLUMNS)]
    top = margin
    place = {}
    for r, row in enumerate(rows):
        height = max(sum(nodes[k]["h"] for k in cells[i]) + stack_gap * (len(cells[i]) - 1) for i in row)
        for position, i in enumerate(row):
            col = position if r % 2 == 0 else SNAKE_COLUMNS - 1 - position
            x = margin + lane + col * (column + gap) + column / 2
            stack = sum(nodes[k]["h"] for k in cells[i]) + stack_gap * (len(cells[i]) - 1)
            y = top + (height - stack) / 2
            for key in cells[i]:
                nodes[key]["x"], nodes[key]["y"] = x, y + nodes[key]["h"] / 2
                place[key] = (r, col)
                y += nodes[key]["h"] + stack_gap
        top += height + row_gap
    width = 2 * (margin + lane) + SNAKE_COLUMNS * column + (SNAKE_COLUMNS - 1) * gap
    height = top - row_gap + margin
    for edge in edges:
        a, b = nodes[edge["from"]], nodes[edge["to"]]
        (ra, ca), (rb, cb) = place[edge["from"]], place[edge["to"]]
        if ra == rb and abs(ca - cb) == 1:
            sx, sy = side(a, b)
            ex, ey = side(b, a)
            mid = (sx + ex) / 2
            edge["path"], edge["length"], edge["mid"] = curve([(sx, sy), (mid, sy), (mid, ey), (ex, ey)])
        elif rb == ra + 1 and ca == cb:
            sx, sy = a["x"], a["y"] + a["h"] / 2
            ex, ey = b["x"], b["y"] - b["h"] / 2
            mid = (sy + ey) / 2
            edge["path"], edge["length"], edge["mid"] = curve([(sx, sy), (sx, mid), (ex, mid), (ex, ey)])
        else:
            right = ca >= (SNAKE_COLUMNS - 1) / 2
            outer = width - margin - lane / 2 if right else margin + lane / 2
            sx = a["x"] + (a["w"] / 2 if right else -a["w"] / 2)
            ex = b["x"] + (b["w"] / 2 if right else -b["w"] / 2)
            edge["path"], edge["length"], edge["mid"] = polyline(
                [(sx, a["y"]), (outer, a["y"]), (outer, b["y"]), (ex, b["y"])])
    return width, height


def flowchart(source, number, tr=str):
    direction, nodes, edges, groups = parse_flowchart(source)
    for item in nodes.values():
        item["label"] = tr(item["label"])
    for edge in edges:
        edge["label"] = tr(edge["label"]) if edge["label"] else None
    for group in groups:
        group["title"] = tr(group["title"])
    layer, forward = layers_of(nodes, edges)
    count = max(layer.values()) + 1
    widest = max(sum(1 for k in nodes if layer[k] == i) for i in range(count))
    if direction in ("LR", "RL") and count <= 4 and not any(e["label"] for e in edges):
        width, height = layered(nodes, edges, groups, layer, forward, True)
    elif count > 4 and widest <= 2 and not groups:
        width, height = snake(nodes, edges, layer)
    else:
        width, height = layered(nodes, edges, groups, layer, forward, False)
    prefix = f"flow-{number}"
    parts = [marker(prefix)]
    for index, group in enumerate(groups):
        members = [n for n in nodes.values() if n["group"] == index]
        if not members:
            continue
        x0, y0, x1, y1 = frame(members)
        parts.append(f'<g class="flow-group"><rect x="{x0:.1f}" y="{y0:.1f}" width="{x1 - x0:.1f}" '
                     f'height="{y1 - y0:.1f}" rx="12"/><text x="{x0 + 12:.1f}" y="{y0 + 16:.1f}" '
                     f'class="flow-group-title">{esc(group["title"])}</text></g>')
    labels = []
    for edge in edges:
        step = layer[edge["from"]]
        cls = "flow-edge is-dotted" if edge["dotted"] else "flow-edge"
        parts.append(f'<path class="{cls}" d="{edge["path"]}" marker-end="url(#{prefix}-arrow)" '
                     f'style="--i:{step};--len:{edge["length"]:.0f}" pathLength="{edge["length"]:.0f}"/>')
        if not edge["dotted"]:
            parts.append(f'<circle class="flow-pulse" r="3.2" style="--i:{step}"><animateMotion begin="indefinite" '
                         f'dur="{max(1.4, edge["length"] / 90):.1f}s" repeatCount="indefinite" path="{edge["path"]}"/>'
                         '</circle>')
        if edge["label"]:
            lx, ly = edge["mid"]
            lines = wrap(edge["label"], 28)
            w = max(units(line) for line in lines) * 6.3 + 16
            h = len(lines) * 15 + 8
            labels.append(f'<g class="flow-label" style="--i:{step}"><rect x="{lx - w / 2:.1f}" y="{ly - h / 2:.1f}" '
                          f'width="{w:.1f}" height="{h:.1f}" rx="6"/>'
                          + "".join(f'<text x="{lx:.1f}" y="{ly - (len(lines) - 1) * 7.5 + i * 15:.1f}" '
                                    f'text-anchor="middle" dominant-baseline="central">{esc(line)}</text>'
                                    for i, line in enumerate(lines)) + "</g>")
    for key in sorted(nodes, key=lambda k: (layer[k], nodes[k]["order"])):
        item = nodes[key]
        parts.append(f'<g class="flow-node" style="--i:{layer[key]}"><rect x="{item["x"] - item["w"] / 2:.1f}" '
                     f'y="{item["y"] - item["h"] / 2:.1f}" width="{item["w"]:.1f}" height="{item["h"]:.1f}" rx="10"/>'
                     + text_lines(item["lines"], item["x"], item["y"], "flow-text") + "</g>")
    parts += labels
    steps = [f'{nodes[e["from"]]["label"]} → {nodes[e["to"]]["label"]}' + (f' ({e["label"]})' if e["label"] else "")
             for e in edges]
    return figure(number, width, height, "".join(parts), tr("Flow diagram"), steps, "flow", tr)


def sequence(source, number, tr=str):
    actors, rows = {}, []
    for line in source.strip().splitlines()[1:]:
        line = line.strip()
        if match := re.match(r"participant\s+(\w+)(?:\s+as\s+(.+))?$", line):
            actors[match.group(1)] = tr(match.group(2) or match.group(1))
        elif match := re.match(r"(\w+)\s*-{1,2}>>?\s*(\w+)\s*:\s*(.+)$", line):
            for key in match.group(1, 2):
                actors.setdefault(key, key)
            rows.append(("message", match.group(1), match.group(2), tr(match.group(3))))
        elif match := re.match(r"Note\s+over\s+(\w+)(?:\s*,\s*\w+)?\s*:\s*(.+)$", line):
            rows.append(("note", match.group(1), None, tr(match.group(2))))
    keys = list(actors)
    margin, head_h = 82, 46
    span = (WIDTH - 2 * margin) / max(1, len(keys) - 1)
    lane = {key: margin + i * span for i, key in enumerate(keys)}
    prefix = f"flow-{number}"
    y, body, steps = head_h + 34, [], []
    for index, (kind, a, b, text) in enumerate(rows):
        if kind == "message":
            x0, x1 = lane[a], lane[b]
            direction = 1 if x1 > x0 else -1
            sx, ex = x0 + 6 * direction, x1 - 6 * direction
            length = abs(ex - sx)
            body.append(f'<g class="seq-row" style="--i:{index}"><text class="seq-text" x="{(x0 + x1) / 2:.1f}" '
                        f'y="{y - 10:.1f}" text-anchor="middle">{esc(text)}</text><path class="flow-edge" '
                        f'd="M{sx:.1f} {y:.1f}H{ex:.1f}" marker-end="url(#{prefix}-arrow)" '
                        f'style="--i:{index};--len:{length:.0f}" pathLength="{length:.0f}"/></g>')
            steps.append(f"{actors[a]} → {actors[b]}: {text}")
            y += 48
        else:
            lines = wrap(text, 52)
            w = max(units(line) for line in lines) * CHAR + 28
            h = len(lines) * LINE + 18
            x = min(max(lane[a], w / 2 + 6), WIDTH - w / 2 - 6)
            body.append(f'<g class="seq-row seq-note" style="--i:{index}"><rect x="{x - w / 2:.1f}" y="{y - 14:.1f}" '
                        f'width="{w:.1f}" height="{h:.1f}" rx="8"/>' + text_lines(lines, x, y - 14 + h / 2, "flow-text")
                        + "</g>")
            steps.append(tr("Note on {name}").replace("{name}", actors[a]) + ": " + text)
            y += h + 18
    bottom = y - 10
    parts = [marker(prefix)]
    for key in keys:
        x = lane[key]
        w = max(108, units(actors[key]) * CHAR + 28)
        parts.append(f'<line class="seq-life" x1="{x:.1f}" y1="{head_h:.1f}" x2="{x:.1f}" y2="{bottom:.1f}"/>')
        parts.append(f'<g class="flow-node" style="--i:0"><rect x="{x - w / 2:.1f}" y="6" width="{w:.1f}" '
                     f'height="{head_h - 12}" rx="10"/>' + text_lines([actors[key]], x, head_h / 2 + 3, "flow-text") + "</g>")
    return figure(number, WIDTH, bottom + 8, "".join(parts + body), tr("Sequence diagram"), steps, "sequence", tr)


def figure(number, width, height, body, kind, steps, variant, tr=str):
    prefix = f"flow-{number}"
    return (f'<figure class="flow-figure flow-{variant}" data-diagram>'
            f'<div class="flow-canvas"><svg viewBox="0 0 {width:.0f} {height:.0f}" width="{width:.0f}" '
            f'height="{height:.0f}" role="img" aria-labelledby="{prefix}-title {prefix}-desc">'
            f'<title id="{prefix}-title">{kind}</title><desc id="{prefix}-desc">{esc("; ".join(steps))}</desc>'
            f'{body}</svg></div><details class="flow-steps"><summary>{esc(tr("Diagram as text"))}</summary><ol>'
            + "".join(f"<li>{esc(step)}</li>" for step in steps) + "</ol></details></figure>")


WORDS = ("Flow diagram", "Sequence diagram", "Diagram as text", "Note on {name}")


def labels_of(source):
    """Every English text a diagram shows, for translation."""
    kind = source.strip().split()[0]
    found = []
    if kind == "sequenceDiagram":
        for line in source.strip().splitlines()[1:]:
            line = line.strip()
            if match := re.match(r"participant\s+(\w+)(?:\s+as\s+(.+))?$", line):
                found.append(match.group(2) or match.group(1))
            elif match := re.match(r"\w+\s*-{1,2}>>?\s*\w+\s*:\s*(.+)$", line):
                found.append(match.group(1))
            elif match := re.match(r"Note\s+over\s+\w+(?:\s*,\s*\w+)?\s*:\s*(.+)$", line):
                found.append(match.group(1))
    elif kind in ("flowchart", "graph"):
        _, nodes, edges, groups = parse_flowchart(source)
        found += [n["label"] for n in nodes.values()] + [e["label"] for e in edges if e["label"]]
        found += [g["title"] for g in groups]
    return found


def render(source, number, labels=None):
    def tr(value):
        return (labels or {}).get(value, value)
    kind = source.strip().split()[0]
    if kind == "sequenceDiagram":
        return sequence(source, number, tr)
    if kind in ("flowchart", "graph"):
        return flowchart(source, number, tr)
    return "<pre><code>" + esc(source) + "</code></pre>"
