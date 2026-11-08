import html
import math
import xml.etree.ElementTree as ElementTree
from collections import Counter, defaultdict

from tgwitness import message_details
from tgwitness.action_protocol import moment
from tgwitness.indicators import Indicators

FORMAT = "tgwitness-analyzer-graph-v1"
MESSAGE_KINDS = "message.new,message.snapshot,message.recovered"
EVENT_LIMIT = 50000
MAX_NODES = 300
SVG_NODES = 120
MAX_REFS = 5
KINDS = ("replies", "forwards", "mentions", "indicators")
INDICATOR_KINDS = ("wallet", "domain", "url", "telegram", "telegram-invite", "email")
NODE_COLORS = {"account": "#2f6fc4", "source": "#8f4fb3", "mention": "#6b7b8b", "indicator": "#c98a12"}
EDGE_COLORS = {"reply": "#2f6fc4", "forward": "#8f4fb3", "mention": "#8c96a0", "posted": "#c98a12"}
COMMUNITY_COLORS = ("#2f6fc4", "#3d9a46", "#b03a14", "#8f4fb3", "#c98a12", "#1b8a8a", "#a0306a", "#5b6b7b")
LIMITS = (
    "Edges count observed messages in the chosen chats. A missing edge does not mean there was no contact.",
    "A shared indicator means the same string appeared. Who controls it is a separate question.",
    "Forward sources and mentions are what the messages show; hidden forwards and private chats are not visible.",
    "Communities are a reading aid computed from replies and posting patterns, not proven groups or organisations.",
    "Only the newest records read for this analysis are included.",
)


def mapping(value):
    return value if isinstance(value, dict) else {}


def reply_target(payload):
    reply = mapping(mapping(payload.get("raw")).get("reply_to"))
    if payload.get("reply_to_peer_id") is not None or reply.get("reply_to_peer_id") is not None:
        return None
    value = payload.get("reply_to_message_id", reply.get("reply_to_msg_id"))
    return value if type(value) is int else None


def read_messages(reader, chats, limit=EVENT_LIMIT):
    events = reader.events(chat_ids=sorted(chats), kind=MESSAGE_KINDS, limit=limit)
    messages = {}
    for event in sorted(events, key=lambda item: item["seq"]):
        key = (event.get("chat_id"), event.get("message_id"))
        if key[1] is None or key in messages:
            continue
        payload = mapping(event.get("payload"))
        sender = mapping(payload.get("sender_observation"))
        messages[key] = {
            "chat": key[0], "id": key[1], "seq": event["seq"], "hash": event.get("hash"),
            "sender": payload.get("sender_id") if payload.get("sender_id") is not None else sender.get("id"),
            "name": sender.get("display_name") or (("@" + sender["username"]) if sender.get("username") else None),
            "outgoing": bool(payload.get("outgoing")), "text": payload.get("text") if isinstance(payload.get("text"), str) else "",
            "sent": moment(payload.get("sent_at")) or moment(event.get("observed_at")),
            "reply_to": reply_target(payload),
            "details": message_details.details(payload.get("raw"))}
    return list(messages.values()), len(events) >= limit


def reference(message):
    return {"chat": message["chat"], "message": message["id"], "seq": message["seq"], "hash": message["hash"]}


class Graph:
    def __init__(self):
        self.nodes, self.edges = {}, {}

    def node(self, key, kind, label, **extra):
        node = self.nodes.setdefault(key, {"id": key, "kind": kind, "label": label, "messages": 0, **extra})
        node["label"] = node["label"] or label
        return node

    def edge(self, source, target, kind, ref):
        item = self.edges.setdefault((source, target, kind), {"source": source, "target": target, "kind": kind,
                                                              "weight": 0, "refs": []})
        item["weight"] += 1
        if len(item["refs"]) < MAX_REFS:
            item["refs"].append(ref)


def account(graph, user, name=None, outgoing=False):
    return graph.node("account:" + str(user), "account",
                      name or ("This account" if outgoing else "ID " + str(user)), user_id=user)["id"]


def communities(ids, edges):
    neighbours = defaultdict(Counter)
    for edge in edges:
        neighbours[edge["source"]][edge["target"]] += edge["weight"]
        neighbours[edge["target"]][edge["source"]] += edge["weight"]
    label = {node: index for index, node in enumerate(sorted(ids))}
    for _ in range(20):
        changed = False
        for node in sorted(ids):
            votes = Counter()
            for other, weight in neighbours[node].items():
                votes[label[other]] += weight
            if not votes:
                continue
            best = max(votes.items(), key=lambda item: (item[1], -item[0]))[0]
            if best != label[node]:
                label[node], changed = best, True
        if not changed:
            break
    order = {}
    for node in sorted(ids):
        order.setdefault(label[node], len(order))
    return {node: order[label[node]] for node in ids}


def build(messages, chats=(), kinds=KINDS, truncated=False, max_nodes=MAX_NODES):
    graph = Graph()
    index = {(m["chat"], m["id"]): m for m in messages}
    for message in messages:
        if message["sender"] is None:
            continue
        source = account(graph, message["sender"], message["name"], message["outgoing"])
        graph.nodes[source]["messages"] += 1
        ref, details = reference(message), message["details"]
        parent = index.get((message["chat"], message["reply_to"])) if message["reply_to"] else None
        if "replies" in kinds and parent and parent["sender"] is not None and parent["sender"] != message["sender"]:
            graph.edge(source, account(graph, parent["sender"], parent["name"], parent["outgoing"]), "reply", ref)
        forward = mapping(details.get("forwarded_from"))
        if "forwards" in kinds and (forward.get("from_id") is not None or forward.get("from_name")):
            origin = forward.get("from_id")
            if isinstance(origin, int) and origin > 0:
                target = account(graph, origin, forward.get("from_name"))
            else:
                key = "source:" + (str(origin) if origin is not None else "name:" + str(forward.get("from_name")))
                target = graph.node(key, "source", forward.get("from_name") or "ID " + str(origin))["id"]
            graph.edge(source, target, "forward", ref)
        mentioned = set()
        if "mentions" in kinds:
            for entity in details.get("text_entities") or []:
                if entity.get("type") == "mention" and entity.get("text"):
                    target = graph.node("mention:" + entity["text"].lower(), "mention", entity["text"])["id"]
                elif entity.get("type") == "mention_name" and isinstance(entity.get("user_id"), int):
                    target = account(graph, entity["user_id"], entity.get("text"))
                else:
                    continue
                if target != source and target not in mentioned:
                    mentioned.add(target)
                    graph.edge(source, target, "mention", ref)
        if "indicators" in kinds:
            found = Indicators()
            found.message(message["text"], details, None, None)
            for item in found.result()["items"]:
                if item["kind"] == "telegram":
                    target = graph.node("mention:" + item["value"].lower(), "mention", item["value"])["id"]
                    if target not in mentioned:
                        mentioned.add(target)
                        graph.edge(source, target, "mention", ref)
                elif item["kind"] in INDICATOR_KINDS:
                    target = graph.node("indicator:" + item["kind"] + ":" + item["value"], "indicator", item["value"],
                                        indicator_kind=item["kind"], chain=item.get("chain"))["id"]
                    graph.edge(source, target, "posted", ref)
    degree = Counter()
    for edge in graph.edges.values():
        degree[edge["source"]] += edge["weight"]
        degree[edge["target"]] += edge["weight"]
    ordered = sorted(graph.nodes, key=lambda key: (-degree[key], -graph.nodes[key]["messages"], key))
    keep = set(ordered[:max_nodes])
    edges = sorted((e for e in graph.edges.values() if e["source"] in keep and e["target"] in keep),
                   key=lambda e: (-e["weight"], e["source"], e["target"], e["kind"]))
    groups = communities(keep, edges)
    nodes = [{**graph.nodes[key], "degree": degree[key], "community": groups[key]} for key in ordered if key in keep]
    shared = Counter(e["target"] for e in edges if e["kind"] == "posted")
    return {"format": FORMAT, "chats": sorted(chats), "kinds": list(kinds), "nodes": nodes, "edges": edges,
            "totals": {"nodes": len(graph.nodes), "shown_nodes": len(nodes), "edges": len(edges),
                       "accounts": sum(n["kind"] == "account" for n in nodes),
                       "communities": len({n["community"] for n in nodes if n["degree"]}),
                       "indicators_shared_by_several": sum(count > 1 for count in shared.values())},
            "truncated": truncated or len(graph.nodes) > max_nodes, "limits": list(LIMITS)}


def collect(reader, chats, kinds=KINDS, limit=EVENT_LIMIT):
    messages, truncated = read_messages(reader, chats, limit)
    return build(messages, chats, kinds, truncated)


def layout(nodes, edges, width=1200, height=760, iterations=150):
    ids = [n["id"] for n in sorted(nodes, key=lambda n: (n["community"], n["id"]))]
    count = len(ids)
    if not count:
        return {}
    centre_x, centre_y, radius = width / 2, height / 2, min(width, height) * 0.38
    position = {node: [centre_x + radius * math.cos(2 * math.pi * i / count),
                       centre_y + radius * math.sin(2 * math.pi * i / count)] for i, node in enumerate(ids)}
    if count == 1:
        return {ids[0]: (centre_x, centre_y)}
    spring = math.sqrt(width * height / count) * 0.6
    links = [(e["source"], e["target"], math.log1p(e["weight"])) for e in edges if e["source"] in position and e["target"] in position]
    temperature = width / 10
    for _ in range(iterations):
        moves = {node: [0.0, 0.0] for node in ids}
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                dx, dy = position[a][0] - position[b][0], position[a][1] - position[b][1]
                distance = math.hypot(dx, dy) or 0.01
                force = spring * spring / distance
                moves[a][0] += dx / distance * force
                moves[a][1] += dy / distance * force
                moves[b][0] -= dx / distance * force
                moves[b][1] -= dy / distance * force
        for a, b, weight in links:
            dx, dy = position[a][0] - position[b][0], position[a][1] - position[b][1]
            distance = math.hypot(dx, dy) or 0.01
            force = distance * distance / spring * (1 + weight)
            moves[a][0] -= dx / distance * force
            moves[a][1] -= dy / distance * force
            moves[b][0] += dx / distance * force
            moves[b][1] += dy / distance * force
        for node in ids:
            dx, dy = moves[node]
            distance = math.hypot(dx, dy) or 0.01
            step = min(distance, temperature)
            position[node][0] = min(width - 60, max(60, position[node][0] + dx / distance * step))
            position[node][1] = min(height - 40, max(40, position[node][1] + dy / distance * step))
        temperature *= 0.95
    return {node: (round(x, 1), round(y, 1)) for node, (x, y) in position.items()}


def short(text, size=28):
    text = " ".join(str(text or "").split())
    return text if len(text) <= size else text[:size - 1] + "…"


def e(value):
    return html.escape(str(value), quote=True)


def svg(model, title="Connections", width=1200, height=760):
    nodes = model["nodes"][:SVG_NODES]
    shown = {n["id"] for n in nodes}
    edges = [edge for edge in model["edges"] if edge["source"] in shown and edge["target"] in shown]
    where = layout(nodes, edges, width, height)
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + str(width) + " " + str(height + 90)
             + '" font-family="system-ui, sans-serif" role="img" aria-label="' + e(title) + '">',
             "<title>" + e(title) + "</title>",
             '<rect width="100%" height="100%" fill="#ffffff"/>',
             '<text x="24" y="34" font-size="20" font-weight="600" fill="#17202a">' + e(title) + "</text>"]
    for edge in edges:
        (x1, y1), (x2, y2) = where[edge["source"]], where[edge["target"]]
        records = ", ".join("#" + str(r["seq"]) for r in edge["refs"])
        parts.append('<line x1="' + str(x1) + '" y1="' + str(y1) + '" x2="' + str(x2) + '" y2="' + str(y2)
                     + '" stroke="' + EDGE_COLORS.get(edge["kind"], "#8c96a0") + '" stroke-opacity="0.55" stroke-width="'
                     + str(round(1 + math.log1p(edge["weight"]) * 1.5, 1)) + '"><title>' + e(edge["kind"] + " × "
                     + str(edge["weight"]) + " · records " + records) + "</title></line>")
    for node in nodes:
        x, y = where[node["id"]]
        radius = round(5 + min(18, math.sqrt(node["degree"] + node["messages"]) * 2), 1)
        colour = (COMMUNITY_COLORS[node["community"] % len(COMMUNITY_COLORS)] if node["kind"] == "account"
                  else NODE_COLORS.get(node["kind"], "#6b7b8b"))
        shape = ('<rect x="' + str(x - radius) + '" y="' + str(y - radius) + '" width="' + str(2 * radius)
                 + '" height="' + str(2 * radius) + '" rx="3"' if node["kind"] == "indicator"
                 else '<circle cx="' + str(x) + '" cy="' + str(y) + '" r="' + str(radius) + '"')
        parts.append("<g>" + shape + ' fill="' + colour + '" stroke="#ffffff" stroke-width="1.5"><title>'
                     + e(node["kind"] + ": " + str(node["label"]) + " · messages " + str(node["messages"])
                         + " · connections " + str(node["degree"])) + "</title></" + ("rect" if node["kind"] == "indicator" else "circle")
                     + '><text x="' + str(round(x + radius + 4, 1)) + '" y="' + str(round(y + 4, 1))
                     + '" font-size="12" fill="#17202a">' + e(short(node["label"])) + "</text></g>")
    legend = [("account", "Account (colour = community)"), ("source", "Forward source"), ("mention", "Mention"),
              ("indicator", "Wallet, domain or link")]
    for index, (kind, label) in enumerate(legend):
        x = 24 + index * 280
        parts.append('<circle cx="' + str(x) + '" cy="' + str(height + 24) + '" r="7" fill="' + NODE_COLORS[kind]
                     + '"/><text x="' + str(x + 14) + '" y="' + str(height + 28) + '" font-size="13" fill="#3a4651">'
                     + e(label) + "</text>")
    caption = model["limits"][0] + " " + model["limits"][1]
    parts.append('<text x="24" y="' + str(height + 62) + '" font-size="12" fill="#5b6b7b">' + e(short(caption, 200))
                 + "</text>")
    if len(model["nodes"]) > len(nodes):
        parts.append('<text x="24" y="' + str(height + 80) + '" font-size="12" fill="#b03a14">'
                     + e("Showing the " + str(len(nodes)) + " most connected of " + str(len(model["nodes"])) + " nodes.")
                     + "</text>")
    parts.append("</svg>")
    return "".join(parts)


def gexf(model, description="TgWitness analyzer graph"):
    root = ElementTree.Element("gexf", {"xmlns": "http://gexf.net/1.3", "version": "1.3"})
    meta = ElementTree.SubElement(root, "meta")
    ElementTree.SubElement(meta, "creator").text = "TgWitness analyzer"
    ElementTree.SubElement(meta, "description").text = description + ". " + " ".join(model["limits"])
    graph = ElementTree.SubElement(root, "graph", {"defaultedgetype": "directed", "mode": "static"})
    node_attributes = ElementTree.SubElement(graph, "attributes", {"class": "node"})
    for index, (name, kind) in enumerate((("kind", "string"), ("community", "integer"), ("messages", "integer"),
                                          ("indicator_kind", "string"))):
        ElementTree.SubElement(node_attributes, "attribute", {"id": str(index), "title": name, "type": kind})
    edge_attributes = ElementTree.SubElement(graph, "attributes", {"class": "edge"})
    for index, name in enumerate(("kind", "records")):
        ElementTree.SubElement(edge_attributes, "attribute", {"id": str(index), "title": name, "type": "string"})
    nodes = ElementTree.SubElement(graph, "nodes")
    for node in model["nodes"]:
        item = ElementTree.SubElement(nodes, "node", {"id": node["id"], "label": str(node["label"])})
        values = ElementTree.SubElement(item, "attvalues")
        for index, value in enumerate((node["kind"], node["community"], node["messages"], node.get("indicator_kind") or "")):
            ElementTree.SubElement(values, "attvalue", {"for": str(index), "value": str(value)})
    edges = ElementTree.SubElement(graph, "edges")
    for number, edge in enumerate(model["edges"]):
        item = ElementTree.SubElement(edges, "edge", {"id": "e" + str(number), "source": edge["source"],
                                                      "target": edge["target"], "weight": str(edge["weight"])})
        values = ElementTree.SubElement(item, "attvalues")
        records = " ".join(str(r["seq"]) + ":" + str(r["hash"]) for r in edge["refs"])
        for index, value in enumerate((edge["kind"], records)):
            ElementTree.SubElement(values, "attvalue", {"for": str(index), "value": value})
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
