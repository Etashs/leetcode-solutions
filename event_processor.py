from asyncio import graph
from common.risk_score import calculate_risk
from common.classifier import classify_attack
from common.attack_chain import build_attack_chains
from common.detector import detect_attacks
from common.log_parser import parse_log_line
from common.correlator import correlate_events
from common.graph_builder import build_graph, draw_graph

def process_log_file(file_path, source):
    events = []

    with open(file_path, "r") as f:
        lines = f.readlines()

        for line in lines:
            event = parse_log_line(line, source)
            if event:
                events.append(event)

    return events


def main():
    api_events = process_log_file("logs/api_logs.log", "API")
    service_events = process_log_file("logs/service_logs.log", "SERVICE")
    db_events = process_log_file("logs/db_logs.log", "DB")

    all_events = api_events + service_events + db_events

    # 🔥 CORRELATION
    grouped = correlate_events(all_events)

    # 🔥 PRINT EVENTS
    for user, events in grouped.items():
        print(f"\nUser: {user}")
        for event in events:
            print(f"{event.timestamp} | {event.source} | {event.action} | {event.user}")

    # 🔥 DETECTION
    alerts = detect_attacks(grouped)

    print("\n=== ALERTS ===")
    for alert in alerts:
        print(alert)

    # 🔥 BUILD CHAINS
    chains = build_attack_chains(grouped)

    print("\n=== ATTACK CHAINS ===")
    for user, chain in chains.items():
        print(f"{user} → {' → '.join(chain)}")

    # 🔥 CLASSIFICATION (ADD THIS)
    attack_types = classify_attack(chains)

    print("\n=== ATTACK TYPES ===")
    for user, attack in attack_types.items():
        print(f"{user} → {attack}")

    # 🔥 RISK SCORING (ADD THIS)
    risk_scores = calculate_risk(grouped)

    print("\n=== RISK SCORES ===")
    for user, score in risk_scores.items():
        print(f"{user} → Risk Score: {score}")

    # 🔥 GRAPH (ONLY ONCE)
    graph = build_graph(chains)
    draw_graph(graph)

if __name__ == "__main__":
    main()