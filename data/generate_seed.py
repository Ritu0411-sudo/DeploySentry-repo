"""Generate seed data for the AstraTravel demo platform (DeploySentry Round 2).

Outputs (all synthetic, demo-only):
  data/seed.json        — agencies, users, flights, bookings, coupons
  data/gateway.log      — 30 days of JSONL gateway traffic (~40k lines)
  data/releases.json    — versioned deploys incl. the v2.4.0 change event
  data/har-sample.json  — two normal user journeys (HAR-style)
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = str(Path(__file__).resolve().parent)

AGENCIES = [
    {"id": "ag_skyways", "name": "SkyWays Travel"},
    {"id": "ag_globetrek", "name": "GlobeTrek Holidays"},
]

USERS = [
    {"username": "sky_admin", "agency_id": "ag_skyways", "role": "agency_admin"},
    {"username": "sky_agent1", "agency_id": "ag_skyways", "role": "sub_agent"},
    {"username": "sky_agent2", "agency_id": "ag_skyways", "role": "sub_agent"},
    {"username": "sky_fin", "agency_id": "ag_skyways", "role": "finance"},
    {"username": "globe_admin", "agency_id": "ag_globetrek", "role": "agency_admin"},
    {"username": "globe_agent1", "agency_id": "ag_globetrek", "role": "sub_agent"},
    {"username": "globe_fin", "agency_id": "ag_globetrek", "role": "finance"},
    {"username": "platform_admin", "agency_id": None, "role": "platform_admin"},
]

FLIGHTS = [
    {"flight_id": "AI-302", "from": "DEL", "to": "BOM", "base_fare": 5200},
    {"flight_id": "6E-441", "from": "DEL", "to": "BLR", "base_fare": 4800},
    {"flight_id": "UK-933", "from": "BOM", "to": "DXB", "base_fare": 14500},
    {"flight_id": "AI-111", "from": "DEL", "to": "LHR", "base_fare": 42000},
    {"flight_id": "6E-208", "from": "BLR", "to": "SIN", "base_fare": 12800},
    {"flight_id": "SG-512", "from": "DEL", "to": "GOI", "base_fare": 3900},
    {"flight_id": "AI-864", "from": "MAA", "to": "DEL", "base_fare": 5600},
    {"flight_id": "UK-707", "from": "HYD", "to": "BOM", "base_fare": 4100},
    {"flight_id": "6E-318", "from": "CCU", "to": "DEL", "base_fare": 6100},
    {"flight_id": "AI-540", "from": "BOM", "to": "COK", "base_fare": 4700},
    {"flight_id": "SG-901", "from": "DEL", "to": "KTM", "base_fare": 9800},
    {"flight_id": "UK-122", "from": "BLR", "to": "MAA", "base_fare": 2900},
]

FIRST = ["Aarav", "Meera", "Rohan", "Priya", "Kabir", "Ananya", "Vikram", "Sana",
         "Arjun", "Neha", "Dev", "Isha", "Manav", "Tara", "Yash", "Nia"]
LAST = ["Sharma", "Patel", "Iyer", "Khan", "Gupta", "Nair", "Reddy", "Das",
        "Mehta", "Joshi", "Singh", "Chopra", "Menon", "Bose", "Rao", "Gill"]

COUPONS = [
    {"code": "FLY10", "discount_pct": 10, "single_use": True, "status": "active"},
    {"code": "WELCOME20", "discount_pct": 20, "single_use": True, "status": "active"},
    {"code": "TRAVEL5", "discount_pct": 5, "single_use": False, "status": "active"},
    {"code": "AGENT15", "discount_pct": 15, "single_use": False, "status": "active"},
    {"code": "DIWALI25", "discount_pct": 25, "single_use": True, "status": "expired"},
    {"code": "SUMMER8", "discount_pct": 8, "single_use": False, "status": "expired"},
]

# ---- seed.json ----
bookings = []
for i in range(1, 41):
    agency = random.choice(AGENCIES)
    flight = random.choice(FLIGHTS)
    pax = random.randint(1, 3)
    fare = flight["base_fare"] * pax
    bookings.append({
        "id": f"AST-{1000 + i}",
        "agency_id": agency["id"],
        "flight_id": flight["flight_id"],
        "travellers": [
            {"name": f"{random.choice(FIRST)} {random.choice(LAST)}",
             "passport": f"X{random.randint(1000000, 9999999)}"}
            for _ in range(pax)],
        "fare": fare,
        "total": fare + random.choice([0, 250, 499]),
        "status": random.choice(["CONFIRMED", "CONFIRMED", "CONFIRMED", "CANCELLED",
                                 "REFUNDED", "HELD"]),
        "created": (datetime(2026, 10, 26) + timedelta(days=random.randint(0, 29),
                    hours=random.randint(0, 23))).isoformat(),
    })

seed = {"agencies": AGENCIES, "users": USERS, "flights": FLIGHTS,
        "bookings": bookings, "coupons": COUPONS,
        "demo_password": "Test@1234 (all test accounts, demo-only)"}
with open(f"{OUT}/seed.json", "w") as f:
    json.dump(seed, f, indent=2)

# ---- gateway.log: 30 days of traffic ----
# /v1/bookings never appears (zombie); /internal/supplier-sync appears (shadow).
# Login and the rare admin role change are in the log too, so the inventory
# agent does not mistake live endpoints for zombies.
ROUTES = [
    ("GET", "/search/flights", 0.30),
    ("GET", "/fares/quote", 0.20),
    ("POST", "/bookings/hold", 0.10),
    ("POST", "/bookings", 0.12),
    ("POST", "/bookings/{id}/pay", 0.10),
    ("POST", "/bookings/{id}/cancel", 0.05),
    ("POST", "/coupons/apply", 0.05),
    ("GET", "/bookings", 0.05),
    ("GET", "/bookings/{id}", 0.02),
    ("POST", "/auth/login", 0.05),
    ("POST", "/admin/users/{who}/role", 0.001),
    ("POST", "/internal/supplier-sync", 0.01),
]
paths, weights = zip(*[(f"{m} {p}", w) for m, p, w in ROUTES])
start = datetime(2026, 10, 26)
lines = 0
with open(f"{OUT}/gateway.log", "w") as f:
    for day in range(30):
        n = random.randint(1100, 1500)
        for _ in range(n):
            ts = start + timedelta(days=day, seconds=random.randint(0, 86399))
            route = random.choices(paths, weights=weights)[0]
            method, path = route.split(" ", 1)
            if "{id}" in path:
                path = path.replace("{id}", f"AST-{random.randint(1001, 1040)}")
            if "{who}" in path:
                path = path.replace("{who}", random.choice(
                    [u["username"] for u in USERS]))
            if path == "/search/flights":
                path += f"?from={random.choice(['DEL', 'BOM', 'BLR'])}" \
                        f"&to={random.choice(['BOM', 'BLR', 'DXB', 'SIN'])}" \
                        f"&date=2026-12-{random.randint(1, 28):02d}"
            user = random.choice([u["username"] for u in USERS
                                  if u["role"] in ("sub_agent", "agency_admin")])
            agency = next(u["agency_id"] for u in USERS if u["username"] == user)
            f.write(json.dumps({
                "ts": ts.isoformat(), "method": method, "path": path,
                "status": random.choices([200, 200, 200, 200, 400, 401, 404],
                                         weights=[85, 5, 3, 2, 2, 2, 1])[0],
                "user": user, "agency": agency,
                "latency_ms": random.randint(20, 420),
                "ip": f"10.0.{random.randint(1, 4)}.{random.randint(2, 250)}",
            }) + "\n")
            lines += 1
print(f"gateway.log: {lines} lines")

# ---- releases.json ----
releases = {
    "releases": [
        {"version": "v2.3.0", "deployed_at": "2026-11-01T06:00:00",
         "notes": "Baseline. Fare engine v3, coupon service, refund flow.",
         "changed_endpoints": []},
        {"version": "v2.4.0", "deployed_at": "DEMO_DAY",
         "notes": "Adds fare-modify endpoint for post-payment fare corrections.",
         "changed_endpoints": ["POST /v2/bookings/{id}/fare-modify"]},
    ]
}
with open(f"{OUT}/releases.json", "w") as f:
    json.dump(releases, f, indent=2)

# ---- har-sample.json: two normal journeys ----
har = {"journeys": [
    {"name": "search-hold-book-pay (sky_agent1)",
     "entries": [
         {"method": "GET", "url": "/search/flights?from=DEL&to=BOM&date=2026-12-05"},
         {"method": "GET", "url": "/fares/quote?flight_id=AI-302"},
         {"method": "POST", "url": "/bookings/hold",
          "body": {"flight_id": "AI-302", "travellers": 2}},
         {"method": "POST", "url": "/bookings",
          "body": {"hold_id": "HLD-881", "fare": 10400, "total": 10649}},
         {"method": "POST", "url": "/bookings/AST-1007/pay",
          "body": {"amount": 10649, "method": "card"}},
     ]},
    {"name": "cancel-refund (globe_agent1)",
     "entries": [
         {"method": "GET", "url": "/bookings/AST-1019"},
         {"method": "POST", "url": "/bookings/AST-1019/cancel",
          "body": {"reason": "traveller request"}},
     ]},
]}
with open(f"{OUT}/har-sample.json", "w") as f:
    json.dump(har, f, indent=2)

print("seed.json, releases.json, har-sample.json written")
