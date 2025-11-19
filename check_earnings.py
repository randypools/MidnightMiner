
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

import requests

from proxy_config import load_proxy_config

DEFAULT_API_BASE = "https://scavenger.prod.gd.midnighttge.io"


def discover_wallet_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    if root.is_file():
        yield root
        return

    for candidate in root.rglob("*.json"):
        if candidate.is_file():
            yield candidate


def extract_addresses_from_json(path: Path) -> Set[str]:
    try:
        with path.open("r", encoding="utf-8") as handler:
            data = json.load(handler)
    except (OSError, json.JSONDecodeError):
        return set()

    addresses: Set[str] = set()

    def _walk(node):
        if isinstance(node, dict):
            address = node.get("address")
            if isinstance(address, str) and address.startswith("addr"):
                addresses.add(address)
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return addresses


def fetch_wallet_statistics(session: requests.Session, wallet_address: str, api_base: str, use_defensio: bool = False) -> Optional[Tuple[float, int, dict]]:
    url = f"{api_base}/statistics/{wallet_address}"
    try:
        response = session.get(url, timeout=8)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Failed to fetch statistics for {wallet_address}: {exc}")
        return None

    local_stats = payload.get("local", {})
    # Determine which allocation field to use based on API
    allocation_field = "dfo_allocation" if use_defensio else "night_allocation"
    token_raw = local_stats.get(allocation_field, 0)
    try:
        token_amount = float(token_raw) / 1_000_000.0
    except Exception:  # noqa: BLE001
        token_amount = 0.0

    solutions = local_stats.get("crypto_receipts", 0)
    try:
        solutions_count = int(solutions)
    except Exception:  # noqa: BLE001
        solutions_count = 0

    return token_amount, solutions_count, payload


def mask_wallet_address(address: str, visible: int = 6) -> str:
    if len(address) <= visible * 2:
        return address
    return f"{address[:visible]}...{address[-visible:]}"


def create_sessions(proxy_config_path: str, desired_workers: int) -> Tuple[Tuple[requests.Session, str], ...]:
    proxies = load_proxy_config(proxy_config_path)

    sessions: list[Tuple[requests.Session, str]] = []

    if proxies:
        for entry in proxies[:desired_workers]:
            session = requests.Session()
            session.trust_env = False
            session.proxies.update(entry["proxies"])
            if entry["auth_header"]:
                session.headers["Proxy-Authorization"] = entry["auth_header"]
            display = entry["display"]
            sessions.append((session, display))
        print(f"Using {len(sessions)} proxy-backed session(s) (configured: {len(proxies)}).")
    else:
        for idx in range(desired_workers):
            session = requests.Session()
            session.trust_env = False
            sessions.append((session, f"direct#{idx + 1}"))
        print(f"Using {len(sessions)} direct session(s) without proxy.")

    return tuple(sessions)


def process_chunk(session: requests.Session, label: str, chunk: Iterable[str], api_base: str, use_defensio: bool = False) -> Dict[str, Tuple[float, int]]:
    results: Dict[str, Tuple[float, int]] = {}
    for wallet_address in chunk:
        result = fetch_wallet_statistics(session, wallet_address, api_base, use_defensio)
        if result is None:
            continue
        token_amount, solutions_count, _payload = result
        results[wallet_address] = (token_amount, solutions_count)
    return results


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize token balance for wallets described in JSON files."
    )
    parser.add_argument(
        "--wallets-path",
        nargs="+",
        default=["wallets.json"],
        help="Wallet JSON file(s) or directories (space-separated). Example: --wallets-path wallets.json json/",
    )
    parser.add_argument(
        "--address",
        type=str,
        help="Check a specific wallet address directly (ignores --wallets-path)",
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help=f"Statistics API base URL (default: {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--proxy-config",
        default="proxy.json",
        help="Path to proxy configuration file (default: proxy.json)",
    )
    parser.add_argument(
        "--proxy-count",
        type=int,
        default=16,
        help="Maximum number of concurrent proxy sessions (default: 16)",
    )
    parser.add_argument(
        "--defensio",
        action="store_true",
        help="Use Defensio API instead of Midnight API",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    # Override API base if using Defensio
    if args.defensio:
        args.api_base = "https://mine.defensio.io/api"

    # Determine token name based on API
    token_name = "DFO" if args.defensio else "NIGHT"

    # If --address is specified, use it directly and skip wallet file discovery
    if args.address:
        addresses = {args.address}
        print(f"Checking specific wallet address: {args.address}")
    else:
        wallet_roots = [Path(entry).resolve() for entry in args.wallets_path]
        wallet_files = {candidate for root in wallet_roots for candidate in discover_wallet_files(root)}

        if not wallet_files:
            joined_sources = ", ".join(str(root) for root in wallet_roots)
            print(f"No wallet JSON files found at: {joined_sources}")
            return 1

        addresses: Set[str] = set()
        for file_path in sorted(wallet_files):
            addresses |= extract_addresses_from_json(file_path)

        if not addresses:
            print("No wallet addresses discovered.")
            return 1

        print(f"Discovered {len(addresses)} unique wallet addresses from {len(wallet_files)} file(s).")

    sorted_addresses = sorted(addresses)
    session_target = max(1, min(args.proxy_count, len(sorted_addresses)))

    sessions = create_sessions(args.proxy_config, session_target)

    try:
        chunks: list[Tuple[requests.Session, str, list[str]]] = []
        session_count = len(sessions)
        for index, (session, label) in enumerate(sessions):
            assigned = sorted_addresses[index::session_count]
            if assigned:
                chunks.append((session, label, assigned))

        per_wallet: dict[str, Tuple[float, int]] = {}

        with ThreadPoolExecutor(max_workers=len(chunks) or 1) as executor:
            futures = [
                executor.submit(process_chunk, session, label, chunk, args.api_base, args.defensio)
                for session, label, chunk in chunks
            ]

            for future in futures:
                chunk_result = future.result()
                per_wallet.update(chunk_result)

        total_tokens = 0.0
        total_solutions = 0
        for address in sorted(per_wallet.keys()):
            token_amount, solutions_count = per_wallet[address]
            masked_address = mask_wallet_address(address)
            total_tokens += token_amount
            total_solutions += solutions_count
            print(f"{masked_address}: {token_amount:.6f} {token_name}, {solutions_count} solutions")

        print("-" * 60)
        print(f"Total {token_name} across {len(per_wallet)} wallet(s): {total_tokens:.6f}")
        print(f"Total solutions across {len(per_wallet)} wallet(s): {total_solutions}")

        missing = addresses - per_wallet.keys()
        if missing:
            print(f"WARNING: Failed to fetch statistics for {len(missing)} wallet(s).")

        return 0 if per_wallet else 2

    finally:
        for session, _label in sessions:
            session.close()


if __name__ == "__main__":
    sys.exit(main())


