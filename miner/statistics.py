"""Statistics and balance tracking for Midnight Miner"""
import logging
from .api_client import get_wallet_statistics


def fetch_total_night_balance(wallet_manager, api_base, use_defensio_api=False):
    """Fetch total token balance across all wallets once at startup.
    Returns balance or None if fetch failed.
    Fetches NIGHT allocation for Midnight, DFO allocation for Defensio."""
    total_balance = 0.0
    failed = False

    # Determine which allocation field to use based on API
    allocation_field = 'dfo_allocation' if use_defensio_api else 'night_allocation'

    for wallet in wallet_manager.wallets:
        stats = get_wallet_statistics(wallet['address'], api_base)
        if stats:
            local = stats.get('local', {})
            balance = local.get(allocation_field, 0) / 1000000.0
            total_balance += balance
        else:
            failed = True
            break

    if failed:
        logging.warning("Some wallet statistics could not be fetched.")
        return None  # Return None to indicate failure

    return total_balance
