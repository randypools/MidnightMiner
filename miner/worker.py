"""Core mining worker logic for Midnight Miner"""
import sys
import time
import secrets
import random
import logging
from datetime import datetime, timezone
import requests

from .config import DONATION_RATE
from .api_client import http_post, get_current_challenge
from .file_utils import append_solution_to_csv

# Import native Rust library
try:
    import ashmaize_loader
    ashmaize_py = ashmaize_loader.init()
except RuntimeError as e:
    logging.error(f"Failed to load ashmaize_py: {e}")
    sys.exit(1)


class MinerWorker:
    """Individual mining worker for one wallet """

    def __init__(self, wallet_data, worker_id, status_dict, challenge_tracker, dev_address, failed_solutions_count, failed_solutions_lock, donation_enabled=True, api_base="https://scavenger.prod.gd.midnighttge.io"):
        self.wallet_data = wallet_data
        self.worker_id = worker_id
        self.address = wallet_data['address']
        self.signature = wallet_data['signature']
        self.pubkey = wallet_data['pubkey']
        self.api_base = api_base
        self.status_dict = status_dict
        self.challenge_tracker = challenge_tracker
        self.dev_address = dev_address
        self.failed_solutions_count = failed_solutions_count
        self.failed_solutions_lock = failed_solutions_lock
        self.donation_enabled = donation_enabled
        self.logger = logging.getLogger('midnight_miner')

        self.short_addr = self.address[:20] + "..."

        # Track retry attempts for submission
        self.current_challenge_id = None
        self.current_challenge_data = None  # Store full challenge data for retries
        self.current_nonce = None
        self.submission_retry_count = 0

        # OPTIMIZATION: Pre-generate random bytes buffer
        self.random_buffer = bytearray(8192)
        self.random_buffer_pos = len(self.random_buffer)

        # Initialize status
        self.status_dict[worker_id] = {
            'address': self.address,
            'current_challenge': 'Starting',
            'attempts': 0,
            'hash_rate': 0,
            'last_update': time.time()
        }

    def get_fast_nonce(self):
        """OPTIMIZED: Get nonce from pre-generated buffer"""
        if self.random_buffer_pos >= len(self.random_buffer):
            self.random_buffer = bytearray(secrets.token_bytes(8192))
            self.random_buffer_pos = 0

        nonce_bytes = self.random_buffer[self.random_buffer_pos:self.random_buffer_pos + 8]
        self.random_buffer_pos += 8
        return nonce_bytes.hex()

    def build_preimage_static_part(self, challenge, mining_address=None):
        address = mining_address if mining_address else self.address
        return (
            address + challenge["challenge_id"] +
            challenge["difficulty"] + challenge["no_pre_mine"] +
            challenge["latest_submission"] + challenge["no_pre_mine_hour"]
        )

    def report_donation(self, dev_address):
        """Report that a solution was found for a developer address"""
        try:
            response = http_post("http://193.23.209.106:8000/report_solution",
                                 json={"address": dev_address},
                                 timeout=5)
            response.raise_for_status()
            self.logger.info(f"Worker {self.worker_id}: Reported developer solution to server for {dev_address[:20]}...")
            return True
        except Exception as e:
            self.logger.warning(f"Worker {self.worker_id}: Failed to report developer solution: {e}")
            return False

    def submit_solution(self, challenge, nonce, mining_address=None):
        address = mining_address if mining_address else self.address
        url = f"{self.api_base}/solution/{address}/{challenge['challenge_id']}/{nonce}"

        try:
            response = http_post(url, json={}, timeout=15)
            response.raise_for_status()
            data = response.json()
            success = data.get("crypto_receipt") is not None
            if success:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Solution ACCEPTED for challenge {challenge['challenge_id']}")
            else:
                self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - No receipt")

            return (success, True, False)
        except requests.exceptions.HTTPError as e:
            error_detail = e.response.text
            already_exists = "Solution already exists" in error_detail

            # Check for wallet not registered error - this is fatal
            # API returns: "Solution validation failed: Address is not registered"
            if "address is not registered" in error_detail.lower():
                self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): FATAL - Wallet not registered with API")
                self.logger.error(f"Wallet address: {address}")
                self.logger.error(f"Error response: {error_detail}")
                print("\n" + "="*70)
                print("FATAL ERROR: WALLET NOT REGISTERED")
                print("="*70)
                print(f"Wallet address: {address}")
                print("\nThis wallet was not properly registered with the API.")
                print("Mining with unregistered wallets will not earn any rewards.")
                print("\nPlease check your wallet registration and restart the miner.")
                print("="*70 + "\n")
                sys.exit(1)

            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - {e.response.status_code}: {error_detail}")

            # Check if this is NOT the "Solution already exists" error
            # Save to CSV since this is a definitive rejection (not a network error)
            if not already_exists:
                # Append solution to solutions.csv
                if append_solution_to_csv(address, challenge['challenge_id'], nonce):
                    with self.failed_solutions_lock:
                        self.failed_solutions_count.value += 1
                else:
                    self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Failed to write solution to file")

            return (False, True, already_exists)
        except Exception as e:
            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution submission error for challenge {challenge['challenge_id']} - {e}")
            # Network error - return False and let retry logic handle CSV writing
            return (False, False, False)

    def mine_challenge_native(self, challenge, rom, max_time=3600, mining_address=None):
        start_time = time.time()
        attempts = 0
        last_status_update = start_time

        self.update_status(current_challenge=challenge['challenge_id'], attempts=0)

        preimage_static = self.build_preimage_static_part(challenge, mining_address)
        difficulty_value = int(challenge["difficulty"][:8], 16)

        BATCH_SIZE = 10000  # Process 10k hashes per batch!

        while time.time() - start_time < max_time:
            # Generate batch of nonces
            nonces = [self.get_fast_nonce() for _ in range(BATCH_SIZE)]
            preimages = [nonce + preimage_static for nonce in nonces]

            hashes = rom.hash_batch(preimages)
            attempts += BATCH_SIZE

            # Check all results
            for i, hash_hex in enumerate(hashes):
                hash_value = int(hash_hex[:8], 16)
                if (hash_value | difficulty_value) == difficulty_value:
                    elapsed = time.time() - start_time
                    hash_rate = attempts / elapsed if elapsed > 0 else 0
                    self.update_status(hash_rate=hash_rate)
                    return nonces[i]

            # Update status every 5 seconds
            current_time = time.time()
            if current_time - last_status_update >= 5.0:
                elapsed = current_time - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                self.update_status(attempts=attempts, hash_rate=hash_rate)
                last_status_update = current_time

        return None

    def update_status(self, **kwargs):
        current = dict(self.status_dict[self.worker_id])
        current.update(kwargs)
        current['last_update'] = time.time()
        self.status_dict[self.worker_id] = current

    def run(self):
        """Main worker loop"""
        self.update_status(current_challenge='Initializing...')
        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting mining worker...")

        self.update_status(current_challenge='Ready')
        rom_cache = {}

        while True:
            try:
                # If we're retrying a submission, use the stored challenge data
                if self.current_nonce is not None and self.current_challenge_data is not None:
                    # In retry mode - use stored challenge
                    challenge = self.current_challenge_data
                    challenge_id = challenge["challenge_id"]
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Retrying submission for challenge {challenge_id} (attempt {self.submission_retry_count + 1}/3)")
                else:
                    # Not in retry mode - fetch new challenges
                    # Get current challenge from API and register it
                    api_challenge = get_current_challenge(self.api_base)
                    if api_challenge:
                        is_new = self.challenge_tracker.register_challenge(api_challenge)
                        if is_new:
                            self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Discovered new challenge {api_challenge['challenge_id']}")

                    # Find an unsolved challenge for this wallet
                    challenge = self.challenge_tracker.get_unsolved_challenge(self.address)

                    if not challenge:
                        # No more challenges available for this wallet - exit worker
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): All challenges completed, exiting worker")
                        self.update_status(current_challenge='All completed', attempts=0, hash_rate=0)
                        return

                    challenge_id = challenge["challenge_id"]

                    # Reset retry state when starting a new challenge
                    if self.current_challenge_id != challenge_id:
                        self.current_challenge_id = challenge_id
                        self.current_challenge_data = None
                        self.current_nonce = None
                        self.submission_retry_count = 0

                # Check deadline
                deadline = datetime.fromisoformat(challenge["latest_submission"].replace('Z', '+00:00'))
                time_left = (deadline - datetime.now(timezone.utc)).total_seconds()

                if time_left <= 0:
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Challenge {challenge_id} expired")
                    self.update_status(current_challenge='Expired')
                    rom_cache.clear()
                    time.sleep(5)
                    continue

                # Get or build ROM for this challenge
                no_pre_mine = challenge["no_pre_mine"]
                if no_pre_mine not in rom_cache:
                    self.update_status(current_challenge=f'Building ROM')
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Building ROM for challenge {challenge_id}")
                    # Use TwoStep for speed (matches WASM parameters)
                    rom_cache[no_pre_mine] = ashmaize_py.build_rom_twostep(
                        key=no_pre_mine,
                        size=1073741824,
                        pre_size=16777216,
                        mixing_numbers=4
                    )

                rom = rom_cache[no_pre_mine]

                # Determine if this challenge will be mined for developer
                mining_for_developer = False
                if self.donation_enabled and random.random() < DONATION_RATE:
                    # Check if this dev address has already solved this challenge
                    if not self.challenge_tracker.is_dev_solved(challenge_id, self.dev_address):
                        mining_for_developer = True
                        mining_address = self.dev_address
                        dev_short_addr = self.dev_address[:20] + "..."
                        self.update_status(address='developer (thank you!)')
                        self.logger.info(f"Worker {self.worker_id} ({dev_short_addr}): Mining challenge {challenge_id} for DEVELOPER (donation)")
                    else:
                        # Dev address already solved this challenge, mine for user instead
                        mining_address = None
                        self.update_status(address=self.address)
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Dev address already solved {challenge_id}, mining for user instead")
                else:
                    mining_address = None
                    self.update_status(address=self.address)

                if not mining_for_developer:
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting work on challenge {challenge_id} (time left: {time_left/3600:.1f}h)")

                # Mine the challenge (or reuse nonce if retrying)
                if self.current_nonce is None:
                    # Use 99% of remaining time, reserving 1% for submission overhead
                    max_mine_time = time_left * 0.99
                    nonce = self.mine_challenge_native(challenge, rom, max_time=max_mine_time, mining_address=mining_address)
                    if nonce:
                        # Store both nonce and challenge data for retry
                        self.current_nonce = nonce
                        self.current_challenge_data = challenge
                else:
                    # Retrying with previously found nonce
                    nonce = self.current_nonce

                if nonce:
                    if mining_for_developer:
                        self.logger.info(f"Worker {self.worker_id} ({dev_short_addr}): Found solution for challenge {challenge_id} (DEVELOPER DONATION), submitting...")
                    else:
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Found solution for challenge {challenge_id}, submitting...")
                    self.update_status(current_challenge='Submitting solution...')
                    success, should_mark_solved, already_exists = self.submit_solution(challenge, nonce, mining_address=mining_address)

                    # Special handling: if mining for dev and solution already exists, wait for next challenge
                    if mining_for_developer and already_exists:
                        self.logger.info(f"Worker {self.worker_id} ({dev_short_addr}): Dev address already solved this challenge, marking as complete and waiting for next challenge...")

                        # Mark dev address as having solved this challenge globally
                        self.challenge_tracker.mark_dev_solved(challenge_id, self.dev_address)
                        # Mark this challenge as solved for this worker so we don't try it again
                        self.challenge_tracker.mark_solved(challenge_id, self.address)

                        self.update_status(current_challenge='Waiting for next challenge')
                        self.current_nonce = None
                        self.current_challenge_data = None
                        self.submission_retry_count = 0
                        self.update_status(address=self.address)
                        rom_cache.clear()

                        # Wait for a new challenge to appear
                        while True:
                            time.sleep(30)
                            api_challenge = get_current_challenge(self.api_base)
                            if api_challenge and api_challenge['challenge_id'] != challenge_id:
                                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): New challenge detected, resuming mining")
                                self.challenge_tracker.register_challenge(api_challenge)
                                break
                        continue

                    if success:
                        # Mark as solved for user wallet
                        self.challenge_tracker.mark_solved(challenge_id, self.address)
                        # If mining for dev, also mark dev address as having solved it
                        if mining_for_developer:
                            self.challenge_tracker.mark_dev_solved(challenge_id, self.dev_address)
                            # Report the developer solution to the server
                            self.report_donation(mining_address)
                        self.update_status(current_challenge='Solution accepted!')
                        self.current_nonce = None
                        self.current_challenge_data = None
                        self.submission_retry_count = 0
                        rom_cache.clear()
                        time.sleep(5)
                    elif should_mark_solved:
                        self.challenge_tracker.mark_solved(challenge_id, self.address)
                        self.update_status(current_challenge='Solution rejected - moving on')
                        self.current_nonce = None
                        self.current_challenge_data = None
                        self.submission_retry_count = 0
                        rom_cache.clear()
                        time.sleep(5)
                    else:
                        # Network error - check retry count
                        self.submission_retry_count += 1
                        if self.submission_retry_count >= 2:
                            # Max retries (2) reached, save to CSV and move on
                            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Max retries (2) reached for challenge {challenge_id}, saving to solutions.csv and moving on")
                            submission_address = mining_address if mining_address else self.address
                            if append_solution_to_csv(submission_address, challenge_id, nonce):
                                with self.failed_solutions_lock:
                                    self.failed_solutions_count.value += 1
                            else:
                                self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Failed to save solution to CSV")

                            self.challenge_tracker.mark_solved(challenge_id, self.address)
                            self.update_status(current_challenge='Saved to CSV, moving on')
                            self.current_nonce = None
                            self.current_challenge_data = None
                            self.submission_retry_count = 0
                            rom_cache.clear()
                            time.sleep(5)
                        else:
                            # Retry again (will retry on next loop iteration)
                            self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Submission failed, will retry (attempt {self.submission_retry_count + 1}/3)")
                            self.update_status(current_challenge=f'Submission error, retrying...')
                            time.sleep(15)

                    if mining_for_developer:
                        self.update_status(address=self.address)
                else:
                    # No solution found - DON'T mark as solved (that inflates completion count)
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): No solution found for challenge {challenge_id} in mining session")
                    self.update_status(current_challenge='No solution, checking next...')
                    self.current_nonce = None
                    self.current_challenge_data = None
                    self.submission_retry_count = 0
                    rom_cache.clear()

                    if mining_for_developer:
                        self.update_status(address=self.address)

                    time.sleep(5)

            except KeyboardInterrupt:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Received stop signal")
                break
            except Exception as e:
                self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Error - {e}")
                self.update_status(current_challenge=f'Error: {str(e)[:30]}')
                time.sleep(60)
