"""
Midnight Scavenger Mine Bot - Multi-Wallet Production Version
Supports multiple concurrent wallets mining simultaneously

Prerequisites:
1. pip install wasmtime requests pycardano
2. Download ashmaize_web_bg.wasm from Midnight website

Usage:
    python midnight_miner.py                    # Single wallet (legacy mode)
    python midnight_miner.py --workers 5        # 5 wallets mining concurrently
    python midnight_miner.py --workers 10 --wallets-file my_wallets.json
"""

import requests
import time
from datetime import datetime, timezone
import secrets
import json
import os
import sys
import threading
import fcntl
import logging
from multiprocessing import Process, Queue, Manager
from urllib.parse import quote
from wasmtime import Store, Module, Instance, Func, FuncType, ValType
from pycardano import PaymentSigningKey, PaymentVerificationKey, Address, Network
import cbor2


# Configure logging
def setup_logging():
    """Setup file and console logging"""
    log_format = '%(asctime)s - %(levelname)s - [%(processName)s] - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Create logger
    logger = logging.getLogger('midnight_miner')
    logger.setLevel(logging.INFO)

    # Check if handlers already exist (to avoid duplicates in forked processes)
    if logger.handlers:
        return logger

    # File handler
    file_handler = logging.FileHandler('miner.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Console handler (only warnings and errors)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


class ChallengeTracker:
    """Manages challenge tracking and completion status with cross-process file locking"""

    def __init__(self, challenges_file="challenges.json"):
        self.challenges_file = challenges_file
        # Ensure file exists
        if not os.path.exists(self.challenges_file):
            with open(self.challenges_file, 'w') as f:
                json.dump({}, f)

    def _locked_operation(self, modify_func):
        """
        Perform atomic read-modify-write with file locking.

        Args:
            modify_func: Function that takes challenges dict and returns (modified_dict, result)

        Returns:
            The result from modify_func
        """
        with open(self.challenges_file, 'r+') as f:
            # Get exclusive lock - blocks until available
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                # Read current state
                f.seek(0)
                content = f.read()
                challenges = json.loads(content) if content else {}

                # Perform modification
                modified_challenges, result = modify_func(challenges)

                # Write back atomically
                f.seek(0)
                f.truncate()
                json.dump(modified_challenges, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

                return result
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def register_challenge(self, challenge):
        """Register a new challenge with all data needed to solve it"""
        def modify(challenges):
            challenge_id = challenge['challenge_id']
            if challenge_id not in challenges:
                challenges[challenge_id] = {
                    'challenge_id': challenge['challenge_id'],
                    'day': challenge.get('day'),
                    'challenge_number': challenge.get('challenge_number'),
                    'difficulty': challenge['difficulty'],
                    'no_pre_mine': challenge['no_pre_mine'],
                    'no_pre_mine_hour': challenge['no_pre_mine_hour'],
                    'latest_submission': challenge['latest_submission'],
                    'discovered_at': datetime.now(timezone.utc).isoformat(),
                    'solved_by': []
                }
                return (challenges, True)
            return (challenges, False)

        return self._locked_operation(modify)

    def mark_solved(self, challenge_id, wallet_address):
        """Mark a challenge as solved by a wallet"""
        def modify(challenges):
            if challenge_id in challenges:
                if wallet_address not in challenges[challenge_id]['solved_by']:
                    challenges[challenge_id]['solved_by'].append(wallet_address)
                    return (challenges, True)
            return (challenges, False)

        return self._locked_operation(modify)

    def is_solved_by(self, challenge_id, wallet_address):
        """Check if wallet has already solved this challenge"""
        def check(challenges):
            if challenge_id in challenges:
                result = wallet_address in challenges[challenge_id]['solved_by']
            else:
                result = False
            return (challenges, result)

        return self._locked_operation(check)

    def get_unsolved_challenge(self, wallet_address):
        """Get an unsolved challenge for this wallet (prioritize newest)"""
        def find_challenge(challenges):
            now = datetime.now(timezone.utc)
            candidates = []

            for challenge_id, data in challenges.items():
                # Check if not solved by this wallet
                if wallet_address not in data['solved_by']:
                    # Check if deadline hasn't passed
                    deadline = datetime.fromisoformat(data['latest_submission'].replace('Z', '+00:00'))
                    time_left = (deadline - now).total_seconds()
                    if time_left > 0:
                        candidates.append({
                            'challenge': data,
                            'time_left': time_left
                        })

            if not candidates:
                result = None
            else:
                # Sort by newest first (most time remaining)
                candidates.sort(key=lambda x: x['time_left'], reverse=True)
                result = candidates[0]['challenge']

            return (challenges, result)

        return self._locked_operation(find_challenge)

    def get_challenge_stats(self):
        """Get overall challenge statistics"""
        def calculate_stats(challenges):
            total_challenges = len(challenges)
            solved_count = sum(1 for c in challenges.values() if len(c['solved_by']) > 0)
            stats = {
                'total': total_challenges,
                'solved': solved_count,
                'unsolved': total_challenges - solved_count
            }
            return (challenges, stats)

        return self._locked_operation(calculate_stats)


class WalletManager:
    """Manages Cardano wallet generation, storage, and signing"""

    def __init__(self, wallet_file="wallets.json"):
        self.wallet_file = wallet_file
        self.wallets = []

    def generate_wallet(self, wallet_id):
        """Generate a new Cardano wallet"""
        signing_key = PaymentSigningKey.generate()
        verification_key = PaymentVerificationKey.from_signing_key(signing_key)
        address = Address(verification_key.hash(), network=Network.MAINNET)
        pubkey = bytes(verification_key.to_primitive()).hex()

        return {
            'id': wallet_id,
            'address': str(address),
            'pubkey': pubkey,
            'signing_key': signing_key.to_primitive().hex(),
            'signature': None,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

    def sign_terms(self, wallet_data, api_base):
        """Sign T&C for a wallet"""
        try:
            response = requests.get(f"{api_base}/TandC")
            message = response.json()["message"]
        except:
            message = "I agree to abide by the terms and conditions as described in version 1-0 of the Midnight scavenger mining process: 281ba5f69f4b943e3fb8a20390878a232787a04e4be22177f2472b63df01c200"

        # Reconstruct keys
        signing_key_bytes = bytes.fromhex(wallet_data['signing_key'])
        signing_key = PaymentSigningKey.from_primitive(signing_key_bytes)
        address = Address.from_primitive(wallet_data['address'])

        address_bytes = bytes(address.to_primitive())

        # CIP-30 signature
        protected = {1: -8, "address": address_bytes}
        protected_encoded = cbor2.dumps(protected)
        unprotected = {"hashed": False}
        payload = message.encode('utf-8')

        sig_structure = ["Signature1", protected_encoded, b'', payload]
        to_sign = cbor2.dumps(sig_structure)
        signature_bytes = signing_key.sign(to_sign)

        cose_sign1 = [protected_encoded, unprotected, payload, signature_bytes]
        wallet_data['signature'] = cbor2.dumps(cose_sign1).hex()

    def load_or_create_wallets(self, num_wallets, api_base):
        """Load existing wallets or create new ones"""
        if os.path.exists(self.wallet_file):
            print(f"✓ Loading wallets from {self.wallet_file}")
            with open(self.wallet_file, 'r') as f:
                self.wallets = json.load(f)

            existing_count = len(self.wallets)
            if existing_count >= num_wallets:
                print(f"✓ Using {num_wallets} existing wallets")
                self.wallets = self.wallets[:num_wallets]
                return self.wallets
            else:
                print(f"✓ Loaded {existing_count} existing wallets")
                print(f"✓ Creating {num_wallets - existing_count} additional wallets...")
                start_id = existing_count
        else:
            print(f"✓ Creating {num_wallets} new wallets...")
            start_id = 0

        # Generate additional wallets
        for i in range(start_id, num_wallets):
            wallet = self.generate_wallet(i)
            self.sign_terms(wallet, api_base)
            self.wallets.append(wallet)
            print(f"  Wallet {i+1}/{num_wallets}: {wallet['address'][:40]}...")

        # Save all wallets
        with open(self.wallet_file, 'w') as f:
            json.dump(self.wallets, f, indent=2)

        print(f"✓ Saved {num_wallets} wallets to {self.wallet_file}")
        return self.wallets


class AshmaizeWASM:
    """Wrapper for Ashmaize WebAssembly module using Wasmtime"""

    def __init__(self, wasm_path="ashmaize_web_bg.wasm"):
        self.store = Store()

        with open(wasm_path, 'rb') as f:
            wasm_bytes = f.read()

        module = Module(self.store.engine, wasm_bytes)

        self.externref_table = {}
        self.next_externref_id = 1

        def js_error(addr, len): pass
        def js_new_error():
            ref_id = self.next_externref_id
            self.next_externref_id += 1
            self.externref_table[ref_id] = {"type": "error"}
            return ref_id
        def js_stack(addr, err_ref): pass
        def js_throw(addr, len): raise RuntimeError(f"WASM error at address {addr}")
        def js_number_new(val):
            ref_id = self.next_externref_id
            self.next_externref_id += 1
            self.externref_table[ref_id] = val
            return ref_id
        def wbindgen_init_externref_table(): pass

        number_new_type = FuncType([ValType.f64()], [ValType.externref()])
        new_error_type = FuncType([], [ValType.externref()])
        stack_type = FuncType([ValType.i32(), ValType.externref()], [])
        error_type = FuncType([ValType.i32(), ValType.i32()], [])
        throw_type = FuncType([ValType.i32(), ValType.i32()], [])
        init_externref_type = FuncType([], [])

        import_list = [
            Func(self.store, number_new_type, js_number_new),
            Func(self.store, new_error_type, js_new_error),
            Func(self.store, stack_type, js_stack),
            Func(self.store, error_type, js_error),
            Func(self.store, throw_type, js_throw),
            Func(self.store, init_externref_type, wbindgen_init_externref_table),
        ]

        self.instance = Instance(self.store, module, import_list)
        self.memory = self.instance.exports(self.store)["memory"]

        start_func = self.instance.exports(self.store).get("__wbindgen_start")
        if start_func:
            start_func(self.store)

    def get_memory_view(self):
        return self.memory.data_ptr(self.store)

    def build_rom(self, key, rom_size=1073741824, pre_size=16777216, mixing_numbers=4):
        key_bytes = key.encode('utf-8')
        exports = self.instance.exports(self.store)
        malloc = exports["__wbindgen_malloc"]

        key_ptr = malloc(self.store, len(key_bytes), 1)
        memory_view = self.get_memory_view()
        for i, byte in enumerate(key_bytes):
            memory_view[key_ptr + i] = byte

        builder_ptr = exports["rombuilder_new"](self.store)
        exports["rombuilder_key"](self.store, builder_ptr, key_ptr, len(key_bytes))
        exports["rombuilder_size"](self.store, builder_ptr, rom_size)
        exports["rombuilder_gen_two_steps"](self.store, builder_ptr, pre_size, mixing_numbers)

        result = exports["rombuilder_build"](self.store, builder_ptr)

        if isinstance(result, (list, tuple)):
            if len(result) > 1 and result[1] != 0:
                raise RuntimeError(f"ROM build failed with error: {result}")
            return result[0]
        return result

    def hash_with_rom(self, rom_ptr, preimage, nb_loops=8, nb_instrs=256):
        preimage_bytes = preimage.encode('utf-8')
        exports = self.instance.exports(self.store)
        malloc = exports["__wbindgen_malloc"]
        free = exports["__wbindgen_free"]

        preimage_ptr = malloc(self.store, len(preimage_bytes), 1)
        memory_view = self.get_memory_view()
        for i, byte in enumerate(preimage_bytes):
            memory_view[preimage_ptr + i] = byte

        result = exports["rom_hash"](
            self.store, rom_ptr, preimage_ptr, len(preimage_bytes), nb_loops, nb_instrs
        )

        if not isinstance(result, (list, tuple)) or len(result) < 2:
            raise RuntimeError(f"Unexpected rom_hash result format: {result}")

        hash_ptr = result[0]
        hash_len = result[1]

        if hash_len > 1024 or hash_len <= 0:
            raise RuntimeError(f"Invalid hash length: {hash_len}")

        memory_view = self.get_memory_view()
        hash_bytes = bytes([memory_view[hash_ptr + i] for i in range(hash_len)])

        try:
            free(self.store, hash_ptr, hash_len, 1)
        except:
            pass

        return hash_bytes.hex()


class MinerWorker:
    """Individual mining worker for one wallet"""

    def __init__(self, wallet_data, worker_id, status_dict, challenge_tracker, api_base="https://scavenger.prod.gd.midnighttge.io/"):
        self.wallet_data = wallet_data
        self.worker_id = worker_id
        self.address = wallet_data['address']
        self.signature = wallet_data['signature']
        self.pubkey = wallet_data['pubkey']
        self.api_base = api_base
        self.status_dict = status_dict
        self.challenge_tracker = challenge_tracker
        self.logger = logging.getLogger('midnight_miner')

        # Short address for logging
        self.short_addr = self.address[:20] + "..."

        # Initialize status
        self.status_dict[worker_id] = {
            'address': self.address,
            'current_challenge': 'Starting',
            'attempts': 0,
            'hash_rate': 0,
            'completed_challenges': 0,
            'night_allocation': 0.0,
            'last_update': time.time()
        }

    def register_wallet(self):
        """Register wallet with API"""
        url = f"{self.api_base}/register/{self.address}/{self.signature}/{self.pubkey}"
        try:
            response = requests.post(url, json={})
            response.raise_for_status()
            self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Wallet registered successfully")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                error_msg = e.response.json().get('message', '')
                if 'already' in error_msg.lower():
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Wallet already registered")
                    return True
            self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Registration failed - {e}")
            return False
        except Exception as e:
            self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Registration error - {e}")
            return False

    def get_current_challenge(self):
        """Fetch current challenge"""
        try:
            response = requests.get(f"{self.api_base}/challenge")
            response.raise_for_status()
            data = response.json()
            if data.get("code") == "active":
                return data["challenge"]
        except:
            pass
        return None

    def get_statistics(self):
        """Get statistics for this wallet"""
        try:
            response = requests.get(f"{self.api_base}/statistics/{self.address}")
            response.raise_for_status()
            return response.json()
        except:
            return None

    def update_statistics(self):
        """Update status dict with current statistics"""
        stats = self.get_statistics()
        if stats:
            local = stats.get('local', {})
            self.update_status(
                completed_challenges=local.get('crypto_receipts', 0),
                night_allocation=local.get('night_allocation', 0)/1000000.0
            )

    def build_preimage(self, nonce, challenge):
        return (
            nonce + self.address + challenge["challenge_id"] +
            challenge["difficulty"] + challenge["no_pre_mine"] +
            challenge["latest_submission"] + challenge["no_pre_mine_hour"]
        )

    def check_difficulty(self, hash_hex, difficulty_hex):
        hash_value = int(hash_hex[:8], 16)
        difficulty_value = int(difficulty_hex[:8], 16)
        return (hash_value | difficulty_value) == difficulty_value

    def submit_solution(self, challenge, nonce):
        """Submit solution to API"""
        addr_encoded = quote(self.address, safe='')
        challenge_encoded = quote(challenge['challenge_id'], safe='')
        nonce_encoded = quote(nonce, safe='')
        url = f"{self.api_base.rstrip('/')}/solution/{addr_encoded}/{challenge_encoded}/{nonce_encoded}"

        try:
            response = requests.post(url, json={})
            response.raise_for_status()
            data = response.json()
            success = data.get("crypto_receipt") is not None
            if success:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Solution ACCEPTED for challenge {challenge['challenge_id']}")
            else:
                self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - No receipt")
            return success
        except Exception as e:
            self.logger.warning(f"Worker {self.worker_id} ({self.short_addr}): Solution REJECTED for challenge {challenge['challenge_id']} - {e}")
            return False

    def mine_challenge(self, challenge, ashmaize, rom_ptr, max_time=3600):
        """Mine a challenge"""
        start_time = time.time()
        attempts = 0

        self.update_status(current_challenge=challenge['challenge_id'], attempts=0)

        while time.time() - start_time < max_time:
            nonce = secrets.token_hex(8)
            preimage = self.build_preimage(nonce, challenge)
            hash_hex = ashmaize.hash_with_rom(rom_ptr, preimage)
            attempts += 1

            # Update status every 1000 attempts
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                self.update_status(attempts=attempts, hash_rate=hash_rate)

            if self.check_difficulty(hash_hex, challenge["difficulty"]):
                elapsed = time.time() - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                self.update_status(hash_rate=hash_rate)
                return nonce

        return None

    def update_status(self, **kwargs):
        """Update status dict - critical to update the whole dict at once for multiprocessing"""
        current = dict(self.status_dict[self.worker_id])
        current.update(kwargs)
        current['last_update'] = time.time()
        self.status_dict[self.worker_id] = current

    def run(self):
        """Main worker loop"""
        self.update_status(current_challenge='Initializing...')
        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting mining worker")

        if not self.register_wallet():
            self.update_status(current_challenge='Registration failed')
            return

        self.update_status(current_challenge='Loading WASM...')
        ashmaize = AshmaizeWASM()
        rom_cache = {}  # Cache ROMs by no_pre_mine key
        last_stats_update = 0

        while True:
            try:
                # Get current challenge from API and register it
                api_challenge = self.get_current_challenge()
                if api_challenge:
                    is_new = self.challenge_tracker.register_challenge(api_challenge)
                    if is_new:
                        self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Discovered new challenge {api_challenge['challenge_id']}")

                # Find an unsolved challenge for this wallet
                challenge = self.challenge_tracker.get_unsolved_challenge(self.address)

                if not challenge:
                    self.update_status(current_challenge='Waiting...', attempts=0, hash_rate=0)
                    time.sleep(60)
                    continue

                challenge_id = challenge["challenge_id"]

                # Check deadline
                deadline = datetime.fromisoformat(challenge["latest_submission"].replace('Z', '+00:00'))
                time_left = (deadline - datetime.now(timezone.utc)).total_seconds()

                if time_left <= 0:
                    # Mark as expired (skip it)
                    self.challenge_tracker.mark_solved(challenge_id, self.address)
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Challenge {challenge_id} expired")
                    self.update_status(current_challenge='Expired')
                    time.sleep(5)
                    continue

                # Get or build ROM for this challenge
                no_pre_mine = challenge["no_pre_mine"]
                if no_pre_mine not in rom_cache:
                    self.update_status(current_challenge=f'Building ROM')
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Building ROM for challenge {challenge_id}")
                    rom_cache[no_pre_mine] = ashmaize.build_rom(no_pre_mine)

                rom_ptr = rom_cache[no_pre_mine]

                # Update statistics every 10 minutes
                if time.time() - last_stats_update > 600:
                    self.update_statistics()
                    last_stats_update = time.time()

                # Log start of mining
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Starting work on challenge {challenge_id} (time left: {time_left/3600:.1f}h)")

                # Mine the challenge
                max_mine_time = min(time_left * 0.8, 3600)
                nonce = self.mine_challenge(challenge, ashmaize, rom_ptr, max_time=max_mine_time)

                if nonce:
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Found solution for challenge {challenge_id}, submitting...")
                    self.update_status(current_challenge='Submitting solution...')
                    if self.submit_solution(challenge, nonce):
                        # Mark as solved
                        self.challenge_tracker.mark_solved(challenge_id, self.address)
                        self.update_statistics()
                        self.update_status(current_challenge='Solution accepted!')
                        time.sleep(5)
                    else:
                        self.update_status(current_challenge='Solution rejected')
                        time.sleep(10)
                else:
                    # Failed to find solution in time, mark as attempted
                    self.challenge_tracker.mark_solved(challenge_id, self.address)
                    self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): No solution found for challenge {challenge_id} within time limit")
                    self.update_status(current_challenge='No solution found')
                    time.sleep(5)

            except KeyboardInterrupt:
                self.logger.info(f"Worker {self.worker_id} ({self.short_addr}): Received stop signal")
                break
            except Exception as e:
                self.logger.error(f"Worker {self.worker_id} ({self.short_addr}): Error - {e}")
                self.update_status(current_challenge=f'Error: {str(e)[:30]}')
                time.sleep(60)


def worker_process(wallet_data, worker_id, status_dict, challenges_file):
    """Process entry point for worker"""
    try:
        # Setup logging for this worker process
        setup_logging()

        # Each process needs its own ChallengeTracker instance
        challenge_tracker = ChallengeTracker(challenges_file)
        worker = MinerWorker(wallet_data, worker_id, status_dict, challenge_tracker)
        worker.run()
    except Exception as e:
        logger = logging.getLogger('midnight_miner')
        logger.error(f"Worker {worker_id}: Fatal error - {e}")
        import traceback
        traceback.print_exc()

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def color_text(text, color):
    return f"{color}{text}{RESET}"

def display_dashboard(status_dict, num_workers, stats_update_interval=600):
    """Display live dashboard of all miners with proper alignment and simple coloring"""

    last_stats_update = 0

    while True:
        try:
            time.sleep(5)

            current_time = time.time()
            if current_time - last_stats_update > stats_update_interval:
                last_stats_update = current_time

            os.system('clear' if os.name == 'posix' else 'cls')

            print("="*110)
            print(f"{BOLD}{CYAN}{'MIDNIGHT MULTI-WALLET MINER DASHBOARD':^110}{RESET}")
            print("="*110)
            print(f"{BOLD}Active Workers: {num_workers} | Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
            print("="*110)
            print()

            # Table header
            header = f"{'ID':<4} {'Address':<44} {'Challenge':<20} {'Attempts':<10} {'H/s':<8} {'Completed':<10} {'NIGHT':<10}"
            print(color_text(header, CYAN))
            print("-"*110)

            total_hashrate = 0
            total_completed = 0
            total_night = 0

            for worker_id in range(num_workers):
                if worker_id not in status_dict:
                    row = f"{worker_id:<4} {'Starting...':<44} {'N/A':<20} {0:<10} {0:<8} {0:<10} {0:<10}"
                    print(row)
                    continue

                status = status_dict[worker_id]
                address = status.get('address', 'N/A')
                if len(address) > 42:
                    address = address[:39] + "..."

                challenge = status.get('current_challenge')
                if challenge is None:
                    challenge_display = "Waiting"
                elif len(str(challenge)) > 18:
                    challenge_display = str(challenge)[:15] + "..."
                else:
                    challenge_display = str(challenge)

                # Pad first, then color
                challenge_display_padded = f"{challenge_display:<20}"
                if "**" in challenge_display:
                    challenge_display_padded = color_text(challenge_display_padded, GREEN)

                attempts = status.get('attempts', 0) or 0
                hash_rate = status.get('hash_rate', 0) or 0
                completed = status.get('completed_challenges', 0) or 0
                night = color_text(str(round(status.get('night_allocation', 0) or 0, 2)), GREEN)

                total_hashrate += hash_rate
                total_completed += completed
                total_night += status.get('night_allocation', 0) or 0

                print(f"{worker_id:<4} {address:<44} {challenge_display_padded} {attempts:<10,} {hash_rate:<8.0f} {completed:<10} {night:<10}")

            # Totals row
            totals_row = f"{'TOTAL':<4} {'':<44} {'':<20} {'':<10} {total_hashrate:<8.0f} {total_completed:<10} {round(total_night, 2):<10}"
            print(color_text("-"*110, CYAN))
            print(color_text(totals_row, CYAN))
            print("="*110)
            print("\nPress Ctrl+C to stop all miners")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)


def main():
    """Main entry point"""
    # Setup logging first
    logger = setup_logging()

    print("="*70)
    print("MIDNIGHT MULTI-WALLET SCAVENGER MINE BOT")
    print("="*70)
    print()

    logger.info("="*70)
    logger.info("Midnight Miner starting up")
    logger.info("="*70)

    # Parse arguments
    num_workers = 1
    wallets_file = "wallets.json"
    challenges_file = "challenges.json"

    for i, arg in enumerate(sys.argv):
        if arg == '--workers' and i + 1 < len(sys.argv):
            num_workers = int(sys.argv[i + 1])
        elif arg == '--wallets-file' and i + 1 < len(sys.argv):
            wallets_file = sys.argv[i + 1]
        elif arg == '--challenges-file' and i + 1 < len(sys.argv):
            challenges_file = sys.argv[i + 1]

    if num_workers < 1:
        print("Error: --workers must be at least 1")
        return 1

    print(f"Configuration:")
    print(f"  Workers: {num_workers}")
    print(f"  Wallets file: {wallets_file}")
    print(f"  Challenges file: {challenges_file}")
    print()

    logger.info(f"Configuration: workers={num_workers}, wallets_file={wallets_file}, challenges_file={challenges_file}")

    # Check WASM file
    if not os.path.exists("ashmaize_web_bg.wasm"):
        print("❌ Error: ashmaize_web_bg.wasm not found")
        logger.error("WASM file not found: ashmaize_web_bg.wasm")
        return 1

    # Setup wallets
    wallet_manager = WalletManager(wallets_file)
    api_base = "https://scavenger.prod.gd.midnighttge.io/"
    wallets = wallet_manager.load_or_create_wallets(num_workers, api_base)
    logger.info(f"Loaded/created {num_workers} wallets")

    print()
    print("="*70)
    print("STARTING MINERS")
    print("="*70)
    print()

    # Create shared status dictionary
    manager = Manager()
    status_dict = manager.dict()

    # Start worker processes
    processes = []
    for i, wallet in enumerate(wallets):
        p = Process(target=worker_process, args=(wallet, i, status_dict, challenges_file))
        p.start()
        processes.append(p)
        logger.info(f"Started worker process {i} for wallet {wallet['address'][:20]}...")
        time.sleep(1)  # Stagger startup

    print("\n" + "="*70)
    print("All workers started. Starting dashboard...")
    print("="*70)
    logger.info(f"All {num_workers} workers started successfully")
    time.sleep(3)

    # Start dashboard in main thread
    try:
        display_dashboard(status_dict, num_workers)
    except KeyboardInterrupt:
        print("\n\nStopping all miners...")
        logger.info("Received shutdown signal, stopping all workers...")

    # Cleanup
    for p in processes:
        p.terminate()

    for p in processes:
        p.join(timeout=5)

    print("\n✓ All miners stopped")
    logger.info("All workers stopped")

    # Show final challenge statistics
    tracker = ChallengeTracker(challenges_file)
    stats = tracker.get_challenge_stats()
    print(f"\nChallenge Statistics:")
    print(f"  Total challenges discovered: {stats['total']}")
    print(f"  Challenges with solutions: {stats['solved']}")
    print(f"  Unsolved challenges: {stats['unsolved']}")

    logger.info(f"Final statistics: {stats['total']} challenges, {stats['solved']} with solutions, {stats['unsolved']} unsolved")
    logger.info("Midnight Miner shutdown complete")

    return 0


if __name__ == "__main__":
    sys.exit(main())
