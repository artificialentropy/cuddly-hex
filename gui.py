# wallet_gui.py
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import requests


# --------------- Helpers ---------------

def safe_int(val, default=0):
    try:
        return int(val)
    except Exception:
        return default


def is_json_response(r: requests.Response) -> bool:
    ct = r.headers.get("content-type", "")
    return "application/json" in ct.lower()


class ApiClient:
    def __init__(self, base_url_getter, log_cb):
        self.base_url_getter = base_url_getter
        self.log = log_cb
        self.token = None
        self.user_id = None
        self.address = None

    def _req(self, method, path, data=None, timeout=8, auth=False):
        base = self.base_url_getter().rstrip("/")
        url = base + path
        headers = {}
        if auth and self.token:
            headers["X-Auth-Token"] = self.token
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, timeout=timeout)
            else:
                r = requests.post(url, json=data or {}, headers=headers, timeout=timeout)
            j = r.json() if is_json_response(r) else {"_raw": r.text, "_status": r.status_code}
            if not r.ok:
                # surface remote error body if present
                msg = j.get("error") if isinstance(j, dict) else str(j)
                raise RuntimeError(msg or f"HTTP {r.status_code}")
            return j
        except Exception as e:
            self.log(f"[HTTP ERROR] {method} {url} -> {e}")
            raise

    # -------- Auth --------
    def login(self, user_id):
        j = self._req("POST", "/auth/login", {"user_id": user_id})
        self.token = j.get("token")
        self.user_id = j.get("user_id")
        self.address = j.get("address")
        return j

    def me(self):
        return self._req("GET", "/u/me", auth=True)

    # -------- Chain & mempool --------
    def get_health(self):
        return self._req("GET", "/health")

    def get_blockchain_len(self):
        return self._req("GET", "/blockchain/length")

    def get_transactions(self):
        return self._req("GET", "/transactions")

    def mine(self):
        return self._req("GET", "/blockchain/mine")

    def get_known_addresses(self):
        return self._req("GET", "/known-addresses")

    # -------- Wallet / balances --------
    def get_balance(self, address, seed_param=None):
        path = f"/wallet/balance/{address}"
        if seed_param is not None and str(seed_param).strip() != "":
            path += f"?seed={seed_param}"
        return self._req("GET", path)

    # -------- Assets --------
    def register_asset(self, asset_id, owner, price, currency, transferable=True):
        payload = {
            "asset_id": asset_id,
            "owner": owner,
            "price": safe_int(price),
            "currency": currency,
            "transferable": bool(transferable),
        }
        return self._req("POST", "/asset/register", payload)

    def get_asset(self, asset_id):
        return self._req("GET", f"/asset/{asset_id}")

    # -------- Transactions (auto /u or /wallet) --------
    def _tx_endpoint(self) -> tuple[str, bool]:
        """Return (path, auth_required). If logged in, prefer user-scoped endpoint."""
        if self.token:
            return ("/u/tx", True)
        return ("/wallet/transact", False)

    def send_coins(self, recipient, amount, currency="COIN", fee=0, metadata=None):
        path, auth = self._tx_endpoint()
        payload = {
            "action": "transfer",
            "recipient": recipient,
            "amount": safe_int(amount),
            "currency": currency,
            "fee": safe_int(fee, 0),
        }
        if metadata:
            payload["metadata"] = metadata
        return self._req("POST", path, payload, auth=auth)

    def list_asset(self, asset_id, price, currency="COIN", fee=0, metadata=None):
        path, auth = self._tx_endpoint()
        payload = {
            "action": "list",
            "asset_id": asset_id,
            "price": safe_int(price),
            "currency": currency,
            "fee": safe_int(fee, 0),
        }
        if metadata:
            payload["metadata"] = metadata
        return self._req("POST", path, payload, auth=auth)

    def purchase_asset(self, asset_id, fee=0, metadata=None):
        path, auth = self._tx_endpoint()
        payload = {
            "action": "purchase",
            "asset_id": asset_id,
            "fee": safe_int(fee, 0),
        }
        if metadata:
            payload["metadata"] = metadata
        return self._req("POST", path, payload, auth=auth)

    def transfer_asset(self, asset_id, recipient, fee=0, metadata=None):
        path, auth = self._tx_endpoint()
        payload = {
            "action": "transfer_asset",
            "asset_id": asset_id,
            "recipient": recipient,
            "fee": safe_int(fee, 0),
        }
        if metadata:
            payload["metadata"] = metadata
        return self._req("POST", path, payload, auth=auth)


# --------------- GUI ---------------

class WalletGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Blockchain Wallet Console")
        self.geometry("1000x740")
        self.minsize(920, 640)

        # state
        self.node_url_var = tk.StringVar(value="http://localhost:5000")
        self.active_addr_var = tk.StringVar(value="")
        self.currency_var = tk.StringVar(value="COIN")

        # api client
        self.api = ApiClient(self.get_base_url, self.log)

        self._build_layout()

    def get_base_url(self):
        return self.node_url_var.get().strip()

    # --- UI building ---
    def on_login(self):
        user_id = (self.user_id_var.get() or "").strip()
        if not user_id:
            messagebox.showwarning("Missing User ID", "Enter a user id to login.")
            return
        j = self.api.login(user_id)
        addr = j.get("address")
        self.active_addr_var.set(addr or "")
        tok = j.get("token", "")
        tok_disp = (tok[:8] + "…") if tok else "n/a"
        self.log(f"[Login] user_id={j.get('user_id')} address={addr} token={tok_disp}")
        # show /u/me
        me = self.api.me()
        self.show_json(me)

    def _build_layout(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="User ID:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.user_id_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.user_id_var, width=20).grid(row=1, column=1, sticky="we", padx=(5, 15), pady=(6, 0))
        ttk.Button(top, text="Login", command=self._async(self.on_login)).grid(row=1, column=2, padx=5, pady=(6, 0))

        ttk.Label(top, text="Node URL:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.node_url_var, width=35).grid(row=0, column=1, sticky="we", padx=(5, 15))

        ttk.Label(top, text="Active Wallet Address:").grid(row=0, column=2, sticky="w")
        ttk.Entry(top, textvariable=self.active_addr_var, width=20).grid(row=0, column=3, sticky="we", padx=(5, 15))

        ttk.Button(top, text="Health", command=self._async(self.on_health)).grid(row=0, column=4, padx=5)
        ttk.Button(top, text="Chain Height", command=self._async(self.on_chain_len)).grid(row=0, column=5, padx=5)
        ttk.Button(top, text="Mine Block", command=self._async(self.on_mine)).grid(row=0, column=6, padx=5)

        top.grid_columnconfigure(1, weight=1)
        top.grid_columnconfigure(3, weight=1)

        # Notebook (tabs)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        nb.add(self._tab_wallet(), text="Wallet")
        nb.add(self._tab_assets(), text="Assets")
        nb.add(self._tab_transactions(), text="Transactions")

        # Log console
        self.log_text = tk.Text(self, height=10, wrap="word", state="disabled", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=False, padx=10, pady=(0, 10))

    def _tab_wallet(self):
        frame = ttk.Frame(self, padding=10)

        # Balance section
        bal_box = ttk.LabelFrame(frame, text="Balance")
        bal_box.pack(fill="x", pady=5)

        ttk.Label(bal_box, text="Address:").grid(row=0, column=0, sticky="w")
        self.bal_addr_var = tk.StringVar()
        bal_addr_entry = ttk.Entry(bal_box, textvariable=self.bal_addr_var, width=34)
        bal_addr_entry.grid(row=0, column=1, sticky="we", padx=5)
        ttk.Label(bal_box, text="Seed?").grid(row=0, column=2)
        self.seed_var = tk.StringVar(value="0")
        ttk.Combobox(bal_box, textvariable=self.seed_var, values=("0", "1"), width=4, state="readonly").grid(row=0, column=3, padx=5)
        ttk.Button(bal_box, text="Get Balance", command=self._async(self.on_get_balance)).grid(row=0, column=4, padx=5)

        bal_box.grid_columnconfigure(1, weight=1)

        # Transfer coins
        tx_box = ttk.LabelFrame(frame, text="Send Coins")
        tx_box.pack(fill="x", pady=8)

        ttk.Label(tx_box, text="Recipient:").grid(row=0, column=0, sticky="w")
        self.tx_recipient_var = tk.StringVar()
        ttk.Entry(tx_box, textvariable=self.tx_recipient_var, width=30).grid(row=0, column=1, sticky="we", padx=5)

        ttk.Label(tx_box, text="Amount:").grid(row=0, column=2, sticky="w")
        self.tx_amount_var = tk.StringVar(value="1")
        ttk.Entry(tx_box, textvariable=self.tx_amount_var, width=10).grid(row=0, column=3, sticky="we", padx=5)

        ttk.Label(tx_box, text="Currency:").grid(row=0, column=4, sticky="w")
        ttk.Entry(tx_box, textvariable=self.currency_var, width=10).grid(row=0, column=5, sticky="we", padx=5)

        ttk.Label(tx_box, text="Fee:").grid(row=0, column=6, sticky="w")
        self.tx_fee_var = tk.StringVar(value="0")
        ttk.Entry(tx_box, textvariable=self.tx_fee_var, width=8).grid(row=0, column=7, sticky="we", padx=5)

        ttk.Button(tx_box, text="Send", command=self._async(self.on_send_coins)).grid(row=0, column=8, padx=5)

        tx_box.grid_columnconfigure(1, weight=1)

        return frame

    def _tab_assets(self):
        frame = ttk.Frame(self, padding=10)

        # Register asset
        reg = ttk.LabelFrame(frame, text="Register Asset")
        reg.pack(fill="x", pady=5)

        self.asset_id_var = tk.StringVar()
        self.asset_owner_var = tk.StringVar()
        self.asset_price_var = tk.StringVar(value="0")
        self.asset_currency_var = tk.StringVar(value="COIN")
        self.asset_transferable_var = tk.BooleanVar(value=True)

        ttk.Label(reg, text="Asset ID:").grid(row=0, column=0, sticky="w")
        ttk.Entry(reg, textvariable=self.asset_id_var, width=20).grid(row=0, column=1, sticky="we", padx=5)

        ttk.Label(reg, text="Owner (defaults to node wallet):").grid(row=0, column=2, sticky="w")
        ttk.Entry(reg, textvariable=self.asset_owner_var, width=22).grid(row=0, column=3, sticky="we", padx=5)

        ttk.Label(reg, text="Price:").grid(row=1, column=0, sticky="w")
        ttk.Entry(reg, textvariable=self.asset_price_var, width=10).grid(row=1, column=1, sticky="we", padx=5)

        ttk.Label(reg, text="Currency:").grid(row=1, column=2, sticky="w")
        ttk.Entry(reg, textvariable=self.asset_currency_var, width=10).grid(row=1, column=3, sticky="we", padx=5)

        ttk.Checkbutton(reg, text="Transferable", variable=self.asset_transferable_var).grid(row=1, column=4, padx=5)

        ttk.Button(reg, text="Register", command=self._async(self.on_register_asset)).grid(row=0, column=4, rowspan=2, padx=5)

        reg.grid_columnconfigure(1, weight=1)
        reg.grid_columnconfigure(3, weight=1)

        # Get asset
        getf = ttk.LabelFrame(frame, text="Get Asset")
        getf.pack(fill="x", pady=5)

        self.get_asset_id_var = tk.StringVar()
        ttk.Label(getf, text="Asset ID:").grid(row=0, column=0, sticky="w")
        ttk.Entry(getf, textvariable=self.get_asset_id_var, width=20).grid(row=0, column=1, sticky="we", padx=5)
        ttk.Button(getf, text="Fetch", command=self._async(self.on_get_asset)).grid(row=0, column=2, padx=5)

        # List / purchase / transfer asset
        act = ttk.LabelFrame(frame, text="Asset Actions")
        act.pack(fill="x", pady=5)

        self.list_asset_id_var = tk.StringVar()
        self.list_price_var = tk.StringVar(value="0")
        self.list_currency_var = tk.StringVar(value="COIN")
        self.list_fee_var = tk.StringVar(value="0")

        ttk.Label(act, text="Asset ID:").grid(row=0, column=0, sticky="w")
        ttk.Entry(act, textvariable=self.list_asset_id_var, width=18).grid(row=0, column=1, padx=5, sticky="we")

        ttk.Label(act, text="List Price:").grid(row=0, column=2, sticky="w")
        ttk.Entry(act, textvariable=self.list_price_var, width=10).grid(row=0, column=3, padx=5)

        ttk.Label(act, text="Currency:").grid(row=0, column=4, sticky="w")
        ttk.Entry(act, textvariable=self.list_currency_var, width=10).grid(row=0, column=5, padx=5)

        ttk.Label(act, text="Fee:").grid(row=0, column=6, sticky="w")
        ttk.Entry(act, textvariable=self.list_fee_var, width=8).grid(row=0, column=7, padx=5, sticky="we")

        ttk.Button(act, text="List for Sale", command=self._async(self.on_list_asset)).grid(row=0, column=8, padx=5)

        # purchase
        self.purchase_asset_id_var = tk.StringVar()
        self.purchase_fee_var = tk.StringVar(value="0")

        ttk.Label(act, text="Asset ID:").grid(row=1, column=0, sticky="w")
        ttk.Entry(act, textvariable=self.purchase_asset_id_var, width=18).grid(row=1, column=1, padx=5, sticky="we")

        ttk.Label(act, text="Fee:").grid(row=1, column=2, sticky="w")
        ttk.Entry(act, textvariable=self.purchase_fee_var, width=8).grid(row=1, column=3, padx=5, sticky="we")

        ttk.Button(act, text="Purchase", command=self._async(self.on_purchase_asset)).grid(row=1, column=4, padx=5)

        # transfer
        self.transfer_asset_id_var = tk.StringVar()
        self.transfer_recipient_var = tk.StringVar()
        self.transfer_fee_var = tk.StringVar(value="0")

        ttk.Label(act, text="Asset ID:").grid(row=2, column=0, sticky="w")
        ttk.Entry(act, textvariable=self.transfer_asset_id_var, width=18).grid(row=2, column=1, padx=5, sticky="we")

        ttk.Label(act, text="Recipient:").grid(row=2, column=2, sticky="w")
        ttk.Entry(act, textvariable=self.transfer_recipient_var, width=22).grid(row=2, column=3, padx=5, sticky="we")

        ttk.Label(act, text="Fee:").grid(row=2, column=4, sticky="w")
        ttk.Entry(act, textvariable=self.transfer_fee_var, width=8).grid(row=2, column=5, padx=5, sticky="we")

        ttk.Button(act, text="Transfer", command=self._async(self.on_transfer_asset)).grid(row=2, column=6, padx=5)

        return frame

    def _tab_transactions(self):
        frame = ttk.Frame(self, padding=10)

        # View mempool txs
        mem = ttk.LabelFrame(frame, text="Mempool")
        mem.pack(fill="x", pady=5)
        ttk.Button(mem, text="Refresh Mempool", command=self._async(self.on_get_mempool)).pack(side="left", padx=5, pady=5)
        ttk.Button(mem, text="Known Addresses", command=self._async(self.on_get_known_addresses)).pack(side="left", padx=5, pady=5)

        # Results text
        self.result_text = tk.Text(frame, height=18, wrap="word")
        self.result_text.pack(fill="both", expand=True, pady=(5, 0))

        return frame

    # --- Async wrapper for buttons ---
    def _async(self, fn):
        def runner():
            threading.Thread(target=self._safe_call, args=(fn,), daemon=True).start()
        return runner

    def _safe_call(self, fn):
        try:
            fn()
        except Exception as e:
            self.log(f"[Error] {e}")

    # --- Logging & output ---
    def log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def show_json(self, obj):
        self.result_text.delete("1.0", "end")
        try:
            self.result_text.insert("end", json.dumps(obj, indent=2))
        except Exception:
            self.result_text.insert("end", str(obj))

    # --- Button handlers ---
    def on_health(self):
        j = self.api.get_health()
        self.log(f"[Health] {j}")
        self.show_json(j)

    def on_chain_len(self):
        j = self.api.get_blockchain_len()
        self.log(f"[Chain Length] {j}")
        self.show_json(j)

    def on_mine(self):
        j = self.api.mine()
        self.log("[Mine] Block mined")
        self.show_json(j)

    def on_get_balance(self):
        addr = (self.bal_addr_var.get().strip() or self.active_addr_var.get().strip())
        if not addr:
            messagebox.showwarning("Missing address", "Enter an address (or set Active Wallet Address).")
            return
        seed = self.seed_var.get().strip()
        j = self.api.get_balance(addr, seed_param=seed)
        self.log(f"[Balance] {addr} -> {j}")
        self.show_json(j)

    def on_send_coins(self):
        recipient = self.tx_recipient_var.get().strip()
        amount = self.tx_amount_var.get().strip()
        currency = self.currency_var.get().strip() or "COIN"
        fee = self.tx_fee_var.get().strip()

        if not recipient or not amount:
            messagebox.showwarning("Missing fields", "Recipient and Amount are required.")
            return

        j = self.api.send_coins(recipient, amount, currency, fee=fee)
        self.log(f"[Transfer] {amount} {currency} (fee {fee or 0}) -> {recipient} : {j.get('id', '')}")
        self.show_json(j)

    def on_register_asset(self):
        aid = self.asset_id_var.get().strip()
        if not aid:
            messagebox.showwarning("Missing Asset ID", "Provide an Asset ID.")
            return
        owner = self.asset_owner_var.get().strip() or self.active_addr_var.get().strip() or None
        price = safe_int(self.asset_price_var.get(), 0)
        currency = self.asset_currency_var.get().strip() or "COIN"
        transferable = bool(self.asset_transferable_var.get())

        j = self.api.register_asset(aid, owner, price, currency, transferable)
        self.log(f"[Asset Register] {aid} -> {j}")
        self.show_json(j)

    def on_get_asset(self):
        aid = self.get_asset_id_var.get().strip()
        if not aid:
            messagebox.showwarning("Missing Asset ID", "Provide an Asset ID.")
            return
        j = self.api.get_asset(aid)
        self.log(f"[Asset Get] {aid} -> {j}")
        self.show_json(j)

    def on_list_asset(self):
        aid = self.list_asset_id_var.get().strip()
        price = self.list_price_var.get().strip()
        currency = self.list_currency_var.get().strip() or "COIN"
        fee = self.list_fee_var.get().strip()

        if not aid:
            messagebox.showwarning("Missing Asset ID", "Provide an Asset ID.")
            return
        if not price:
            messagebox.showwarning("Missing Price", "Provide a list price.")
            return

        j = self.api.list_asset(aid, price, currency, fee=fee)
        self.log(f"[Asset List] {aid} for {price} {currency} (fee {fee or 0}) -> {j}")
        self.show_json(j)

    def on_purchase_asset(self):
        aid = self.purchase_asset_id_var.get().strip()
        fee = self.purchase_fee_var.get().strip()
        if not aid:
            messagebox.showwarning("Missing Asset ID", "Provide an Asset ID.")
            return
        j = self.api.purchase_asset(aid, fee=fee)
        self.log(f"[Asset Purchase] {aid} (fee {fee or 0}) -> {j}")
        self.show_json(j)

    def on_transfer_asset(self):
        aid = self.transfer_asset_id_var.get().strip()
        recipient = self.transfer_recipient_var.get().strip()
        fee = self.transfer_fee_var.get().strip()
        if not aid or not recipient:
            messagebox.showwarning("Missing fields", "Provide Asset ID and Recipient.")
            return
        j = self.api.transfer_asset(aid, recipient, fee=fee)
        self.log(f"[Asset Transfer] {aid} -> {recipient} (fee {fee or 0}) : {j}")
        self.show_json(j)

    def on_get_mempool(self):
        j = self.api.get_transactions()
        self.log("[Mempool] fetched")
        self.show_json(j)

    def on_get_known_addresses(self):
        j = self.api.get_known_addresses()
        self.log("[Known Addresses] fetched")
        self.show_json(j)


if __name__ == "__main__":
    app = WalletGUI()
    app.mainloop()
