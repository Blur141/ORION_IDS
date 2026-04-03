# ============================================================
# state.py — Global Start/Stop Switch
# ============================================================
# This file holds one simple variable: is the sniffer running?
# We put it in its own file so ALL other files can import it
# without causing circular import errors.
# ============================================================

# This is a mutable dictionary so other modules can change the
# value inside it (plain variables can't be changed across modules).
sniffer_state = {
    "running": False   # False = stopped, True = capturing packets
}
