#!/usr/bin/env python3
"""
BLE Sniffing Comparison Test — PQ-BLE-HANDSHAKE
================================================
Simula ciò che un BLE sniffer (es. nRF52840 con Wireshark/tshark) vedrebbe
PRIMA e DOPO l'handshake PQ-BLE.

Scenario A: BLE standard senza PQ – dati in chiaro visibili allo sniffer
Scenario B: PQ-BLE handshake completato – dati cifrati AES-256-GCM

Questo script NON richiede hardware BLE reale: simula i payload GATT
così come apparirebbero in una cattura Wireshark.

COLLEGAMENTO CON TESI TRIENNALE:
La pipeline ble_pipeline.py della tesi triennale (analisi sicurezza BLE)
può essere usata per catturare il traffico REALE di questo handshake,
dimostrando che:
  - La connessione BLE è stabilita (CONNECT_IND visibile)
  - L'SMP pairing NON avviene (nessun Security Manager exchange)
  - I pacchetti GATT contengono pk ML-KEM e ct (non standard)
  - Dopo l'handshake, i dati su GATT NOTIFY sono cifrati AES-GCM
"""

import hashlib
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

# Aggiungi src/ al path per importare i moduli del progetto
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.common.ml_kem import generate_keypair, encapsulate, decapsulate
from src.common.sas import derive_sas, format_sas
from src.common.session import (
    derive_session_key,
    SecureChannel,
    generate_session_id,
)
from src.common.fragmentation import fragment_data, reassemble_data
from src.common.constants import (
    SERVICE_UUID, CHAR_PUBKEY_UUID, CHAR_CIPHERTEXT_UUID,
    CHAR_DATA_UUID, CHAR_CONTROL_UUID, DEVICE_NAME,
    PK_SIZE, CT_SIZE, SS_SIZE,
    PERIPHERAL_ROLE, CENTRAL_ROLE,
)

# ─── ANSI Colors ───────────────────────────────────────────────
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE   = "\033[94m"
C_CYAN   = "\033[96m"
C_BOLD   = "\033[1m"
C_RESET  = "\033[0m"

# ─── Simulated BLE Addresses ──────────────────────────────────
PERIPHERAL_MAC = "DE:AD:BE:EF:FE:ED"
CENTRAL_MAC    = "CA:FE:CA:FE:CA:FE"

# Simulati connection parameters
CONN_INTERVAL_MS = 30   # connection interval tipico BLE
ACCESS_ADDRESS   = 0xA1B2C3D4


@dataclass
class BlePacket:
    """Rappresenta un pacchetto BLE catturato dallo sniffer."""
    timestamp: float
    direction: str       # "CENTRAL → PERIPHERAL" o "PERIPHERAL → CENTRAL"
    access_addr: int
    llid: str            # LL Data, LL Control, Empty PDU
    channel: int
    layer: str           # "GATT" o "Link Layer" o "SMP"
    gatt_op: str         # READ_REQ, READ_RSP, WRITE_REQ, WRITE_RSP, NOTIFY
    att_handle: int
    uuid_hint: str       # hint dell'UUID (se noto)
    payload_hex: str     # payload in esadecimale
    payload_ascii: str   # tentativo di decodifica ASCII
    note: str = ""       # annotazione


@dataclass
class SniffSession:
    """Una sessione di sniffing completa."""
    scenario: str
    packets: List[BlePacket] = field(default_factory=list)
    start_time: float = 0.0
    duration_ms: float = 0.0

    def add_packet(self, direction: str, layer: str, gatt_op: str,
                   uuid_hint: str, payload: bytes, note: str = ""):
        """Aggiunge un pacchetto alla cattura."""
        ts = time.time() - self.start_time
        ts_ms = ts * 1000

        # Determina LLID
        if gatt_op in ("READ_REQ", "WRITE_REQ", "WRITE_RSP"):
            llid = "LL Data (start)"
        elif gatt_op in ("READ_RSP", "NOTIFY", "INDICATE"):
            llid = "LL Data (cont)"
        else:
            llid = "LL Data"

        pkt = BlePacket(
            timestamp=ts_ms,
            direction=direction,
            access_addr=ACCESS_ADDRESS,
            llid=llid,
            channel=7 + (len(self.packets) % 30),  # simulato
            layer=layer,
            gatt_op=gatt_op,
            att_handle=0x002A + len(self.packets),
            uuid_hint=uuid_hint,
            payload_hex=payload[:32].hex() + ("..." if len(payload) > 32 else ""),
            payload_ascii=payload[:32].decode("ascii", errors="replace"),
            note=note,
        )
        self.packets.append(pkt)


# ═══════════════════════════════════════════════════════════════
#  SCENARIO A: BLE standard — dati in chiaro
# ═══════════════════════════════════════════════════════════════

def simulate_plaintext_ble():
    """Simula una connessione BLE dove i dati viaggiano in chiaro."""
    session = SniffSession(scenario="A: BLE senza PQ (dati in chiaro)")
    session.start_time = time.time()

    print()
    print(C_BOLD + "═" * 70 + C_RESET)
    print(C_BOLD + "  SCENARIO A: BLE STANDARD — DATI IN CHIARO" + C_RESET)
    print(C_BOLD + "═" * 70 + C_RESET)
    print(f"  Sniffer: nRF52840 Dongle + Wireshark")
    print(f"  Peripheral: {PERIPHERAL_MAC} ({DEVICE_NAME})")
    print(f"  Central:    {CENTRAL_MAC}")
    print()

    # ── Connection Setup ──────────────────────────────────────
    print(C_CYAN + "── Connessione BLE ──" + C_RESET)

    session.add_packet(
        "PERIPHERAL → CENTRAL", "Link Layer", "ADV_IND",
        "Advertising", b"PQ-BLE-Device",
        "Il peripheral si annuncia"
    )
    session.add_packet(
        "CENTRAL → PERIPHERAL", "Link Layer", "CONNECT_IND",
        "Connection", b"\x00" * 34,
        f"Connessione stabilita (CI={CONN_INTERVAL_MS}ms)"
    )

    # ── GATT Discovery ────────────────────────────────────────
    print(C_CYAN + "── GATT Service Discovery ──" + C_RESET)

    session.add_packet(
        "CENTRAL → PERIPHERAL", "GATT", "READ_BY_GROUP_TYPE_REQ",
        "Service Discovery", b"",
        "Richiesta: elenca tutti i primary services"
    )
    session.add_packet(
        "PERIPHERAL → CENTRAL", "GATT", "READ_BY_GROUP_TYPE_RSP",
        SERVICE_UUID, SERVICE_UUID.encode(),
        f"Risposta: service {SERVICE_UUID[:8]}..."
    )

    # ── Plaintext Data Exchange ──────────────────────────────
    print(C_YELLOW + "── Scambio Dati in CHIARO su GATT ──" + C_RESET)
    print(C_RED + "   ⚠ LO SNIFFER LEGGE TUTTO IN CHIARO!" + C_RESET)
    print()

    sensitive_messages = [
        b"LOGIN: admin / P@ssw0rd123!",
        b"TEMPERATURA_SENSORE: 36.8C",
        b"API_KEY: sk-7a8f6d3c2b1e4098",
        b"CREDENZIALI_WIFI: MyWifiNetwork / secretkey",
        b"TOKEN_JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    ]

    for i, msg in enumerate(sensitive_messages):
        session.add_packet(
            "PERIPHERAL → CENTRAL", "GATT", "NOTIFY",
            CHAR_DATA_UUID, msg,
            f"⚠ DATO IN CHIARO #{i+1}: '{msg.decode()}'"
        )

    print(C_RED + "   ❌ RISULTATO: L'attaccante vede TUTTI i dati sensibili!" + C_RESET)
    print(C_RED + "   ❌ Password, API key, token JWT, dati personali ESPOSTI" + C_RESET)

    return session


# ═══════════════════════════════════════════════════════════════
#  SCENARIO B: PQ-BLE — handshake + canale cifrato
# ═══════════════════════════════════════════════════════════════

def simulate_pq_ble_handshake():
    """Simula la connessione BLE con handshake PQ e dati cifrati."""
    session = SniffSession(scenario="B: PQ-BLE (dati cifrati con ML-KEM + AES-GCM)")
    session.start_time = time.time()

    print()
    print(C_BOLD + "═" * 70 + C_RESET)
    print(C_BOLD + "  SCENARIO B: PQ-BLE HANDSHAKE — DATI CIFRATI" + C_RESET)
    print(C_BOLD + "═" * 70 + C_RESET)
    print(f"  Sniffer: nRF52840 Dongle + Wireshark")
    print(f"  Peripheral: {PERIPHERAL_MAC} ({DEVICE_NAME})")
    print(f"  Central:    {CENTRAL_MAC}")
    print()

    # ── Connection Setup ──────────────────────────────────────
    print(C_CYAN + "── Connessione BLE (identica allo Scenario A) ──" + C_RESET)

    session.add_packet(
        "PERIPHERAL → CENTRAL", "Link Layer", "ADV_IND",
        "Advertising", b"PQ-BLE-Device",
        "Advertising — nessuna differenza"
    )
    session.add_packet(
        "CENTRAL → PERIPHERAL", "Link Layer", "CONNECT_IND",
        "Connection", b"\x00" * 34,
        "Connessione stabilita"
    )

    # ── GATT Discovery ────────────────────────────────────────
    print(C_CYAN + "── GATT Discovery (servizio PQ custom) ──" + C_RESET)

    session.add_packet(
        "CENTRAL → PERIPHERAL", "GATT", "READ_BY_TYPE_REQ",
        "Service Discovery", b"",
        "Central cerca servizi"
    )
    session.add_packet(
        "PERIPHERAL → CENTRAL", "GATT", "READ_BY_TYPE_RSP",
        SERVICE_UUID, SERVICE_UUID.encode(),
        f"Servizio PQ custom: {SERVICE_UUID[:18]}..."
    )

    # ── Eseguiamo l'handshake REALE con ML-KEM ────────────────
    print(C_GREEN + "── PQ Handshake (ML-KEM-768 + SAS) ──" + C_RESET)

    # Peripheral genera chiavi
    pk, sk = generate_keypair()
    print(f"  [Peripheral] keygen ML-KEM-768 → pk={len(pk)}B, sk={len(sk)}B")

    # GATT READ: Central legge la public key
    pk_fragments = fragment_data(pk, mtu=512)
    print(f"  [GATT] Central READ pk → {len(pk_fragments)} frammenti ({len(pk)}B totali)")

    for i, frag in enumerate(pk_fragments):
        session.add_packet(
            "CENTRAL → PERIPHERAL", "GATT", "READ_REQ",
            CHAR_PUBKEY_UUID, b"",
            f"Richiesta pk_A (frammento {i+1}/{len(pk_fragments)})"
        )
        session.add_packet(
            "PERIPHERAL → CENTRAL", "GATT", "READ_RSP",
            CHAR_PUBKEY_UUID, frag,
            f"⚠ pk ML-KEM ({len(frag)}B) — cifrato? NO, è la CHIAVE PUBBLICA"
        )

    # Central: encapsulate
    ct, ss_central = encapsulate(pk)
    print(f"  [Central] encapsulate(pk) → ct={len(ct)}B, ss={len(ss_central)}B")

    # GATT WRITE: Central scrive il ciphertext
    ct_fragments = fragment_data(ct, mtu=512)
    print(f"  [GATT] Central WRITE ct → {len(ct_fragments)} frammenti ({len(ct)}B totali)")

    for i, frag in enumerate(ct_fragments):
        session.add_packet(
            "CENTRAL → PERIPHERAL", "GATT", "WRITE_REQ",
            CHAR_CIPHERTEXT_UUID, frag,
            f"⚠ Ciphertext ML-KEM ({len(frag)}B) — inutile senza sk"
        )

    # Peripheral: decapsulate
    ss_peripheral = decapsulate(sk, ct)
    assert ss_central == ss_peripheral, "Shared secret mismatch!"
    print(f"  [Peripheral] decapsulate(sk, ct) → ss={len(ss_peripheral)}B ✓")

    # SAS Numeric Comparison
    sas = derive_sas(pk, ct, ss_central)
    sas_str = format_sas(sas)
    print(f"  [SAS] Entrambi derivano SAS: {sas_str}")
    print(f"  [UTENTE] Confronta visivamente → CONFERMA ✓")

    # HKDF: derivazione chiave di sessione
    session_key = derive_session_key(ss_central)
    session_id = generate_session_id()
    print(f"  [HKDF] session_key derivata: {len(session_key)}B (AES-256)")
    print(f"  [AAD] session_id={session_id.hex()[:16]}... role binding attivo")

    # ── Canale Cifrato ─────────────────────────────────────────
    print(C_GREEN + "── Canale Cifrato AES-256-GCM su GATT NOTIFY ──" + C_RESET)
    print(C_GREEN + "   ✅ D'ora in poi, TUTTI i dati sono cifrati!" + C_RESET)
    print()

    channel_p = SecureChannel(session_key, session_id=session_id,
                               role=PERIPHERAL_ROLE)
    channel_c = SecureChannel(session_key, session_id=session_id,
                              role=CENTRAL_ROLE)

    sensitive_messages = [
        b"LOGIN: admin / P@ssw0rd123!",
        b"TEMPERATURA_SENSORE: 36.8C",
        b"API_KEY: sk-7a8f6d3c2b1e4098",
        b"CREDENZIALI_WIFI: MyWifiNetwork / secretkey",
        b"TOKEN_JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6...",
    ]

    for i, msg in enumerate(sensitive_messages):
        # Cifra il messaggio (peripheral → central)
        wire_data = channel_p.encrypt(msg)
        seq = wire_data[:8]
        msg_type = wire_data[8:9]
        iv = wire_data[9:21]
        ct_data = wire_data[21:-16]
        tag = wire_data[-16:]

        session.add_packet(
            "PERIPHERAL → CENTRAL", "GATT", "NOTIFY",
            CHAR_DATA_UUID, wire_data,
            f"🔒 DATO CIFRATO #{i+1}: seq={int.from_bytes(seq,'big')} "
            f"type={msg_type.hex()} IV={iv.hex()[:16]}... ct={len(ct_data)}B, tag={tag.hex()[:16]}..."
        )

        # Decifra per verifica (central riceve)
        decrypted = channel_c.decrypt(wire_data)
        assert decrypted == msg, f"Decrypt fallito per msg #{i+1}!"

    print(C_GREEN + "   ✅ RISULTATO: Lo sniffer vede SOLO byte cifrati!" + C_RESET)
    print(C_GREEN + "   ✅ AES-256-GCM: confidenzialità + integrità + autenticità" + C_RESET)
    print(C_GREEN + "   ✅ ML-KEM-768: resistenza quantistica (NIST FIPS 203)" + C_RESET)

    return session


# ═══════════════════════════════════════════════════════════════
#  RIEPILOGO COMPARATIVO
# ═══════════════════════════════════════════════════════════════

def print_comparison(session_a: SniffSession, session_b: SniffSession):
    """Stampa il confronto tra i due scenari."""

    print()
    print(C_BOLD + "═" * 70 + C_RESET)
    print(C_BOLD + "  CONFRONTO: SCENARIO A vs SCENARIO B" + C_RESET)
    print(C_BOLD + "═" * 70 + C_RESET)
    print()

    print(f"  {'':<35} {'SCENARIO A':<22} {'SCENARIO B':<22}")
    print(f"  {'':<35} {'Senza PQ':<22} {'Con PQ-BLE':<22}")
    print(f"  {'─'*35} {'─'*22} {'─'*22}")

    rows = [
        ("Pacchetti GATT totali", f"{len(session_a.packets)}", f"{len(session_b.packets)}"),
        ("Dati sensibili esposti?", f"{C_RED}✅ SÌ — tutti{C_RESET}",
         f"{C_GREEN}❌ NO — cifrati{C_RESET}"),
        ("Password visibile?", f"{C_RED}SÌ — 'P@ssw0rd123!'{C_RESET}",
         f"{C_GREEN}NO — solo byte casuali{C_RESET}"),
        ("API key visibile?", f"{C_RED}SÌ — 'sk-7a8f6d3c...'{C_RESET}",
         f"{C_GREEN}NO — cifrata{C_RESET}"),
        ("Token JWT visibile?", f"{C_RED}SÌ — header.payload...{C_RESET}",
         f"{C_GREEN}NO — cifrato{C_RESET}"),
        ("Resistenza store-now-decrypt-later?", f"{C_RED}❌ Nessuna (ECDH){C_RESET}",
         f"{C_GREEN}✅ ML-KEM-768 (~174 bit QC){C_RESET}"),
        ("Cifratura", f"{C_RED}NESSUNA{C_RESET}",
         f"{C_GREEN}AES-256-GCM AEAD{C_RESET}"),
        ("Autenticazione", f"{C_RED}NESSUNA{C_RESET}",
         f"{C_GREEN}SAS Numeric Comparison{C_RESET}"),
        ("MITM rilevabile?", f"{C_RED}❌ No{C_RESET}",
         f"{C_GREEN}✅ Sì — SAS mismatch{C_RESET}"),
        ("Click pairing SMP?", f"{C_RED}N/A{C_RESET}",
         f"{C_GREEN}NON USATO (app-level){C_RESET}"),
    ]

    for label, val_a, val_b in rows:
        print(f"  {label:<35} {val_a:<30} {val_b}")

    print()
    print(C_BOLD + "  CONCLUSIONE:" + C_RESET)
    print(f"  Nello Scenario A, uno sniffer BLE passivo (es. nRF52840 + Wireshark)")
    print(f"  legge TUTTI i dati in chiaro. Password, token, API key: tutto esposto.")
    print()
    print(f"  Nello Scenario B, lo stesso sniffer vede SOLO byte cifrati.")
    print(f"  Anche con un quantum computer futuro, ML-KEM-768 protegge lo scambio")
    print(f"  chiavi. AES-256-GCM protegge i dati. SAS rileva MITM attivi.")
    print()
    print(f"  {C_BOLD}Questa è la differenza tra 'sicurezza BLE standard' e{C_RESET}")
    print(f"  {C_BOLD}la protezione post-quantum del protocollo PQ-BLE-HANDSHAKE.{C_RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
#  EXPORT WIRESHARK-STYLE (PCAP simulato in formato testo)
# ═══════════════════════════════════════════════════════════════

def export_wireshark_style(session: SniffSession, filename: str):
    """Esporta la sessione in un formato simile al output di tshark."""
    with open(filename, "w") as f:
        f.write(f"# BLE Sniffing Report — {session.scenario}\n")
        f.write(f"# Sniffer: nRF52840 Dongle (nRF Sniffer for Bluetooth LE v4.1)\n")
        f.write(f"# Data: {datetime.now().isoformat()}\n")
        f.write(f"# Pacchetti: {len(session.packets)}\n")
        f.write(f"#\n")
        f.write(f"# {'No.':>4}  {'Time (ms)':>10}  {'Direction':<28}  "
                f"{'Layer':<12}  {'GATT Op':<25}  {'UUID Hint':<24}  {'Note'}\n")
        f.write(f"# {'─'*4}  {'─'*10}  {'─'*28}  {'─'*12}  "
                f"{'─'*25}  {'─'*24}  {'─'*40}\n")

        for i, pkt in enumerate(session.packets):
            f.write(
                f"  {i+1:>4}  {pkt.timestamp:>10.3f}  "
                f"{pkt.direction:<28}  {pkt.layer:<12}  "
                f"{pkt.gatt_op:<25}  {pkt.uuid_hint:<24}  {pkt.note}\n"
            )

    print(f"\n  📄 Report esportato: {filename}")


def export_payload_dump(session: SniffSession, filename: str):
    """Esporta un hex dump dei payload per confronto visivo."""
    with open(filename, "w") as f:
        f.write(f"# Payload Hex Dump — {session.scenario}\n")
        f.write(f"# ==================================================\n\n")

        for i, pkt in enumerate(session.packets):
            f.write(f"[{i+1:>3}] {pkt.gatt_op:<25} {pkt.direction}\n")
            f.write(f"     UUID: {pkt.uuid_hint}\n")
            f.write(f"     Hex:  {pkt.payload_hex}\n")
            if pkt.payload_ascii.strip():
                f.write(f"     ASCII: {pkt.payload_ascii.strip()}\n")
            if pkt.note:
                f.write(f"     NOTE: {pkt.note}\n")
            f.write("\n")

    print(f"  📄 Hex dump esportato: {filename}")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print(C_BOLD + C_BLUE)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   PQ-BLE-HANDSHAKE — Sniffing Test Comparativo              ║")
    print("║   Dimostrazione: cosa vede uno sniffer BLE                  ║")
    print("║   PRIMA e DOPO l'handshake post-quantum                     ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(C_RESET)

    print()
    print("  🎓 Collegamento tesi triennale → progetto SSR:")
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │ Tesi triennale: Analisi della sicurezza BLE             │")
    print("  │   → Sniffing passivo di pairing ECDH                   │")
    print("  │   → ble_pipeline.py per cattura + audit                │")
    print("  │   → nRF52840 come sniffer hardware                     │")
    print("  │                                                         │")
    print("  │ Progetto SSR: PQ-BLE-HANDSHAKE                         │")
    print("  │   → Sostituzione ECDH con ML-KEM-768                   │")
    print("  │   → Handshake GATT-based a livello applicativo         │")
    print("  │   → Stesso sniffer nRF52840 per VERIFICARE             │")
    print("  │   → Dimostrazione: traffico PRIMA in chiaro, DOPO      │")
    print("  │     cifrato AES-256-GCM                                │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()

    # ═══ SCENARIO A ═══
    session_a = simulate_plaintext_ble()

    print()
    input(C_YELLOW + "  Premi INVIO per passare allo Scenario B (PQ-BLE)..." + C_RESET)
    print()

    # ═══ SCENARIO B ═══
    session_b = simulate_pq_ble_handshake()

    # ═══ CONFRONTO ═══
    print()
    input(C_YELLOW + "  Premi INVIO per vedere il confronto finale..." + C_RESET)
    print_comparison(session_a, session_b)

    # ═══ EXPORT ═══
    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)

    export_wireshark_style(session_a,
        os.path.join(output_dir, "sniff_plaintext.txt"))
    export_wireshark_style(session_b,
        os.path.join(output_dir, "sniff_pq_ble.txt"))
    export_payload_dump(session_a,
        os.path.join(output_dir, "payload_dump_plaintext.txt"))
    export_payload_dump(session_b,
        os.path.join(output_dir, "payload_dump_pq_ble.txt"))

    print()
    print(C_BOLD + "  ✅ Test di sniffing completato!" + C_RESET)
    print(f"  I report sono in: {output_dir}/")
    print()
    print("  Per la cattura REALE con hardware:")
    print(f"    Terminale 1: PYTHONPATH=. python -m experimental.peripheral.main")
    print(f"    Terminale 2: python -m src.central.main")
    print(f"    Terminale 3: python ble_pipeline.py --dur 60 --base pq_test")
    print(f"    (ble_pipeline.py è la tua pipeline della tesi triennale)")
    print()


if __name__ == "__main__":
    main()
