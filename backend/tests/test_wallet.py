import pytest
from uuid import uuid4
from decimal import Decimal
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.users.models import User
from server.wallet.models import Wallet, Transaction, LedgerEntry


@pytest.mark.asyncio
async def test_wallet_creation_and_idempotency(client: AsyncClient, get_auth_headers):
    # 1. Register test user
    reg_resp = await client.post("/auth/register", json={
        "email_address": "wallet_user1@example.com",
        "password": "SecurePassword123!"
    })
    assert reg_resp.status_code == 201

    headers = get_auth_headers("wallet_user1@example.com")

    # 2. Create GHS wallet
    create_resp = await client.post("/wallets", json={"currency": "GHS"}, headers=headers)
    assert create_resp.status_code == 201
    w_data = create_resp.json()
    assert w_data["currency"] == "GHS"
    assert float(w_data["balance"]) == 0.0
    wallet_id = w_data["id"]

    # 3. Create duplicate GHS wallet (should return existing wallet)
    dup_resp = await client.post("/wallets", json={"currency": "GHS"}, headers=headers)
    assert dup_resp.status_code == 201
    dup_data = dup_resp.json()
    assert dup_data["id"] == wallet_id


@pytest.mark.asyncio
async def test_deposit_and_balance(client: AsyncClient, get_auth_headers, session: AsyncSession):
    # Register and create wallet
    await client.post("/auth/register", json={
        "email_address": "deposit_user@example.com",
        "password": "Password123!"
    })
    headers = get_auth_headers("deposit_user@example.com")
    
    w_resp = await client.post("/wallets", json={"currency": "GHS"}, headers=headers)
    wallet_id = w_resp.json()["id"]

    # Deposit funds
    dep_resp = await client.post(
        f"/wallets/{wallet_id}/deposit",
        json={"amount": 1000.0, "currency": "GHS", "description": "ATM Deposit"},
        headers=headers
    )
    assert dep_resp.status_code == 200
    assert dep_resp.json()["status"] == "SUCCESS"

    # Verify balance
    me_resp = await client.get("/wallets/me", headers=headers)
    assert me_resp.status_code == 200
    wallets = me_resp.json()
    assert len(wallets) == 1
    assert float(wallets[0]["balance"]) == 1000.0


@pytest.mark.asyncio
async def test_p2p_transfer_and_idempotency(client: AsyncClient, get_auth_headers, session: AsyncSession):
    # Register two users
    await client.post("/auth/register", json={
        "email_address": "sender@example.com",
        "password": "Password123!"
    })
    await client.post("/auth/register", json={
        "email_address": "receiver@example.com",
        "password": "Password123!"
    })

    sender_headers = get_auth_headers("sender@example.com")
    receiver_headers = get_auth_headers("receiver@example.com")

    # Create wallets
    sender_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=sender_headers)).json()
    receiver_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=receiver_headers)).json()

    sender_wallet_id = sender_w["id"]
    receiver_wallet_id = receiver_w["id"]

    # Fund sender
    await client.post(
        f"/wallets/{sender_wallet_id}/deposit",
        json={"amount": 500.00, "currency": "GHS"},
        headers=sender_headers
    )

    # Perform P2P transfer
    idempotency_key = f"tx_key_{uuid4()}"
    transfer_payload = {
        "source_wallet_id": sender_wallet_id,
        "destination_wallet_id": receiver_wallet_id,
        "amount": 200.00,
        "currency": "GHS",
        "description": "Lunch split"
    }

    # First attempt
    tx_resp1 = await client.post(
        "/wallets/transfer",
        json=transfer_payload,
        headers={**sender_headers, "Idempotency-Key": idempotency_key}
    )
    assert tx_resp1.status_code == 200
    res1 = tx_resp1.json()
    assert res1["status"] == "SUCCESS"
    assert float(res1["sender_balance"]) == 300.00

    # Verify sender and receiver balances in DB
    sender_me = (await client.get("/wallets/me", headers=sender_headers)).json()
    assert float(sender_me[0]["balance"]) == 300.00

    receiver_me = (await client.get("/wallets/me", headers=receiver_headers)).json()
    assert float(receiver_me[0]["balance"]) == 200.00

    # Repeat transfer with same idempotency key (replay)
    tx_resp2 = await client.post(
        "/wallets/transfer",
        json=transfer_payload,
        headers={**sender_headers, "Idempotency-Key": idempotency_key}
    )
    assert tx_resp2.status_code == 200
    res2 = tx_resp2.json()
    # Should be identical to res1
    assert res2["transaction_id"] == res1["transaction_id"]
    assert float(res2["sender_balance"]) == 300.00

    # Verify balances did NOT change (no double spend)
    sender_me_again = (await client.get("/wallets/me", headers=sender_headers)).json()
    assert float(sender_me_again[0]["balance"]) == 300.00


@pytest.mark.asyncio
async def test_transfer_validation_errors(client: AsyncClient, get_auth_headers):
    await client.post("/auth/register", json={
        "email_address": "user_errors@example.com",
        "password": "Password123!"
    })
    headers = get_auth_headers("user_errors@example.com")

    # Create wallet
    w = (await client.post("/wallets", json={"currency": "GHS"}, headers=headers)).json()
    wallet_id = w["id"]

    # Fund wallet with 100 GHS
    await client.post(f"/wallets/{wallet_id}/deposit", json={"amount": 100.00, "currency": "GHS"}, headers=headers)

    # Create a destination wallet for testing insufficient funds
    await client.post("/auth/register", json={
        "email_address": "receiver_errors@example.com",
        "password": "Password123!"
    })
    rec_headers = get_auth_headers("receiver_errors@example.com")
    rec_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=rec_headers)).json()
    receiver_wallet_id = rec_w["id"]

    # 1. Insufficient funds
    fail_resp1 = await client.post(
        "/wallets/transfer",
        json={
            "source_wallet_id": wallet_id,
            "destination_wallet_id": receiver_wallet_id,
            "amount": 250.00,
            "currency": "GHS"
        },
        headers={**headers, "Idempotency-Key": str(uuid4())}
    )
    assert fail_resp1.status_code == 400
    assert "Insufficient funds" in fail_resp1.json()["detail"]

    # 1.5. Destination wallet not found
    fail_resp1_5 = await client.post(
        "/wallets/transfer",
        json={
            "source_wallet_id": wallet_id,
            "destination_wallet_id": str(uuid4()),  # non-existent
            "amount": 10.00,
            "currency": "GHS"
        },
        headers={**headers, "Idempotency-Key": str(uuid4())}
    )
    assert fail_resp1_5.status_code == 404
    assert "Destination wallet not found" in fail_resp1_5.json()["detail"]

    # 2. Transfer to self
    fail_resp2 = await client.post(
        "/wallets/transfer",
        json={
            "source_wallet_id": wallet_id,
            "destination_wallet_id": wallet_id,
            "amount": 10.00,
            "currency": "GHS"
        },
        headers={**headers, "Idempotency-Key": str(uuid4())}
    )
    assert fail_resp2.status_code == 400
    assert "different" in fail_resp2.json()["detail"]


@pytest.mark.asyncio
async def test_daily_limit_exceeded(client: AsyncClient, get_auth_headers):
    await client.post("/auth/register", json={
        "email_address": "limit_user@example.com",
        "password": "Password123!"
    })
    await client.post("/auth/register", json={
        "email_address": "limit_rec@example.com",
        "password": "Password123!"
    })

    sender_headers = get_auth_headers("limit_user@example.com")
    rec_headers = get_auth_headers("limit_rec@example.com")

    sender_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=sender_headers)).json()
    rec_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=rec_headers)).json()

    # Fund sender with 6000 GHS
    await client.post(f"/wallets/{sender_w['id']}/deposit", json={"amount": 6000.00, "currency": "GHS"}, headers=sender_headers)

    # Attempt to transfer 5001 GHS (limit is 5000)
    limit_resp = await client.post(
        "/wallets/transfer",
        json={
            "source_wallet_id": sender_w["id"],
            "destination_wallet_id": rec_w["id"],
            "amount": 5001.00,
            "currency": "GHS"
        },
        headers={**sender_headers, "Idempotency-Key": str(uuid4())}
    )
    assert limit_resp.status_code == 400
    assert "limit" in limit_resp.json()["detail"]


@pytest.mark.asyncio
async def test_velocity_limit_exceeded(client: AsyncClient, get_auth_headers):
    await client.post("/auth/register", json={
        "email_address": "velocity_user@example.com",
        "password": "Password123!"
    })
    await client.post("/auth/register", json={
        "email_address": "velocity_rec@example.com",
        "password": "Password123!"
    })

    sender_headers = get_auth_headers("velocity_user@example.com")
    rec_headers = get_auth_headers("velocity_rec@example.com")

    sender_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=sender_headers)).json()
    rec_w = (await client.post("/wallets", json={"currency": "GHS"}, headers=rec_headers)).json()

    # Fund sender
    await client.post(f"/wallets/{sender_w['id']}/deposit", json={"amount": 1000.00, "currency": "GHS"}, headers=sender_headers)

    # Perform 5 valid transfers in rapid succession
    for i in range(5):
        resp = await client.post(
            "/wallets/transfer",
            json={
                "source_wallet_id": sender_w["id"],
                "destination_wallet_id": rec_w["id"],
                "amount": 1.00,
                "currency": "GHS"
            },
            headers={**sender_headers, "Idempotency-Key": f"velocity_key_{i}"}
        )
        assert resp.status_code == 200

    # 6th transfer should violate velocity check (limit is max 5 per minute)
    fail_resp = await client.post(
        "/wallets/transfer",
        json={
            "source_wallet_id": sender_w["id"],
            "destination_wallet_id": rec_w["id"],
            "amount": 1.00,
            "currency": "GHS"
        },
        headers={**sender_headers, "Idempotency-Key": "velocity_key_6"}
    )
    assert fail_resp.status_code == 429
    assert "Velocity limit exceeded" in fail_resp.json()["detail"]
