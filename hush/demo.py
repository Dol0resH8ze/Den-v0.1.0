"""A reproducible three-client loopback demonstration using the actual protocol."""

import asyncio

from .client import RoomClient
from .relay import Relay


async def _until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.01)


async def _chat(client):
    async with asyncio.timeout(5):
        while True:
            event = await client.events.get()
            if event["type"] == "chat":
                return event
            if event["type"] == "closed":
                raise ConnectionError("Demo room closed unexpectedly.")


async def run():
    print("HUSH LOCAL DEMO — three clients, actual encryption, no Tor anonymity")
    relay = Relay()
    clients = []
    await relay.start()
    try:
        alice = await RoomClient.create("Alice", relay.address[0], relay.address[1], local_test=True)
        clients.append(alice)
        print("1. Alice creates a room. No signup; fresh session identity generated.")
        for name in ("Bob", "Cara"):
            guest = await RoomClient.join(name, alice.invite.encode(), local_test=True)
            clients.append(guest)
            await _until(lambda: guest.identity.sign_key in alice.pending)
            print(f"2. {name} requests admission; Alice approves the device.")
            await alice.approve(name)
            await _until(lambda: all(c.admitted and len(c.members) == len(clients) for c in clients))
        bob, cara = clients[1:]
        await bob.send_text("Hello from a private room!")
        received = await asyncio.gather(_chat(alice), _chat(cara))
        assert all(e["text"] == "Hello from a private room!" for e in received)
        print("3. Bob sends a message. Alice and Cara decrypt it; the relay only forwards ciphertext.")
        await alice.set_locked(True)
        await _until(lambda: bob.locked and cara.locked)
        print("4. Alice locks the room against new joins.")
        await alice.kick("Cara")
        await _until(lambda: cara.closed.is_set() and len(bob.members) == 2)
        await bob.send_text("Only the remaining participants can read this new message.")
        await _chat(alice)
        print("5. Alice removes Cara. Bob's next message is delivered to Alice only.")
        await alice.close()
        await _until(lambda: bob.closed.is_set())
        print("6. Alice leaves. The room closes and the relay discards its room state.")
        print("PASS — room creation, approval, encrypted group chat, lock, removal, and closure.")
    finally:
        await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)
        await relay.close()

