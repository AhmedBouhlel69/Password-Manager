"""
BLE Central (Desktop Client) using bleak.

Runs asynchronous BLE discovery, connection, challenge dispatch, and response
collection to communicate with the iPhone companion peripheral.
Can be executed in a dedicated background worker thread or via asyncio.
"""

import asyncio
from typing import Optional, Dict, Any, List
from bleak import BleakScanner, BleakClient

from src.ble.protocol import (
    SERVICE_UUID,
    CHALLENGE_CHAR_UUID,
    RESPONSE_CHAR_UUID,
    PAIRING_CHAR_UUID,
    CHALLENGE_TIMEOUT_SECONDS,
    create_challenge_payload,
    parse_challenge_response,
    verify_ecdsa_p256_signature
)


class BLECentralError(Exception):
    pass


class BLECentralClient:
    """Async BLE Central for communicating with iPhone companion app."""

    def __init__(self, service_uuid: str = SERVICE_UUID):
        self.service_uuid = service_uuid
        self._client: Optional[BleakClient] = None

    async def scan_for_companion(self, timeout: float = 5.0) -> List[Any]:
        """Scans for nearby iPhone companion peripherals advertising our service UUID."""
        devices = await BleakScanner.discover(timeout=timeout, service_uuids=[self.service_uuid])
        return devices

    async def request_approval(
        self,
        device_address_or_ble_device: Any,
        vault_name: str,
        nonce: bytes,
        stored_public_key: bytes,
        timeout: float = CHALLENGE_TIMEOUT_SECONDS
    ) -> bool:
        """
        Connects to the companion, sends the challenge, awaits approval notification,
        and cryptographically verifies the response signature.
        """
        response_future = asyncio.get_running_loop().create_future()

        def notification_handler(characteristic, data: bytearray):
            if not response_future.done():
                response_future.set_result(bytes(data))

        try:
            async with BleakClient(device_address_or_ble_device, timeout=10.0) as client:
                # 1. Subscribe to response notification
                await client.start_notify(RESPONSE_CHAR_UUID, notification_handler)

                # 2. Write challenge payload
                payload = create_challenge_payload(vault_name, nonce)
                await client.write_gatt_char(CHALLENGE_CHAR_UUID, payload, response=True)

                # 3. Wait for approval notification
                raw_response = await asyncio.wait_for(response_future, timeout=timeout)
                await client.stop_notify(RESPONSE_CHAR_UUID)

                # 4. Parse response
                parsed = parse_challenge_response(raw_response)
                if parsed.get("status") != "approved":
                    return False

                # 5. Verify cryptographic signature
                signature = parsed.get("signature", b"")
                is_valid = verify_ecdsa_p256_signature(stored_public_key, nonce, signature)
                return is_valid

        except (asyncio.TimeoutError, Exception) as exc:
            raise BLECentralError(f"BLE challenge-response failed: {exc}") from exc
