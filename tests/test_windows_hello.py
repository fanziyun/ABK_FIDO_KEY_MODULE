#!/usr/bin/env python3
"""Pin the Windows Hello behaviours that must survive a refactor.

Windows is picky about the exact transport and ceremony shapes, and none of
them can be executed on the host, so each one is pinned at the source level:
the byte pattern, the exact response byte, or the condition that implements
the behaviour. If one of these strings disappears the real Windows path is
silently broken — the on-device check list is in README.md.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
DRIVER = REPOSITORY / "files/drivers/abk_fido_key/core.c"


class WindowsHelloShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.driver = DRIVER.read_text()

    def _assert_text(self, needle: str, message: str) -> None:
        self.assertIn(needle, self.driver, message)

    def test_usb_report_descriptor_is_fido_hid(self) -> None:
        # Windows webauthn only lists devices whose top-level collection uses
        # usage page 0xF1D0, usage 0x01.
        self._assert_text(
            "0x06, 0xd0, 0xf1,", "FIDO usage page missing from report descriptor"
        )
        self._assert_text("0x09, 0x01,", "FIDO usage missing from report descriptor")
        self._assert_text(
            "USB_CLASS_HID", "FIDO interface is not class HID"
        )

    def test_ctaphid_init_reply_shape_windows_reads(self) -> None:
        # protocol version 2, build 0, caps 0x0d (LOCK | CBOR | NMSG).
        self._assert_text("init_resp[12] = 2;", "INIT protocol version byte")
        self._assert_text("init_resp[16] = 0x0d;", "INIT capabilities byte")

    def test_broadcast_channel_is_served(self) -> None:
        # Windows sends INIT and CBOR on CID 0xffffffff.
        self._assert_text(
            "#define ABK_FIDO_CID_BROADCAST			0xffffffffU",
            "broadcast CID define missing",
        )
        self._assert_text(
            "ch = abk_fido_alloc_channel_locked(cid);",
            "packet path does not allocate a channel for an unknown CID",
        )

    def test_device_selection_ceremony_is_handled(self) -> None:
        self._assert_text(
            '!strcmp(req->rp_id, "SelectDevice")',
            "Windows SelectDevice ceremony recognition missing",
        )

    def test_silent_getassertion_is_refused(self) -> None:
        # Browsers probe credential existence with up=0. With no matching
        # credential the driver refuses without prompting, so background
        # probes cannot spam the phone.
        self._assert_text(
            "getAssertion silent refused", "silent getAssertion refusal missing"
        )

    def test_silent_probe_with_a_match_gets_the_approval_prompt(self) -> None:
        # Refusing a probe that DOES match would make clients offer to
        # register a new credential instead of reusing the existing one.
        self._assert_text(
            "getAssertion silent probe prompted",
            "silent probe with match no longer prompts for approval",
        )

    def test_assertion_carries_the_user_object_for_resident_keys(self) -> None:
        # Windows Hello sign-in sends an allowList and still needs the user
        # handle to pick the account.
        self._assert_text(
            "abk_fido_dev.store.creds[slots[0]].resident",
            "resident credentials no longer force the user object",
        )

    def test_makecredential_mints_an_hmac_secret(self) -> None:
        self._assert_text(
            "get_random_bytes(cred->hmac_secret",
            "hmac-secret is not created at registration",
        )
        # The response is `true`, appended to the signed authData.
        self._assert_text(
            "abk_cbor_put_bool(&ew, true);",
            "makeCredential response does not append hmac-secret: true",
        )

    def test_getassertion_embeds_the_hmac_output_in_authdata(self) -> None:
        self._assert_text(
            "abk_cbor_put_bytes(&ew, hmac_output, 64);",
            "getAssertion response does not append the hmac-secret output",
        )

    def test_attach_pipeline_is_diagnosable_over_sysfs(self) -> None:
        # A phone that never enumerates the key on Windows is diagnosable via
        # /sys/kernel/abk_fido_key/attach_state.
        self._assert_text(
            "attach_state_show", "attach_state sysfs node missing"
        )
        self._assert_text(
            'abk_fido_set_attach_state_locked("attached")',
            "prepare_config does not record the attached state",
        )
        self._assert_text(
            'abk_fido_set_attach_state_locked("auto_attach_disabled")',
            "AUTO_ATTACH-off state is not recorded",
        )

    def test_stuck_in_transfer_is_unwedged_on_new_commands(self) -> None:
        # A host that times out stops polling the IN endpoint; the queued
        # request then never completes and every later response would queue
        # behind it (Windows shows "touch your key" forever). A fresh
        # command dequeues the stuck transfer.
        self._assert_text(
            "dequeue of stuck IN request",
            "stuck IN transfer is no longer dequeued on new commands",
        )
        self._assert_text(
            "hid_state_attr", "hid_state diagnostic node missing"
        )


if __name__ == "__main__":
    unittest.main()
