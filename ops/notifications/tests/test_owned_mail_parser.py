import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('owned_delivery', Path(__file__).parents[1] / 'owned-delivery-smoke.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OwnedMessage(unittest.TestCase):
    def message(self, sender=m.SENDER, recipient=m.RECIPIENT, url=m.ORIGIN + '/#notifications'):
        return (f'From: {sender}\r\nTo: {recipient}\r\nSubject: CL8Y wallet security notice\r\n'
                'Message-ID: <11111111-1111-4111-8111-111111111111@security.cl8y.com>\r\n'
                'Content-Type: text/plain; charset=utf-8\r\n\r\n'
                f'Confirm your CL8Y email channel by entering this one-use code at {url}:\n'
                + 'a' * 64 + '\nExpires soon.').encode()

    def test_fixed_owned_headers_and_valid_message_id(self):
        result = m.owned_message(self.message())
        self.assertIsNotNone(result)

    def test_other_sender_recipient_or_link_is_ignored(self):
        for options in ({'sender': 'other@example.invalid'}, {'recipient': 'other@example.invalid'},
                        {'url': 'https://example.invalid/#notifications'}):
            self.assertIsNone(m.owned_message(self.message(**options)))

    def test_oversized_or_invalid_id_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, 'mail_bound'):
            m.owned_message(b'x' * 8193)
        self.assertIsNone(m.owned_message(self.message().replace(b'11111111-1111-4111-8111-111111111111', b'not-a-valid-id')))


if __name__ == '__main__':
    unittest.main()
