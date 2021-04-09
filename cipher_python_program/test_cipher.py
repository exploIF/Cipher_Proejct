import unittest
from cipher import User


class TestCipher(unittest.TestCase):

    def setUp(self):
        self.user_1 = User()
        self.user_2 = User()

    def test_cipher(self):
        test_messages = ('Test message',
                         'Another 123test 898message with numbers 788888',
                         'Test message with '
                         'new line ',
                         'Test message with \n special character',
                         'Test message with         tab inside',
                         'MESSAGE WITH LOWERCASE',
                         'message with uppercase',
                         'Message with \\n \\t escape characters',
                         '1237162387163',
                         r'Message with unicode special \U character',
                         'Polskie znaki też są obsługiwane.',
                         'Testing some punctuation marks: ,.?!><+=')

        for message in test_messages:
            encrypted_message = User.encryption(self.user_2.public_key, message)
            decrypted_message = self.user_2.decryption(encrypted_message)
            self.assertEqual(message, decrypted_message)


if __name__ == "__main__":
    unittest.main()
