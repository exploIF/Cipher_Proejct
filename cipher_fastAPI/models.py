from sqlalchemy import Column, ForeignKey, Integer, String, DATETIME
from datetime import datetime
from database import Base, SessionLocal
from sqlalchemy.orm import relationship
import random


class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    public_key_e = Column(Integer, default=0)
    public_key_n = Column(Integer, default=0)
    private_key_d = Column(Integer, default=0)

    def key_generator(self):
        """
        Method returning users public and private keys. Keys are calculated from randomly selected numbers from
        range 10 to 200. Then they are calculated using standard RSA steps, Euler's function, and modular multiplicative
        inverse.

        Returning two tuples, first is a public key, second is a private key.
        """

        primes = []
        for x in range(10, 200):    # generating prime numbers
            for y in range(2, x):
                if x % y == 0:
                    break
            else:
                primes.append(x)
        p = random.choice(primes)   # first random prime number
        while True:
            q = random.choice(primes)   # second random prime number
            if q != p:     # p and q must be various
                break
        n = p * q
        euler_function = (p - 1) * (q - 1)      # calculating Euler's function
        random.seed()
        while True:
            e = random.randint(2, euler_function - 1)   # generating e number
            if self.euclid(euler_function, e) == 1:     # checking if e is coprime to result of Euler's function
                break
        d = self.mod_multi_inverse(e, euler_function)   # calling mod_multi_inverse function to get d value
        return e, n, d   # returning public and private key

    @staticmethod
    def euclid(a, b):
        """
        Static method returning greatest common divisor of integers a and b.

        Parameters
        _____
        a : int
            First integer.
        b : int
            Second integer.
        """

        while b != 0:
            c = a % b
            a = b
            b = c
        return a

    @staticmethod
    def extended_euclid(a, b):
        """
        Static method returning greatest common divisor of integers a and b.

        Parameters
        _____
        a : int
            First integer. Coprime to b.
        b : int
            Second integer. Coprime to a.
        """

        if a == 0:
            return b, 0, 1
        else:
            g, y, x = User.extended_euclid(b % a, a)
            return g, x - (b // a) * y, y

    @staticmethod
    def mod_multi_inverse(a, m):
        """
        Static method returning modular multiplicative inverse of integers a and m. User to calculate d element
        of private key.

        Parameters
        _____
        a : int
            Result of Euler's function result for randomly choose two prime numbers.
        m : int
            Randomly choose number (1 < m < a) coprime to Euler's function result for randomly chosen two
            prime numbers.
        """

        g, x, y = User.extended_euclid(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m


class Message(Base):
    __tablename__ = "messages"

    message_id = Column(Integer, primary_key=True, index=True)
    coded_message = Column(String)
    sender = Column(String, ForeignKey('users.username'))
    receiver = Column(String, ForeignKey('users.username'))
    date_time = Column(DATETIME, default=datetime.now)

    sender_fk = relationship("User", foreign_keys=[sender])
    receiver_fk = relationship("User", foreign_keys=[receiver])

    def encryption(self, message):
        """
        Static method returning encrypted with RSA algorithm message.

        Parameters
        _____
        public_key : tuple
             Tuple with receiver's public key.
        message : string
            String that should be encrypted.
        """
        db = SessionLocal()
        receiver = db.query(User).filter_by(username=self.receiver).first()
        n = receiver.public_key_n
        e = receiver.public_key_e
        code = []
        raw_message = r"{}".format(message)     # using raw string to protect from unicode error (characters like \U)
        for letter in raw_message:
            coded_message = (ord(letter) ** e) % n      # every coded ascii value stored in 5-digits block
            code.append('0' * (5 - len(str(coded_message))) + str(coded_message))
        return "".join(code)

    def decryption(self):
        """
        Method returning decrypted with RSA algorithm message.

        Parameters
        _____
        coded_message : string
            String consisting of digits, coded message.
        """
        coded_message = self.coded_message
        db = SessionLocal()
        receiver = db.query(User).filter_by(username=self.receiver).first()
        n = receiver.public_key_n
        d = receiver.private_key_d
        message = []
        index = 0
        while index < len(coded_message):       # using while loop to have more control on index value
            ascii_character = int(coded_message[index:index+5]) ** d % n
            index += 5
            if chr(ascii_character) == '\\':    # checking if current character is escape character
                # finding new line character, using double back slash as escape character
                if chr(int(coded_message[index:index+5]) ** d % n) == 'n' and message[-1] == '\\':
                    message.append('\n')
                    index += 5      # skipping next iteration if current character is \, next is n and previous is not \
                    continue
                # finding tab character, using double back slash as escape character
                elif chr(int(coded_message[index:index+5]) ** d % n) == 't' and message[-1] == '\\':
                    message.append('\t')
                    index += 5   # skipping next iteration if current character is \ and next is t and previous is not \
                    continue
            message.append(chr(ascii_character))
        return "".join(message)
