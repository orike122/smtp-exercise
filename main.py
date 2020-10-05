import base64
import re
import ssl
import traceback
from dataclasses import dataclass
from enum import auto, Enum

from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from typing import Union, List, ClassVar, Pattern, Callable, Tuple, Any, Type
import getpass

def _notify(obj: Any) -> Any:
    print(obj)
    return obj

class Codes(auto):
    CONNECTION = 220
    HELO = 250
    QUIT = 221
    DATA = 354
    AUTH_PROCCED = 334
    AUTH_COMPLETED = 235
    SENT = 250
    OK = 250



class SMTPCommands(auto):
    HELO = "HELO"
    QUIT = "QUIT"
    DATA = "DATA"
    MAIL = "MAIL"
    RCPT = "RCPT"
    AUTH_LOGIN = "AUTH LOGIN"



class BadSmptRequest(Exception):
    pass


@dataclass
class Response:
    code: int
    msg: str
    success: bool

    def __repr__(self) -> bool:
        return self.success

    def __str__(self) -> str:
        success: str = "Successful" if self.success else "Unsuccessful"
        return f"\nRequest was {success}. Code: {self.code}.\nReturned with message:\n{self.msg}"


@dataclass
class Email:
    sender: str
    recipient: str
    subject: str
    content: str

    _EMAIL_REGEX: ClassVar[Pattern] = re.compile("^[a-z0-9]+[\.'\-]*[a-z0-9]+@(gmail|googlemail)\.com$")

    @staticmethod
    def _input_sender() -> str:
        sender_email: str = ""
        while not Email._EMAIL_REGEX.match(sender_email):
            sender_email = input("Enter Sender Email: ")

        return sender_email

    @staticmethod
    def _input_recipient() -> str:
        recipient_email: str = ""
        while not Email._EMAIL_REGEX.match(recipient_email):
            recipient_email = input("Enter Recipient Email: ")

        return recipient_email

    @staticmethod
    def _input_content(sender: str, recipient: str, subject: str) -> str:

        lines: List[str] = [
            f"From: {sender}",
            f"To: {recipient}",
            f"Subject: {subject}"
        ]

        print("Enter Content(Write . in a line on itself to end):\n")

        while lines[-1] != '.':
            lines.append(input())

        return '\r\n'.join(lines) + '\r\n'

    @staticmethod
    def _input_subject() -> str:
        return input("Enter Subject: ")

    @classmethod
    def compose(cls):

        sender: str = cls._input_sender()
        recipient: str = cls._input_recipient()
        subject: str = cls._input_subject()
        content: str = cls._input_content(sender, recipient, subject)

        return cls(sender, recipient, subject, content)

@dataclass
class User:
    username: str # b64 username
    password: str # b64 password

    @classmethod
    def create(cls, username: str, password: str):
        return cls(
            base64.encodebytes(username.encode("UTF-8")),
            base64.encodebytes(password.encode("UTF-8"))
        )

    @classmethod
    def login(cls):
        username: str = input("Enter Email: ")
        password: str = getpass.getpass("Enter Password: ")
        return cls.create(username, password)

    def credentials(self) -> Tuple[str,str]:
        return self.username, self.password


def consume_exception(fn: Callable):
    def inner_func(*args, **kwargs):
        try:
            fn(*args, **kwargs)
        except BadSmptRequest:
            print("Error: Aborted!")

    return inner_func

def _validate_response(res: Response):
    if not res:
        raise BadSmptRequest()

class SmtpClient:
    SERVER: str = "74.125.206.109"
    PORT: int = 465

    RECV_SIZE = 8192

    def __init__(self, with_print: bool = False):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.with_print: bool = with_print

    @staticmethod
    def _validate_response(res: Response):
        if not res:
            raise BadSmptRequest()

    def _get_respose(self, res: str, success_code: int) -> Response:
        code: int = -1
        msg: str = ""
        if res:
            try:
                code = int(res[:3])
                msg = res[3:]
            except ValueError:
                pass

        if code == success_code:
            return _notify(Response(code, msg, True))

        return _notify(Response(code, msg, False))

    def _recv(self, size: int = RECV_SIZE) -> str:
        msg: bytes = self.socket.recv(self.RECV_SIZE)
        msg_str: str = msg.decode("UTF-8").strip('\n').strip('\r')

        if self.with_print:
            print(f"\nGot: {msg_str}")

        return msg_str

    def _send(self, message: Union[bytes, str]):

        if type(message) is str:
            message = message.encode("UTF-8") + b'\n'

        self.socket.sendall(message)

        if self.with_print:
            print(f"\nSending: {message.decode('UTF-8')}")


    def say_hello(self, name: str):

        self._send(f"{SMTPCommands.HELO} {name}")
        self._get_respose(self._recv(), Codes.HELO)

    def send_email(self):
        email: Email = Email.compose()

        self._send(f"{SMTPCommands.MAIL} From:<{email.sender}>")
        self._get_respose(self._recv(), Codes.OK)

        self._send(f"{SMTPCommands.RCPT} To:<{email.recipient}>")
        self._get_respose(self._recv(), Codes.OK)

        self._send(f"{SMTPCommands.DATA}")
        self._get_respose(self._recv(), Codes.DATA)

        self._send(email.content)
        self._get_respose(self._recv(), Codes.SENT)

    @consume_exception
    def authenticate(self) -> bool:
        if not hasattr(self, "user"):
            print("Authentication was not configured!")
            return False

        username, password = self.user.credentials()

        self._send(f"{SMTPCommands.AUTH_LOGIN}")
        _validate_response(self._get_respose(self._recv(), Codes.AUTH_PROCCED))
        self._send(username)
        _validate_response(self._get_respose(self._recv(), Codes.AUTH_PROCCED))
        self._send(password)
        _validate_response(self._get_respose(self._recv(), Codes.AUTH_COMPLETED))


    def quit(self):
        self._send(SMTPCommands.QUIT)
        self._get_respose(self._recv(), Codes.QUIT)

    def __enter__(self):
        self.socket.connect((self.SERVER, self.PORT))
        _validate_response(self._get_respose(self._recv(), Codes.CONNECTION))
        return self

    def __exit__(self, exc_type, exc_value, tb):

        self.socket.shutdown(SHUT_RDWR)
        self.socket.close()

        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, tb)
            # return False # uncomment to pass exception through

        return True


@dataclass
class Auth:

    user: User

    @staticmethod
    def _configure_authentication(client: SmtpClient):
        client.socket = ssl.wrap_socket(client.socket)

    def make_client(self, client_cls: Type[SmtpClient]):
        instance = client_cls(with_print=True)
        Auth._configure_authentication(instance)
        setattr(instance, "user", self.user)
        return instance

    def get_credentials(self) -> Tuple[str, str]:
        return self.user.username, self.user.password




def main():
    user: User = User.login()
    with Auth(user).make_client(SmtpClient) as client:
        client.say_hello("ori")
        client.authenticate()
        client.send_email()
        client.quit()


if __name__ == "__main__":
    main()
