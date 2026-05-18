import bcrypt

class Security:
    @staticmethod
    def get_password_hash(password: str):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


    @staticmethod
    def verify_password(plain_password: str, hashed_password: str):
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except ValueError:
            return False


security = Security()