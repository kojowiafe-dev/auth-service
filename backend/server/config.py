import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")





class Settings:
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    RESET_TOKEN_EXPIRE_MINUTES = os.getenv("RESET_TOKEN_EXPIRE_MINUTES")
    DATABASE_URL = os.getenv("DATABASE_URL")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    ERRX_VERBOSITY = os.getenv("ERRX_VERBOSITY")

    
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = os.getenv("SMTP_PORT")
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    EMAIL_FROM = os.getenv("EMAIL_FROM")



    

settings = Settings()