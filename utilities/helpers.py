import random
import string


def generate_random_name():
    def random_string(length):
        characters = string.ascii_letters
        return ''.join(random.choice(characters) for _ in range(length))

    first_name = random_string(random.randint(4, 8)).capitalize()
    last_name = random_string(random.randint(4, 10)).capitalize()
    return f"{first_name} {last_name}"


def generate_random_password(length=10):
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    special_char = random.choice("@$!%*?&")  # Only allow specific special characters
    required_chars = [lowercase, uppercase, digit, special_char]

    all_characters = string.ascii_letters + string.digits + "!@#$%"
    remaining_chars = [random.choice(all_characters) for _ in range(length - 4)]
    password_list = required_chars + remaining_chars
    random.shuffle(password_list)
    return ''.join(password_list)

def generate_random_email():
    username = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'example.com', 'yourdomain.com']
    domain = random.choice(email_domains)
    email = f"{username}@{domain}"
    return email
