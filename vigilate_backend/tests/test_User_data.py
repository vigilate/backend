same_user_to_create = {"email": "a", "password": "a"}

multiple_user = [
    {"email": "b", "password": "b"},
    {"email": "c", "password": "c"},
    {"email": "d", "password": "d"},
]

superuser = {"username": "vigilate", "password": "vigilate_pwd", "email": "vigilate@test.com"}

wrong_password_superuser = "wrong"

wrong_password_user = {"email": "a", "password": "a", "wrong_password": "b"}

wrong_password_email = {"email": "a", "password": "a", "wrong_email": "b"}

bogus_basic_data = "Basic test"
