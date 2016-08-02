same_user_to_create = {"email": "aaa@aaa.fr", "password": "a"}

multiple_user = [
    {"email": "bbb@bbb.fr", "password": "b"},
    {"email": "ccc@ccc.fr", "password": "c"},
    {"email": "ccc@ddd.fr", "password": "d"},
]

superuser = {"username": "vigilate", "password": "vigilate_pwd", "email": "vigilate@test.com"}

wrong_password_superuser = "wrong"

wrong_password_user = {"email": "aaa@aaa.fr", "password": "a", "wrong_password": "b"}

wrong_password_email = {"email": "aaa@aaa.fr", "password": "a", "wrong_email": "b"}

bogus_basic_data = "Basic test"
