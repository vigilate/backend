same_user_to_create = {"email": "aaa@aaa.fr", "password": "a"}

multiple_user = [
    {"email": "bbb@bbb.fr", "password": "b"},
    {"email": "ccc@ccc.fr", "password": "c"},
    {"email": "ccc@ddd.fr", "password": "d"},
]

superuser = {"password": "vigilate_pwd", "email": "vigilate@test.com"}

wrong_password_superuser = "wrong"

wrong_password_user = {"email": "aaa@aaa.fr", "password": "a", "wrong_password": "b"}

wrong_password_email = {"email": "aaa@aaa.fr", "password": "a", "wrong_email": "b"}

bogus_basic_data = "Basic test"

good_phone_numbers = ["+33611223344", "+15855004242", "+441743253876"]

bad_phone_numbers = ["0666666666", "abcde", "4242"]

good_emails = ["test@test.fr", "prenom.nom@epitech.eu", "user_42@lol.io"]

bad_emails = ["test", "a@a.a", "123@123.0", "31337"]
