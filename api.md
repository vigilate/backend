**Add User**
----
  Add an user to the backend

* **URL**

  /api/users/

* **Method:**

  `POST`

* **Data Params**

  ```javascript
  {
    "username": "",
    "email": "",
    "password": "",
    "user_type": 0,
    "contrat": 0,
    "id_dealer": 0
}
  ```

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    
    ```javascript
    {"id":1,"username":"foo","email":"foo@bar.com","password":"HASH","user_type":0,"contrat":0,"id_dealer":0}
    ```


**Add Program**
----
  Add a program to an user

* **URL**

  /api/uprog/

* **Method:**

  `POST`

* **Data Params**

  ```javascript
  {
    "program_name": "",
    "program_version": "",
    "minimum_score": 0,
    "user": 0
  }
  ```

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    
    ```javascript
    {"minimum_score": 0, "user": 2, "program_name": "firefox", "program_version": "0"}
    ```

**Delete Program**
----
  Delete a program from an user

* **URL**

  /api/uprog/:id

* **Method:**

  `DELETE`

* **Success Response:**

  * **Code:** 200 <br />

**List Programs**
----
  List program of current user.

* **URL**

  /api/uprog/

* **Method:**

  `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    
    ```javascript
    [{"program_name":"firefox","program_version":"42","minimum_score":0,"user":1}]
    ```
